// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(any(target_os = "linux", target_os = "windows"))]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pm_crypto::digest;
#[cfg(windows)]
use pm_native_channel::{WindowsClientPipe, WindowsServerPipe, WindowsStopEvent};
use pm_sync::{OpaqueSyncStore, SyncError};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
    client::{
        AlwaysResolvesClientRawPublicKeys, ClientConfig, ClientConnection, Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, verify_tls13_signature_with_raw_key},
    pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
        UnixTime,
    },
    server::{
        AlwaysResolvesServerRawPublicKeys, ServerConfig, ServerConnection,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
    version,
};
#[cfg(target_os = "linux")]
use std::os::unix::{
    fs::{FileTypeExt, MetadataExt, PermissionsExt},
    net::{UnixListener, UnixStream},
};
#[cfg(windows)]
use std::sync::{Condvar, Mutex};
use std::{
    fmt::Write as _,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"PMK1";
const ALPN: &[u8] = b"pm-sync/1";
const MAX_FRAME: usize = 1024 * 1024;
#[derive(Debug)]
struct Key {
    private: Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
}

fn main() {
    if run().is_err() {
        eprintln!("SYNC_UNAVAILABLE");
        std::process::exit(4)
    }
}
fn run() -> Result<(), ()> {
    let mut a = std::env::args_os().skip(1);
    match a.next().and_then(|v| v.into_string().ok()).as_deref() {
        Some("serve") => {
            let db = take(&mut a, "--db")?;
            let socket = take(&mut a, "--socket")?;
            let key = read_key(&take(&mut a, "--server-key")?)?;
            let namespace = hex32(&take(&mut a, "--namespace")?)?;
            #[cfg(windows)]
            let server_sid = take_string(&mut a, "--server-sid")?;
            let mut clients = Vec::new();
            #[cfg(windows)]
            let mut client_sids = Vec::new();
            while let Some(flag) = a.next() {
                if flag != "--client-pub" {
                    return Err(());
                }
                clients.push(read_public(&PathBuf::from(a.next().ok_or(())?))?);
                #[cfg(windows)]
                {
                    if a.next().as_deref() != Some(std::ffi::OsStr::new("--client-sid")) {
                        return Err(());
                    }
                    client_sids.push(a.next().ok_or(())?.into_string().map_err(|_| ())?);
                }
            }
            #[cfg(target_os = "linux")]
            {
                serve(&db, &socket, &key, namespace, clients)
            }
            #[cfg(windows)]
            {
                serve(
                    &db,
                    &socket,
                    &key,
                    namespace,
                    clients,
                    &server_sid,
                    client_sids,
                )
            }
        }
        Some(method @ ("put" | "get" | "publish" | "list" | "delete")) => client(method, &mut a),
        _ => Err(()),
    }
}

#[cfg(windows)]
fn take_string(a: &mut impl Iterator<Item = std::ffi::OsString>, flag: &str) -> Result<String, ()> {
    take(a, flag)?
        .into_os_string()
        .into_string()
        .map_err(|_| ())
}
fn take(a: &mut impl Iterator<Item = std::ffi::OsString>, flag: &str) -> Result<PathBuf, ()> {
    if a.next().as_deref() != Some(std::ffi::OsStr::new(flag)) {
        return Err(());
    }
    a.next().map(PathBuf::from).ok_or(())
}

#[cfg(target_os = "linux")]
fn serve(
    db: &Path,
    socket: &Path,
    key: &Key,
    namespace: [u8; 32],
    clients: Vec<Vec<u8>>,
) -> Result<(), ()> {
    if clients.is_empty() || clients.iter().any(|v| v.len() != 44) {
        return Err(());
    }
    let store = OpaqueSyncStore::create(db).map_err(|_| ())?;
    for rpk in &clients {
        store.authorize(namespace, rpk).map_err(|_| ())?;
    }
    let config = server_config(certified(key)?, clients)?;
    match fs::symlink_metadata(socket) {
        Ok(metadata)
            if metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() } =>
        {
            fs::remove_file(socket).map_err(|_| ())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(()),
    }
    let listener = UnixListener::bind(socket).map_err(|_| ())?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o666)).map_err(|_| ())?;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let store_path = db.to_owned();
        let config = Arc::clone(&config);
        std::thread::spawn(move || {
            let _ = serve_one_unix(stream, &store_path, config);
        });
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn serve(
    db: &Path,
    socket: &Path,
    key: &Key,
    namespace: [u8; 32],
    clients: Vec<Vec<u8>>,
    server_sid: &str,
    client_sids: Vec<String>,
) -> Result<(), ()> {
    if clients.is_empty()
        || clients.len() != client_sids.len()
        || clients.iter().any(|value| value.len() != 44)
    {
        return Err(());
    }
    let name = socket.to_str().ok_or(())?;
    let store = OpaqueSyncStore::create(db).map_err(|_| ())?;
    for rpk in &clients {
        store.authorize(namespace, rpk).map_err(|_| ())?;
    }
    let config = server_config(certified(key)?, clients)?;
    loop {
        let stop = WindowsStopEvent::create().map_err(|_| ())?;
        let mut pipe = match WindowsServerPipe::create_sync(name, server_sid, &client_sids, &stop) {
            Ok(pipe) => pipe,
            Err(_) => {
                stop.close().map_err(|_| ())?;
                return Err(());
            }
        };
        if pipe.accept().is_err() {
            drop(pipe);
            stop.close().map_err(|_| ())?;
            continue;
        }
        let pending = Arc::new(Mutex::new(Some((pipe, stop))));
        let worker_pending = Arc::clone(&pending);
        let store_path = db.to_owned();
        let worker_config = Arc::clone(&config);
        let spawned = std::thread::Builder::new()
            .name("pm-sync-windows-request".to_owned())
            .spawn(move || {
                let pending = match worker_pending.lock() {
                    Ok(mut slot) => slot.take(),
                    Err(_) => {
                        eprintln!("SYNC_REQUEST_FAILED");
                        return;
                    }
                };
                let Some((pipe, stop)) = pending else {
                    eprintln!("SYNC_REQUEST_FAILED");
                    return;
                };
                let result = run_with_deadline(&stop, || {
                    serve_one_windows(pipe, &store_path, worker_config)
                });
                let closed = stop.close().map_err(|_| ());
                if result.is_err() || closed.is_err() {
                    eprintln!("SYNC_REQUEST_FAILED");
                }
            });
        if spawned.is_err() {
            let (pipe, stop) = pending.lock().map_err(|_| ())?.take().ok_or(())?;
            drop(pipe);
            stop.close().map_err(|_| ())?;
            return Err(());
        }
    }
}

#[cfg(windows)]
fn serve_one_windows(
    mut pipe: WindowsServerPipe,
    db: &Path,
    config: Arc<ServerConfig>,
) -> Result<(), ()> {
    pipe.verify().map_err(|_| ())?;
    let result = serve_one(&mut pipe, db, config);
    let peer = pipe.verify().map_err(|_| ());
    match (result, peer) {
        (Ok(()), Ok(())) => Ok(()),
        _ => Err(()),
    }
}

#[cfg(windows)]
fn run_with_deadline(
    stop: &WindowsStopEvent,
    operation: impl FnOnce() -> Result<(), ()>,
) -> Result<(), ()> {
    let completed = Arc::new((Mutex::new(false), Condvar::new()));
    let waiter = Arc::clone(&completed);
    let signal = stop.clone();
    let worker = std::thread::Builder::new()
        .name("pm-sync-request-deadline".to_owned())
        .spawn(move || {
            let (lock, changed) = &*waiter;
            let finished = lock.lock().map_err(|_| ())?;
            let (finished, timeout) = changed
                .wait_timeout_while(finished, Duration::from_secs(30), |done| !*done)
                .map_err(|_| ())?;
            if timeout.timed_out() && !*finished {
                signal.signal().map_err(|_| ())?;
            }
            Ok(())
        })
        .map_err(|_| ())?;
    let result = operation();
    let completion = (|| {
        let (lock, changed) = &*completed;
        *lock.lock().map_err(|_| ())? = true;
        changed.notify_all();
        worker.join().map_err(|_| ())?
    })();
    match (result, completion) {
        (Ok(()), Ok(())) => Ok(()),
        _ => Err(()),
    }
}

#[cfg(target_os = "linux")]
fn serve_one_unix(stream: UnixStream, db: &Path, config: Arc<ServerConfig>) -> Result<(), ()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| ())?;
    serve_one(stream, db, config)
}

fn serve_one(stream: impl Read + Write, db: &Path, config: Arc<ServerConfig>) -> Result<(), ()> {
    let conn = ServerConnection::new(config).map_err(|_| ())?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let request = read_frame(&mut tls)?;
    let peer = tls
        .conn
        .peer_certificates()
        .and_then(|v| v.first())
        .ok_or(())?
        .as_ref()
        .to_vec();
    if tls.conn.alpn_protocol() != Some(ALPN) {
        return Err(());
    }
    let store = OpaqueSyncStore::create(db).map_err(|_| ())?;
    let response = dispatch(
        &store,
        &peer,
        std::str::from_utf8(&request).map_err(|_| ())?,
    )
    .unwrap_or_else(|()| "{\"ok\":false}".to_owned());
    write_frame(&mut tls, response.as_bytes())
}

fn dispatch(store: &OpaqueSyncStore, rpk: &[u8], json: &str) -> Result<String, ()> {
    let method = field(json, "method")?;
    let ns = hex32s(&field(json, "namespace")?)?;
    match method.as_str() {
        "sync.put" => {
            let hash = hex32s(&field(json, "hash")?)?;
            let bytes = STANDARD.decode(field(json, "bytes")?).map_err(|_| ())?;
            if let Err(error) = store.put(ns, rpk, hash, &bytes) {
                return Ok(failure(&error));
            }
            Ok(ok())
        }
        "sync.get" => {
            let hash = hex32s(&field(json, "hash")?)?;
            let bytes = match store.get(ns, rpk, hash) {
                Ok(bytes) => bytes,
                Err(error) => return Ok(failure(&error)),
            };
            Ok(format!(
                "{{\"ok\":true,\"bytes\":\"{}\"}}",
                STANDARD.encode(bytes)
            ))
        }
        "sync.publish" => {
            if let Err(error) = store.publish(ns, rpk, hex32s(&field(json, "root_hash")?)?) {
                return Ok(failure(&error));
            }
            Ok(ok())
        }
        "sync.list" => {
            let cursor = optional_field(json, "cursor")
                .map(|value| value.parse::<u64>().map_err(|_| ()))
                .transpose()?;
            let limit = optional_number(json, "limit")?.unwrap_or(128);
            let roots = match store.list(ns, rpk, cursor, limit) {
                Ok(roots) => roots,
                Err(error) => return Ok(failure(&error)),
            };
            let joined = roots
                .iter()
                .map(|(cursor, hash)| {
                    format!(
                        "{{\"cursor\":\"{cursor}\",\"root_hash\":\"{}\"}}",
                        hex(hash)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            Ok(format!("{{\"ok\":true,\"roots\":[{joined}]}}"))
        }
        "sync.delete" => {
            let hashes = string_array_field(json, "hashes")?
                .iter()
                .map(|value| hex32s(value))
                .collect::<Result<Vec<_>, _>>()?;
            if let Err(error) = store.delete(ns, rpk, &hashes) {
                return Ok(failure(&error));
            }
            Ok(ok())
        }
        _ => Err(()),
    }
}
fn ok() -> String {
    "{\"ok\":true}".to_owned()
}
fn failure(error: &SyncError) -> String {
    let code = match error {
        SyncError::Missing => "missing",
        SyncError::Backpressure => "backpressure",
        SyncError::Integrity | SyncError::InvalidRequest => "integrity",
        _ => "unavailable",
    };
    format!("{{\"ok\":false,\"code\":\"{code}\"}}")
}
fn field(json: &str, name: &str) -> Result<String, ()> {
    optional_field(json, name).ok_or(())
}
fn optional_field(json: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\":\"");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    let value = &rest[..end];
    if value.contains(['\\', '\n', '\r']) {
        return None;
    }
    Some(value.to_owned())
}
fn optional_number(json: &str, name: &str) -> Result<Option<usize>, ()> {
    let needle = format!("\"{name}\":");
    let Some(start) = json.find(&needle).map(|value| value + needle.len()) else {
        return Ok(None);
    };
    let digits: String = json[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        return Err(());
    }
    Ok(Some(digits.parse().map_err(|_| ())?))
}
fn string_array_field(json: &str, name: &str) -> Result<Vec<String>, ()> {
    let needle = format!("\"{name}\":[");
    let start = json.find(&needle).ok_or(())? + needle.len();
    let end = json[start..].find(']').ok_or(())? + start;
    let body = &json[start..end];
    if body.is_empty() {
        return Ok(Vec::new());
    }
    body.split(',')
        .map(|value| {
            value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .filter(|value| !value.contains(['\\', '\n', '\r', '"']))
                .map(str::to_owned)
                .ok_or(())
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn client(method: &str, a: &mut impl Iterator<Item = std::ffi::OsString>) -> Result<(), ()> {
    let socket = take(a, "--socket")?;
    let key = read_key(&take(a, "--client-key")?)?;
    let server = read_public(&take(a, "--server-pub")?)?;
    let namespace = hex32(&take(a, "--namespace")?)?;
    let hash = if matches!(method, "put" | "get" | "publish" | "delete") {
        Some(hex32(&take(a, "--hash")?)?)
    } else {
        None
    };
    let input = if method == "put" {
        Some(fs::read(take(a, "--input")?).map_err(|_| ())?)
    } else {
        None
    };
    let mut cursor = None;
    let mut limit = 128_usize;
    if method == "list" {
        while let Some(flag) = a.next() {
            match flag.to_str() {
                Some("--cursor") => {
                    cursor = Some(a.next().ok_or(())?.into_string().map_err(|_| ())?);
                }
                Some("--limit") => {
                    limit = a
                        .next()
                        .ok_or(())?
                        .into_string()
                        .map_err(|_| ())?
                        .parse()
                        .map_err(|_| ())?;
                }
                _ => return Err(()),
            }
        }
    }
    if a.next().is_some() {
        return Err(());
    }
    let json = match method {
        "put" => {
            let bytes = input.unwrap();
            if digest(&bytes) != hash.unwrap() {
                return Err(());
            }
            format!(
                "{{\"method\":\"sync.put\",\"namespace\":\"{}\",\"hash\":\"{}\",\"bytes\":\"{}\"}}",
                hex(&namespace),
                hex(&hash.unwrap()),
                STANDARD.encode(bytes)
            )
        }
        "get" => format!(
            "{{\"method\":\"sync.get\",\"namespace\":\"{}\",\"hash\":\"{}\"}}",
            hex(&namespace),
            hex(&hash.unwrap())
        ),
        "publish" => format!(
            "{{\"method\":\"sync.publish\",\"namespace\":\"{}\",\"root_hash\":\"{}\"}}",
            hex(&namespace),
            hex(&hash.unwrap())
        ),
        "list" => {
            if let Some(cursor) = cursor {
                format!(
                    "{{\"method\":\"sync.list\",\"namespace\":\"{}\",\"cursor\":\"{cursor}\",\"limit\":{limit}}}",
                    hex(&namespace)
                )
            } else {
                format!(
                    "{{\"method\":\"sync.list\",\"namespace\":\"{}\",\"limit\":{limit}}}",
                    hex(&namespace)
                )
            }
        }
        "delete" => format!(
            "{{\"method\":\"sync.delete\",\"namespace\":\"{}\",\"hashes\":[\"{}\"]}}",
            hex(&namespace),
            hex(&hash.unwrap())
        ),
        _ => return Err(()),
    };
    let config = client_config(&key, &server)?;
    let response = client_exchange(&socket, config, json.as_bytes())?;
    let response = String::from_utf8(response).map_err(|_| ())?;
    if !response.starts_with("{\"ok\":true") {
        let code = if response.contains("\"code\":\"missing\"") {
            5
        } else if response.contains("\"code\":\"backpressure\"") {
            6
        } else if response.contains("\"code\":\"integrity\"") {
            7
        } else {
            4
        };
        std::process::exit(code);
    }
    println!("{response}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn client_exchange(socket: &Path, config: ClientConfig, request: &[u8]) -> Result<Vec<u8>, ()> {
    let stream = UnixStream::connect(socket).map_err(|_| ())?;
    let conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("passwordmanager.invalid").map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    write_frame(&mut tls, request)?;
    read_frame(&mut tls)
}

#[cfg(windows)]
fn client_exchange(socket: &Path, config: ClientConfig, request: &[u8]) -> Result<Vec<u8>, ()> {
    let name = socket.to_str().ok_or(())?;
    let stop = WindowsStopEvent::create().map_err(|_| ())?;
    let mut response = None;
    let result = run_with_deadline(&stop, || {
        let pipe = WindowsClientPipe::connect_sync(name, &stop).map_err(|_| ())?;
        let conn = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("passwordmanager.invalid").map_err(|_| ())?,
        )
        .map_err(|_| ())?;
        let mut tls = rustls::StreamOwned::new(conn, pipe);
        write_frame(&mut tls, request)?;
        response = Some(read_frame(&mut tls)?);
        tls.sock.verify().map_err(|_| ())?;
        Ok(())
    });
    let closed = stop.close().map_err(|_| ());
    match (result, closed, response) {
        (Ok(()), Ok(()), Some(response)) => Ok(response),
        _ => Err(()),
    }
}

fn provider() -> CryptoProvider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    p
}
fn certified(key: &Key) -> Result<Arc<CertifiedKey>, ()> {
    let p = provider();
    let signing = p
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.private.to_vec(),
        )))
        .map_err(|_| ())?;
    if signing.public_key().ok_or(())?.as_ref() != key.spki {
        return Err(());
    }
    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(key.spki.clone())],
        signing,
    )))
}
fn server_config(key: Arc<CertifiedKey>, allowed: Vec<Vec<u8>>) -> Result<Arc<ServerConfig>, ()> {
    let p = provider();
    let verifier = Arc::new(ClientPins {
        allowed,
        algorithms: p.signature_verification_algorithms,
    });
    let mut c = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| ())?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(key)));
    c.alpn_protocols = vec![ALPN.to_vec()];
    c.max_early_data_size = 0;
    Ok(Arc::new(c))
}
fn client_config(key: &Key, server: &[u8]) -> Result<ClientConfig, ()> {
    if server.len() != 44 {
        return Err(());
    }
    let p = provider();
    let verifier = Arc::new(ServerPin {
        expected: server.to_vec(),
        algorithms: p.signature_verification_algorithms,
    });
    let mut c = ClientConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| ())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified(
            key,
        )?)));
    c.alpn_protocols = vec![ALPN.to_vec()];
    c.resumption = Resumption::disabled();
    c.enable_early_data = false;
    Ok(c)
}
#[derive(Debug)]
struct ServerPin {
    expected: Vec<u8>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl ServerCertVerifier for ServerPin {
    fn verify_server_cert(
        &self,
        e: &CertificateDer<'_>,
        i: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        pin(e, i, std::slice::from_ref(&self.expected))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        raw(m, c, d, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
#[derive(Debug)]
struct ClientPins {
    allowed: Vec<Vec<u8>>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl ClientCertVerifier for ClientPins {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        e: &CertificateDer<'_>,
        i: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        pin(e, i, &self.allowed)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        raw(m, c, d, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
fn pin(
    e: &CertificateDer<'_>,
    i: &[CertificateDer<'_>],
    allowed: &[Vec<u8>],
) -> Result<(), TlsError> {
    if !i.is_empty() || !allowed.iter().any(|v| v.as_slice() == e.as_ref()) {
        return Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ));
    }
    Ok(())
}
fn raw(
    m: &[u8],
    c: &CertificateDer<'_>,
    d: &DigitallySignedStruct,
    a: &rustls::crypto::WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, TlsError> {
    verify_tls13_signature_with_raw_key(m, &SubjectPublicKeyInfoDer::from(c.as_ref()), d, a)
}
fn read_key(path: &Path) -> Result<Key, ()> {
    #[cfg(target_os = "linux")]
    let b = {
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o400
        {
            return Err(());
        }
        fs::read(path).map_err(|_| ())?
    };
    #[cfg(windows)]
    let b = {
        let mut file = pm_native_channel::open_regular_file(path).map_err(|_| ())?;
        let length = usize::try_from(file.metadata().map_err(|_| ())?.len()).map_err(|_| ())?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes).map_err(|_| ())?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing).map_err(|_| ())? != 0 {
            return Err(());
        }
        bytes
    };
    if !b.starts_with(MAGIC) || b.len() < 4 + 4 + 44 {
        return Err(());
    }
    let n = u32::from_be_bytes(b[4..8].try_into().map_err(|_| ())?) as usize;
    if b.len() != 8 + n + 44 {
        return Err(());
    }
    Ok(Key {
        private: Zeroizing::new(b[8..8 + n].to_vec()),
        spki: b[8 + n..].to_vec(),
    })
}
fn read_public(path: &Path) -> Result<Vec<u8>, ()> {
    #[cfg(target_os = "linux")]
    {
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(());
        }
        let bytes = fs::read(path).map_err(|_| ())?;
        if bytes.len() != 44 {
            return Err(());
        }
        Ok(bytes)
    }
    #[cfg(windows)]
    {
        let mut file = pm_native_channel::open_regular_file(path).map_err(|_| ())?;
        if file.metadata().map_err(|_| ())?.len() != 44 {
            return Err(());
        }
        let mut bytes = vec![0; 44];
        file.read_exact(&mut bytes).map_err(|_| ())?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing).map_err(|_| ())? != 0 {
            return Err(());
        }
        Ok(bytes)
    }
}
fn write_frame(w: &mut impl Write, b: &[u8]) -> Result<(), ()> {
    if b.len() > MAX_FRAME {
        return Err(());
    }
    let length = u32::try_from(b.len()).map_err(|_| ())?;
    w.write_all(&length.to_be_bytes())
        .and_then(|()| w.write_all(b))
        .and_then(|()| w.flush())
        .map_err(|_| ())
}
fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, ()> {
    let mut n = [0; 4];
    r.read_exact(&mut n).map_err(|_| ())?;
    let n = u32::from_be_bytes(n) as usize;
    if n > MAX_FRAME {
        return Err(());
    }
    let mut b = vec![0; n];
    r.read_exact(&mut b).map_err(|_| ())?;
    Ok(b)
}
fn hex(v: &[u8]) -> String {
    v.iter()
        .fold(String::with_capacity(v.len() * 2), |mut out, b| {
            write!(&mut out, "{b:02x}").unwrap();
            out
        })
}
fn hex32(path: &Path) -> Result<[u8; 32], ()> {
    hex32s(path.to_str().ok_or(())?)
}
fn hex32s(v: &str) -> Result<[u8; 32], ()> {
    if v.len() != 64 {
        return Err(());
    }
    let mut out = [0; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let start = i * 2;
        *slot = u8::from_str_radix(&v[start..start + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}
