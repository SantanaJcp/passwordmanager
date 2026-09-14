// SPDX-License-Identifier: AGPL-3.0-only

//! Trusted, closed SSH authentication consumer.
//!
//! This process owns the `russh` transport before host-key verification and
//! retains it after authentication. Custody can release a password only after
//! the pinned host is connected, or answer bounded signing requests.

use aws_lc_rs::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use russh::{
    Signer, client,
    keys::{HashAlg, PublicKey, PublicKeyOrCertificate},
};
use std::fmt::Write as _;
use std::{
    collections::BTreeMap,
    fmt, fs,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: usize = 128 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Profile {
    fields: BTreeMap<String, String>,
    port: u16,
    consumer_uid: u32,
}
#[derive(Debug)]
pub struct ProfileError;
impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("INVALID_PROFILE")
    }
}
impl std::error::Error for ProfileError {}

impl Profile {
    /// Parses the closed installed profile.
    /// # Errors
    /// Rejects unknown, duplicate, non-UTF-8, unbounded or unsafe fields.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        const FIELDS: [&str; 10] = [
            "version",
            "profile_id",
            "integrations",
            "methods",
            "host",
            "port",
            "username",
            "host_key_sha256",
            "consumer_uid",
            "server_version",
        ];
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(ProfileError);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| ProfileError)?;
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            let (key, val) = line.split_once('=').ok_or(ProfileError)?;
            if !FIELDS.contains(&key)
                || val.is_empty()
                || fields.insert(key.into(), val.into()).is_some()
            {
                return Err(ProfileError);
            }
        }
        if fields.len() != FIELDS.len()
            || value(&fields, "version")? != "1"
            || value(&fields, "integrations")? != "ssh-server,linux-system-ssh"
            || value(&fields, "methods")? != "publickey,password"
            || value(&fields, "server_version")? != "OpenSSH_10.5p1"
            || !identifier(value(&fields, "profile_id")?, 128)
            || !identifier(value(&fields, "username")?, 64)
            || value(&fields, "username")? == "root"
            || !host(value(&fields, "host")?)
            || !hex_sha256(value(&fields, "host_key_sha256")?)
        {
            return Err(ProfileError);
        }
        let port = value(&fields, "port")?.parse().map_err(|_| ProfileError)?;
        if port == 0 {
            return Err(ProfileError);
        }
        let consumer_uid = value(&fields, "consumer_uid")?
            .parse()
            .map_err(|_| ProfileError)?;
        if consumer_uid == 0 {
            return Err(ProfileError);
        }
        Ok(Self {
            fields,
            port,
            consumer_uid,
        })
    }
    /// Reads a root/provider-owned, non-writable installed profile.
    /// # Errors
    /// Rejects symlinks, wrong ownership/mode, oversized input, or invalid fields.
    pub fn read_installed(path: &Path, owner_uid: u32) -> Result<Self, ProfileError> {
        let meta = fs::symlink_metadata(path).map_err(|_| ProfileError)?;
        if !meta.file_type().is_file() || meta.uid() != owner_uid || meta.mode() & 0o177 != 0 {
            return Err(ProfileError);
        }
        Self::parse(&fs::read(path).map_err(|_| ProfileError)?)
    }
    #[must_use]
    pub fn profile_id(&self) -> &str {
        self.value("profile_id")
    }
    #[must_use]
    pub fn allows(&self, integration: &str, method: &str) -> bool {
        matches!(integration, "ssh-server" | "linux-system-ssh")
            && matches!(method, "publickey" | "password")
    }
    #[must_use]
    pub fn host(&self) -> &str {
        self.value("host")
    }
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
    #[must_use]
    pub fn username(&self) -> &str {
        self.value("username")
    }
    #[must_use]
    pub fn host_key_sha256(&self) -> &str {
        self.value("host_key_sha256")
    }
    #[must_use]
    pub const fn consumer_uid(&self) -> u32 {
        self.consumer_uid
    }
    fn value(&self, key: &str) -> &str {
        self.fields.get(key).map_or("", String::as_str)
    }
}
fn value<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, ProfileError> {
    fields.get(key).map(String::as_str).ok_or(ProfileError)
}
fn identifier(v: &str, max: usize) -> bool {
    !v.is_empty()
        && v.len() <= max
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn host(v: &str) -> bool {
    v.len() <= 253
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
        && !v.starts_with('.')
        && !v.ends_with('.')
        && !v.contains("..")
}
fn hex_sha256(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

#[derive(Debug)]
pub enum Error {
    Profile,
    Io,
    Protocol,
    Ssh,
    Unauthorized,
    Rejected,
    Challenge,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Profile => "INVALID_PROFILE",
            Self::Io | Self::Ssh => "SSH_UNAVAILABLE",
            Self::Protocol => "PROTOCOL_ERROR",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Rejected => "AUTH_REJECTED",
            Self::Challenge => "WAITING_FOR_HUMAN",
        })
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
impl From<russh::Error> for Error {
    fn from(_: russh::Error) -> Self {
        Self::Ssh
    }
}
impl From<ProfileError> for Error {
    fn from(_: ProfileError) -> Self {
        Self::Profile
    }
}

struct Verifier {
    expected: String,
    rejected: Arc<AtomicBool>,
}
impl client::Handler for Verifier {
    type Error = russh::Error;
    fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let accepted = server
            .public_key()
            .to_bytes()
            .is_ok_and(|raw| hex(digest::digest(&digest::SHA256, &raw).as_ref()) == self.expected);
        if !accepted {
            self.rejected.store(true, Ordering::SeqCst);
        }
        std::future::ready(Ok(accepted))
    }
}
struct CustodySigner<'a> {
    stream: &'a mut UnixStream,
}
#[derive(Debug)]
struct SignError;
impl From<russh::SendError> for SignError {
    fn from(_: russh::SendError) -> Self {
        Self
    }
}
impl Signer for CustodySigner<'_> {
    type Error = SignError;
    async fn auth_sign(
        &mut self,
        _key: &russh::keys::agent::AgentIdentity,
        hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        if hash_alg.is_some() || to_sign.len() > MAX_FRAME - 5 {
            to_sign.zeroize();
            return Err(SignError);
        }
        let mut request = vec![6];
        put_bytes(&mut request, &to_sign).map_err(|_| SignError)?;
        write_frame(self.stream, &request)
            .await
            .map_err(|_| SignError)?;
        request.zeroize();
        let response = read_frame(self.stream).await.map_err(|_| SignError)?;
        let mut cursor = Cursor::new(&response);
        if cursor.byte().map_err(|_| SignError)? != 7 {
            return Err(SignError);
        }
        let signature = cursor.bytes().map_err(|_| SignError)?.to_vec();
        cursor.finish().map_err(|_| SignError)?;
        to_sign.extend_from_slice(
            &u32::try_from(signature.len())
                .map_err(|_| SignError)?
                .to_be_bytes(),
        );
        to_sign.extend_from_slice(&signature);
        Ok(to_sign)
    }
}
struct Retained {
    handle: client::Handle<Verifier>,
}

/// Serves the trusted custody and consumer sockets until terminated.
/// # Errors
/// Returns a closed error without credential material on failure.
pub async fn serve(
    profile: Arc<Profile>,
    provider_socket: &Path,
    provider_uid: u32,
    consumer_socket: &Path,
) -> Result<(), Error> {
    prepare_socket(provider_socket)?;
    prepare_socket(consumer_socket)?;
    let provider = UnixListener::bind(provider_socket)?;
    fs::set_permissions(provider_socket, fs::Permissions::from_mode(0o666))?;
    let consumer = UnixListener::bind(consumer_socket)?;
    fs::set_permissions(consumer_socket, fs::Permissions::from_mode(0o666))?;
    let mut retained: BTreeMap<String, Retained> = BTreeMap::new();
    loop {
        tokio::select! {
            accepted=provider.accept()=>{
                let(mut stream,_)=accepted?;if peer_uid(&stream)?!=provider_uid{continue}
                match authenticate(&profile,&mut stream).await{
                    Ok((reference,connection,result))=>{retained.insert(reference,connection);write_frame(&mut stream,&result).await?;}
                    Err(Error::Challenge)=>{let mut r=vec![1];put_bytes(&mut r,b"additional_factor_required")?;write_frame(&mut stream,&r).await?;}
                    Err(Error::Rejected)=>write_frame(&mut stream,&[2,0,0,0,0]).await?,
                    Err(Error::Unauthorized|Error::Protocol|Error::Profile)=>write_frame(&mut stream,&[4,0,0,0,0]).await?,
                    Err(Error::Io|Error::Ssh)=>write_frame(&mut stream,&[3,0,0,0,0]).await?,
                }
            }
            accepted=consumer.accept()=>{
                let(mut stream,_)=accepted?;if peer_uid(&stream)?!=profile.consumer_uid(){continue}
                let Ok(request)=read_frame(&mut stream).await else{continue};let mut cursor=Cursor::new(&request);
                let parsed=cursor.byte().ok().filter(|v|*v==1).and_then(|_|cursor.bytes().ok()).and_then(|v|std::str::from_utf8(v).ok()).filter(|_|cursor.finish().is_ok()).map(str::to_owned);
                let Some(reference)=parsed else{continue};let Some(connection)=retained.get(&reference) else{write_frame(&mut stream,&[1]).await?;continue};
                match connection.handle.channel_open_session().await{Ok(channel)=>{channel.close().await.map_err(|_|Error::Ssh)?;write_frame(&mut stream,&[0]).await?;}Err(_)=>write_frame(&mut stream,&[1]).await?,}
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn authenticate(
    profile: &Profile,
    stream: &mut UnixStream,
) -> Result<(String, Retained, Vec<u8>), Error> {
    let request = read_frame(stream).await?;
    let mut cursor = Cursor::new(&request);
    if cursor.byte()? != 4 {
        return Err(Error::Protocol);
    }
    let _attempt = cursor.fixed(16)?;
    let _revision = cursor.fixed(16)?;
    let integration = cursor.text()?;
    let method = cursor.text()?;
    let destination = cursor.text()?;
    let context = cursor.bytes()?;
    let username = cursor.text()?;
    let public = cursor.text()?;
    let owner = cursor.fixed(16)?;
    let _generation = cursor.fixed(8)?;
    cursor.finish()?;
    if owner == [0; 16]
        || !profile.allows(integration, method)
        || destination != profile.profile_id()
        || context != profile.profile_id().as_bytes()
        || username != profile.username()
        || (method == "publickey") == public.is_empty()
    {
        return Err(Error::Unauthorized);
    }
    let public_key = if method == "publickey" {
        let parsed = PublicKey::from_openssh(public).map_err(|_| Error::Protocol)?;
        if parsed.algorithm().as_str() != "ssh-ed25519" {
            return Err(Error::Protocol);
        }
        Some(parsed)
    } else {
        None
    };
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(IO_TIMEOUT),
        ..Default::default()
    });
    let rejected = Arc::new(AtomicBool::new(false));
    let handler = Verifier {
        expected: profile.host_key_sha256().into(),
        rejected: Arc::clone(&rejected),
    };
    let mut handle = client::connect(config, (profile.host(), profile.port()), handler)
        .await
        .map_err(|error| {
            if rejected.load(Ordering::SeqCst)
                || matches!(
                    error,
                    russh::Error::UnknownKey
                        | russh::Error::WrongServerSig
                        | russh::Error::KeyChanged { .. }
                )
            {
                Error::Rejected
            } else {
                Error::Ssh
            }
        })?;
    write_frame(stream, &[5, 0, 0, 0, 0]).await?;
    let auth = if method == "password" {
        let response = read_frame(stream).await?;
        let mut cursor = Cursor::new(&response);
        if cursor.byte()? != 5 {
            return Err(Error::Protocol);
        }
        let mut password = Zeroizing::new(cursor.bytes()?.to_vec());
        cursor.finish()?;
        let text = std::str::from_utf8(&password)
            .map_err(|_| Error::Protocol)?
            .to_owned();
        let result = handle
            .authenticate_password(profile.username(), text)
            .await?;
        password.zeroize();
        result
    } else {
        let mut signer = CustodySigner { stream };
        handle
            .authenticate_publickey_with(
                profile.username(),
                public_key.ok_or(Error::Protocol)?,
                None,
                &mut signer,
            )
            .await
            .map_err(|_| Error::Protocol)?
    };
    match auth {
        client::AuthResult::Success => {
            let reference = random_reference()?;
            let observed = profile.host_key_sha256();
            let json = format!(
                "{{\"kind\":\"ssh_authenticated_connection\",\"consumer_ref\":\"{reference}\",\"host_key_sha256\":\"{observed}\",\"username\":\"{}\"}}",
                profile.username()
            );
            let mut response = vec![0];
            put_bytes(&mut response, json.as_bytes())?;
            Ok((reference, Retained { handle }, response))
        }
        client::AuthResult::Failure {
            partial_success: true,
            ..
        } => Err(Error::Challenge),
        client::AuthResult::Failure { .. } => Err(Error::Rejected),
    }
}

/// Opens and closes one post-auth session channel through an opaque reference.
/// # Errors
/// Returns rejection for invalid/dead references.
pub async fn consume(socket: &Path, reference: &str) -> Result<(), Error> {
    if reference.len() != 43
        || !reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(Error::Protocol);
    }
    let mut stream = UnixStream::connect(socket).await?;
    let mut request = vec![1];
    put_bytes(&mut request, reference.as_bytes())?;
    write_frame(&mut stream, &request).await?;
    match read_frame(&mut stream).await?.as_slice() {
        [0] => Ok(()),
        _ => Err(Error::Rejected),
    }
}
fn random_reference() -> Result<String, Error> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Io)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn prepare_socket(path: &Path) -> Result<(), Error> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let parent = path.parent().ok_or(Error::Profile)?;
    let meta = fs::symlink_metadata(parent).map_err(|_| Error::Profile)?;
    if !meta.file_type().is_dir() || meta.mode() & 0o022 != 0 {
        return Err(Error::Profile);
    }
    Ok(())
}
fn peer_uid(stream: &UnixStream) -> Result<u32, Error> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len =
        libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).map_err(|_| Error::Io)?;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(Error::Io);
    }
    Ok(cred.uid)
}
async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, Error> {
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(Error::Protocol);
    }
    let mut value = vec![0; len];
    stream.read_exact(&mut value).await?;
    Ok(value)
}
async fn write_frame(stream: &mut UnixStream, value: &[u8]) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_FRAME {
        return Err(Error::Protocol);
    }
    stream
        .write_u32(u32::try_from(value.len()).map_err(|_| Error::Protocol)?)
        .await?;
    stream.write_all(value).await?;
    stream.flush().await?;
    Ok(())
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Error::Protocol)?
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}
fn hex(value: &[u8]) -> String {
    value.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn fixed(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(len).ok_or(Error::Protocol)?;
        let value = self.bytes.get(self.at..end).ok_or(Error::Protocol)?;
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(*self.fixed(1)?.first().ok_or(Error::Protocol)?)
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len =
            u32::from_be_bytes(self.fixed(4)?.try_into().map_err(|_| Error::Protocol)?) as usize;
        if len > MAX_FRAME {
            return Err(Error::Protocol);
        }
        self.fixed(len)
    }
    fn text(&mut self) -> Result<&'a str, Error> {
        std::str::from_utf8(self.bytes()?).map_err(|_| Error::Protocol)
    }
    fn finish(&self) -> Result<(), Error> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Protocol)
        }
    }
}
