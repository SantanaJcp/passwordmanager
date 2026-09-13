// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::Shutdown,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::Arc,
    time::Duration,
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
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
use zeroize::{Zeroize, Zeroizing};

use pm_custody::{AuthenticatedHumanChannel, unix_peer_uid};
use pm_vault::{HumanCommitError, HumanVault, PasswordRecord, PreparedHumanCommand};

use crate::{Failure, take_path};

const KEY_MAGIC: &[u8] = b"PMK1";
const BOOTSTRAP_MAGIC: &[u8] = b"PMCB1";
const PROFILE_MAGIC: &[u8] = b"PMP1";
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const SPKI_BYTES: usize = 44;
const MAX_PROTECTED_BYTES: u64 = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const HUMAN_MAGIC: &[u8; 5] = b"PMH1\n";
const MAX_HUMAN_FRAME: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Agent,
    Human,
}

impl Role {
    const fn byte(self) -> u8 {
        match self {
            Self::Agent => 1,
            Self::Human => 2,
        }
    }

    fn parse(value: &OsStr) -> Result<Self, Failure> {
        match value.to_str() {
            Some("agent") => Ok(Self::Agent),
            Some("human") => Ok(Self::Human),
            _ => Err(Failure::Usage),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Human => "human",
        }
    }

    const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Agent => b"pm-agent/1",
            Self::Human => b"pm-human/1",
        }
    }
}

struct KeyMaterial {
    private: Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
}

struct Bootstrap {
    server: KeyMaterial,
    agent_uid: u32,
    agent_spki: Vec<u8>,
    human_uid: u32,
    human_spki: Vec<u8>,
}

struct Profile {
    role: Role,
    server_uid: u32,
    server_spki: Vec<u8>,
}

struct VaultService {
    path: std::path::PathBuf,
    device: [u8; 16],
}

pub(crate) fn run(arguments: Vec<OsString>) -> Result<(), Failure> {
    let mut arguments = arguments.into_iter();
    let command = arguments.next().ok_or(Failure::Usage)?;
    match command.to_str() {
        Some("keygen") => keygen(&mut arguments),
        Some("provision-bootstrap") => provision_bootstrap(&mut arguments),
        Some("provision-profile") => provision_profile(&mut arguments),
        Some("serve") => serve(&mut arguments),
        Some("serve-vault") => serve_vault(&mut arguments),
        Some("probe") => probe(&mut arguments),
        Some("human-password-crud") => human_password_crud(&mut arguments),
        _ => Err(Failure::Usage),
    }
}

fn keygen(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let private_path = take_path(arguments, "--private")?;
    let public_path = take_path(arguments, "--public")?;
    finish_arguments(arguments)?;

    let document =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| Failure::Unavailable)?;
    let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).map_err(|_| Failure::Unavailable)?;
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(pair.public_key().as_ref());
    let mut encoded =
        Vec::with_capacity(KEY_MAGIC.len() + 4 + document.as_ref().len() + SPKI_BYTES);
    encoded.extend_from_slice(KEY_MAGIC);
    push_bytes(&mut encoded, document.as_ref())?;
    encoded.extend_from_slice(&spki);

    if let Err(error) = write_new(&private_path, &encoded, 0o400) {
        encoded.zeroize();
        return Err(error);
    }
    encoded.zeroize();
    if let Err(error) = write_new(&public_path, &spki, 0o444) {
        let _ = fs::remove_file(private_path);
        return Err(error);
    }
    Ok(())
}

fn provision_bootstrap(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let path = take_path(arguments, "--path")?;
    let server_private = take_path(arguments, "--server-private")?;
    let server_public = take_path(arguments, "--server-public")?;
    let agent_public = take_path(arguments, "--agent-public")?;
    let agent_uid = take_u32(arguments, "--agent-uid")?;
    let human_public = take_path(arguments, "--human-public")?;
    let human_uid = take_u32(arguments, "--human-uid")?;
    finish_arguments(arguments)?;
    if agent_uid == human_uid || agent_uid == current_uid() || human_uid == current_uid() {
        return Err(Failure::Unavailable);
    }

    let server = read_key(&server_private, current_uid())?;
    let installed_server_spki = read_public(&server_public)?;
    if server.spki != installed_server_spki {
        return Err(Failure::Unavailable);
    }
    let agent_spki = read_public(&agent_public)?;
    let human_spki = read_public(&human_public)?;
    if agent_spki == human_spki || agent_spki == server.spki || human_spki == server.spki {
        return Err(Failure::Unavailable);
    }

    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(BOOTSTRAP_MAGIC);
    push_bytes(&mut encoded, &server.private)?;
    encoded.extend_from_slice(&server.spki);
    encoded.extend_from_slice(&agent_uid.to_be_bytes());
    encoded.extend_from_slice(&agent_spki);
    encoded.extend_from_slice(&human_uid.to_be_bytes());
    encoded.extend_from_slice(&human_spki);
    let result = write_new(&path, &encoded, 0o400);
    encoded.zeroize();
    result
}

fn provision_profile(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    if current_uid() != 0 {
        return Err(Failure::Unavailable);
    }
    let path = take_path(arguments, "--path")?;
    let server_public = take_path(arguments, "--server-public")?;
    let server_uid = take_u32(arguments, "--server-uid")?;
    let role_flag = arguments.next().ok_or(Failure::Usage)?;
    let role_value = arguments.next().ok_or(Failure::Usage)?;
    if role_flag != "--role" {
        return Err(Failure::Usage);
    }
    let role = Role::parse(&role_value)?;
    finish_arguments(arguments)?;
    if server_uid == 0 {
        return Err(Failure::Unavailable);
    }
    let server_spki = read_public(&server_public)?;
    let mut encoded = Vec::with_capacity(PROFILE_MAGIC.len() + 1 + 4 + SPKI_BYTES);
    encoded.extend_from_slice(PROFILE_MAGIC);
    encoded.push(role.byte());
    encoded.extend_from_slice(&server_uid.to_be_bytes());
    encoded.extend_from_slice(&server_spki);
    write_new(&path, &encoded, 0o444)
}

fn serve(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let bootstrap_path = take_path(arguments, "--bootstrap")?;
    let agent_socket = take_path(arguments, "--agent-socket")?;
    let human_socket = take_path(arguments, "--human-socket")?;
    finish_arguments(arguments)?;
    serve_loop(&bootstrap_path, &agent_socket, &human_socket, None)
}

fn serve_vault(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let bootstrap_path = take_path(arguments, "--bootstrap")?;
    let agent_socket = take_path(arguments, "--agent-socket")?;
    let human_socket = take_path(arguments, "--human-socket")?;
    let vault_path = take_path(arguments, "--vault")?;
    let device_value = take_path(arguments, "--device")?;
    finish_arguments(arguments)?;
    let device = decode_hex_16(&device_value)?;
    let service = VaultService {
        path: vault_path,
        device,
    };
    serve_loop(
        &bootstrap_path,
        &agent_socket,
        &human_socket,
        Some(&service),
    )
}

fn serve_loop(
    bootstrap_path: &Path,
    agent_socket: &Path,
    human_socket: &Path,
    vault: Option<&VaultService>,
) -> Result<(), Failure> {
    let bootstrap = read_bootstrap(bootstrap_path)?;
    validate_runtime_parent(agent_socket)?;
    validate_runtime_parent(human_socket)?;

    let server_key = certified_key(&bootstrap.server)?;
    let agent_config = server_config(server_key.clone(), &bootstrap.agent_spki, Role::Agent)?;
    let human_config = server_config(server_key, &bootstrap.human_spki, Role::Human)?;
    let agent_listener = bind_socket(agent_socket)?;
    let human_listener = bind_socket(human_socket)?;
    agent_listener
        .set_nonblocking(true)
        .map_err(|_| Failure::Unavailable)?;
    human_listener
        .set_nonblocking(true)
        .map_err(|_| Failure::Unavailable)?;

    loop {
        accept_one(
            &agent_listener,
            bootstrap.agent_uid,
            Role::Agent,
            &agent_config,
            None,
        );
        accept_one(
            &human_listener,
            bootstrap.human_uid,
            Role::Human,
            &human_config,
            vault,
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn probe(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    let key = read_key(&private_path, current_uid())?;

    let stream = UnixStream::connect(socket_path).map_err(|_| Failure::Unavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    let observed_uid = unix_peer_uid(&stream).map_err(|_| Failure::Unavailable)?;
    if observed_uid != profile.server_uid {
        return Err(Failure::Unavailable);
    }
    let config = client_config(&key, &profile.server_spki, profile.role)?;
    let server_name =
        ServerName::try_from("passwordmanager.invalid").map_err(|_| Failure::Unavailable)?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|_| Failure::Unavailable)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    tls.write_all(b"PING\n").map_err(|_| Failure::Unavailable)?;
    tls.flush().map_err(|_| Failure::Unavailable)?;
    let mut response = [0_u8; 5];
    tls.read_exact(&mut response)
        .map_err(|_| Failure::Unavailable)?;
    if response != *b"READY" || tls.conn.alpn_protocol() != Some(profile.role.alpn()) {
        return Err(Failure::Unavailable);
    }
    println!(
        "READY role={} peer_uid={} tls=1.3 rpk=pinned alpn={}",
        profile.role.name(),
        observed_uid,
        String::from_utf8_lossy(profile.role.alpn())
    );
    Ok(())
}

fn human_password_crud(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let profile_path = take_path(arguments, "--profile")?;
    let private_path = take_path(arguments, "--private")?;
    let socket_path = take_path(arguments, "--socket")?;
    finish_arguments(arguments)?;
    let profile = read_profile(&profile_path)?;
    if profile.role != Role::Human {
        return Err(Failure::Unavailable);
    }
    let key = read_key(&private_path, current_uid())?;
    let mut input = std::io::stdin().lock();
    let password = Zeroizing::new(read_wire_field(&mut input, 1024)?);
    let title = read_wire_string(&mut input, 1024)?;
    let username = read_wire_string(&mut input, 1024 * 1024)?;
    let secret_one = Zeroizing::new(read_wire_field(&mut input, 1024 * 1024)?);
    let destination = read_wire_string(&mut input, 8 * 1024)?;
    let notes = read_wire_string(&mut input, 1024 * 1024)?;
    let edited_title = read_wire_string(&mut input, 1024)?;
    let secret_two = Zeroizing::new(read_wire_field(&mut input, 1024 * 1024)?);

    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let prepared = rpc_prepare(
        &mut tls,
        2,
        None,
        &title,
        &username,
        &secret_one,
        &destination,
        &notes,
    )?;
    let mut changed_body = prepared.body.clone();
    *changed_body.last_mut().ok_or(Failure::Unavailable)? ^= 1;
    let changed = encode_commit_request(5, &prepared, &changed_body)?;
    write_frame(&mut tls, &changed)?;
    expect_status(&read_frame(&mut tls)?, 2)?;

    write_frame(
        &mut tls,
        &encode_commit_request(8, &prepared, &prepared.body)?,
    )?;
    let mut lost = [0_u8; 1];
    if let Ok(received) = tls.read(&mut lost)
        && received != 0
    {
        return Err(Failure::Unavailable);
    }
    drop(tls);

    let mut tls = connect(&profile, &key, &socket_path)?;
    tls.write_all(HUMAN_MAGIC)
        .map_err(|_| Failure::Unavailable)?;
    rpc_unlock(&mut tls, &password)?;
    let recovered = rpc_receipt(&mut tls, prepared.transaction_id)?;
    let replay = rpc_commit(&mut tls, &prepared)?;
    if recovered != replay {
        return Err(Failure::Unavailable);
    }
    assert_read(
        &mut tls,
        prepared.item_id,
        &title,
        &username,
        &secret_one,
        &destination,
        &notes,
    )?;
    let edited = rpc_prepare(
        &mut tls,
        3,
        Some(prepared.item_id),
        &edited_title,
        &username,
        &secret_two,
        &destination,
        &notes,
    )?;
    rpc_commit(&mut tls, &edited)?;
    assert_read(
        &mut tls,
        prepared.item_id,
        &edited_title,
        &username,
        &secret_two,
        &destination,
        &notes,
    )?;
    let deleted = rpc_prepare(&mut tls, 4, Some(prepared.item_id), "", "", &[], "", "")?;
    rpc_commit(&mut tls, &deleted)?;
    let mut read_deleted = vec![6];
    read_deleted.extend_from_slice(&prepared.item_id);
    write_frame(&mut tls, &read_deleted)?;
    expect_status(&read_frame(&mut tls)?, 3)?;
    println!("PASS human-crud-e2e receipts=3 replay=1 body-change=rejected");
    Ok(())
}

struct WirePrepared {
    transaction_id: [u8; 16],
    item_id: [u8; 16],
    command: Vec<u8>,
    body: Vec<u8>,
    signature: [u8; 64],
}

fn connect(
    profile: &Profile,
    key: &KeyMaterial,
    socket_path: &Path,
) -> Result<rustls::StreamOwned<ClientConnection, UnixStream>, Failure> {
    let stream = UnixStream::connect(socket_path).map_err(|_| Failure::Unavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    if unix_peer_uid(&stream).map_err(|_| Failure::Unavailable)? != profile.server_uid {
        return Err(Failure::Unavailable);
    }
    let config = client_config(key, &profile.server_spki, profile.role)?;
    let server_name =
        ServerName::try_from("passwordmanager.invalid").map_err(|_| Failure::Unavailable)?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|_| Failure::Unavailable)?;
    Ok(rustls::StreamOwned::new(connection, stream))
}

fn rpc_unlock(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    password: &[u8],
) -> Result<(), Failure> {
    let mut request = vec![1];
    push_bytes(&mut request, password)?;
    write_frame(tls, &request)?;
    expect_status(&read_frame(tls)?, 0)
}

#[allow(clippy::too_many_arguments)]
fn rpc_prepare(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    operation: u8,
    item: Option<[u8; 16]>,
    title: &str,
    username: &str,
    password: &[u8],
    destination: &str,
    notes: &str,
) -> Result<WirePrepared, Failure> {
    let mut request = vec![operation];
    if let Some(item) = item {
        request.extend_from_slice(&item);
    }
    if operation != 4 {
        for field in [
            title.as_bytes(),
            username.as_bytes(),
            password,
            destination.as_bytes(),
            notes.as_bytes(),
        ] {
            push_bytes(&mut request, field)?;
        }
    }
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    let transaction_id = cursor
        .fixed(16)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    let item_id = cursor
        .fixed(16)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    let command = cursor.bytes()?;
    let body = cursor.bytes()?;
    let signature = cursor
        .fixed(64)?
        .try_into()
        .map_err(|_| Failure::Unavailable)?;
    cursor.finish()?;
    Ok(WirePrepared {
        transaction_id,
        item_id,
        command,
        body,
        signature,
    })
}

fn encode_commit_request(
    opcode: u8,
    prepared: &WirePrepared,
    body: &[u8],
) -> Result<Vec<u8>, Failure> {
    let mut request = vec![opcode];
    push_bytes(&mut request, &prepared.command)?;
    request.extend_from_slice(&prepared.signature);
    push_bytes(&mut request, body)?;
    Ok(request)
}

fn rpc_commit(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    prepared: &WirePrepared,
) -> Result<Vec<u8>, Failure> {
    write_frame(tls, &encode_commit_request(5, prepared, &prepared.body)?)?;
    let response = read_frame(tls)?;
    expect_success_payload(&response)
}

fn rpc_receipt(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    transaction_id: [u8; 16],
) -> Result<Vec<u8>, Failure> {
    let mut request = vec![7];
    request.extend_from_slice(&transaction_id);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    expect_success_payload(&response)
}

#[allow(clippy::too_many_arguments)]
fn assert_read(
    tls: &mut rustls::StreamOwned<ClientConnection, UnixStream>,
    item: [u8; 16],
    title: &str,
    username: &str,
    password: &[u8],
    destination: &str,
    notes: &str,
) -> Result<(), Failure> {
    let mut request = vec![6];
    request.extend_from_slice(&item);
    write_frame(tls, &request)?;
    let response = read_frame(tls)?;
    let mut cursor = Cursor::new(&response);
    cursor.expect(&[0])?;
    for expected in [
        title.as_bytes(),
        username.as_bytes(),
        password,
        destination.as_bytes(),
        notes.as_bytes(),
    ] {
        if cursor.bytes()? != expected {
            return Err(Failure::Unavailable);
        }
    }
    cursor.finish()
}

fn expect_success_payload(response: &[u8]) -> Result<Vec<u8>, Failure> {
    if response.first() != Some(&0) || response.len() < 2 {
        return Err(Failure::Unavailable);
    }
    Ok(response[1..].to_vec())
}

fn expect_status(response: &[u8], status: u8) -> Result<(), Failure> {
    if response == [status] {
        Ok(())
    } else {
        Err(Failure::Unavailable)
    }
}

fn handle_human_rpc(
    tls: &mut rustls::StreamOwned<ServerConnection, UnixStream>,
    service: &VaultService,
    channel: AuthenticatedHumanChannel,
) -> Result<(), Failure> {
    let unlock = read_frame(tls)?;
    let mut cursor = Cursor::new(&unlock);
    cursor.expect(&[1])?;
    let mut password = Zeroizing::new(cursor.bytes()?);
    cursor.finish()?;
    let mut vault = HumanVault::unlock(&service.path, &password, service.device, channel)
        .map_err(|_| Failure::Unavailable)?;
    password.zeroize();
    write_frame(tls, &[0])?;
    loop {
        let Ok(request) = read_frame(tls) else {
            return Ok(());
        };
        let drop_response = request.first() == Some(&8);
        let response = handle_human_request(&mut vault, &request);
        if drop_response {
            let _ = tls.sock.shutdown(Shutdown::Both);
            return response.map(|_| ());
        }
        write_frame(tls, &response?)?;
    }
}

fn handle_human_request(vault: &mut HumanVault, request: &[u8]) -> Result<Vec<u8>, Failure> {
    let (&opcode, rest) = request.split_first().ok_or(Failure::Unavailable)?;
    match opcode {
        2 | 3 => {
            let mut cursor = Cursor::new(rest);
            let item = if opcode == 3 {
                Some(
                    cursor
                        .fixed(16)?
                        .try_into()
                        .map_err(|_| Failure::Unavailable)?,
                )
            } else {
                None
            };
            let record = decode_wire_record(&mut cursor)?;
            cursor.finish()?;
            let prepared = if let Some(item) = item {
                vault.prepare_edit(item, &record)
            } else {
                vault.prepare_create(&record)
            }
            .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        4 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            let prepared = vault
                .prepare_delete(item)
                .map_err(|_| Failure::Unavailable)?;
            encode_prepared(vault, &prepared)
        }
        5 | 8 => {
            let mut cursor = Cursor::new(rest);
            let command = cursor.bytes()?;
            let signature = cursor
                .fixed(64)?
                .try_into()
                .map_err(|_| Failure::Unavailable)?;
            let body = cursor.bytes()?;
            cursor.finish()?;
            match vault.commit(&command, &signature, &body) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(response)
                }
                Err(HumanCommitError::BodyChanged) => Ok(vec![2]),
                Err(_) => Ok(vec![1]),
            }
        }
        6 => {
            let item = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.read_password(item) {
                Ok(record) => {
                    let mut response = vec![0];
                    for field in [
                        record.title().as_bytes(),
                        record.username().as_bytes(),
                        record.password(),
                        record.destination().as_bytes(),
                        record.notes().as_bytes(),
                    ] {
                        push_bytes(&mut response, field)?;
                    }
                    Ok(response)
                }
                Err(HumanCommitError::ItemNotFound) => Ok(vec![3]),
                Err(_) => Ok(vec![1]),
            }
        }
        7 => {
            let transaction_id = rest.try_into().map_err(|_| Failure::Unavailable)?;
            match vault.receipt(transaction_id) {
                Ok(receipt) => {
                    let mut response = vec![0];
                    response.extend_from_slice(&receipt.to_bytes());
                    Ok(response)
                }
                Err(_) => Ok(vec![3]),
            }
        }
        _ => Err(Failure::Unavailable),
    }
}

fn encode_prepared(
    vault: &HumanVault,
    prepared: &PreparedHumanCommand,
) -> Result<Vec<u8>, Failure> {
    let signature = vault.sign(prepared).map_err(|_| Failure::Unavailable)?;
    let mut response = vec![0];
    response.extend_from_slice(prepared.transaction_id());
    response.extend_from_slice(prepared.item_id());
    push_bytes(&mut response, prepared.command())?;
    push_bytes(&mut response, prepared.body())?;
    response.extend_from_slice(&signature);
    Ok(response)
}

fn decode_wire_record(cursor: &mut Cursor<'_>) -> Result<PasswordRecord, Failure> {
    let title = cursor.bytes()?;
    let username = cursor.bytes()?;
    let mut password = Zeroizing::new(cursor.bytes()?);
    let destination = cursor.bytes()?;
    let notes = cursor.bytes()?;
    let record = PasswordRecord::new(
        std::str::from_utf8(&title).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(&username).map_err(|_| Failure::Unavailable)?,
        &password,
        std::str::from_utf8(&destination).map_err(|_| Failure::Unavailable)?,
        std::str::from_utf8(&notes).map_err(|_| Failure::Unavailable)?,
    )
    .map_err(|_| Failure::Unavailable)?;
    password.zeroize();
    Ok(record)
}

fn write_frame(output: &mut impl Write, value: &[u8]) -> Result<(), Failure> {
    if value.len() > MAX_HUMAN_FRAME {
        return Err(Failure::Unavailable);
    }
    let length = u32::try_from(value.len()).map_err(|_| Failure::Unavailable)?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|()| output.write_all(value))
        .and_then(|()| output.flush())
        .map_err(|_| Failure::Unavailable)
}

fn read_frame(input: &mut impl Read) -> Result<Vec<u8>, Failure> {
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|_| Failure::Unavailable)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Failure::Unavailable)?;
    if length == 0 || length > MAX_HUMAN_FRAME {
        return Err(Failure::Unavailable);
    }
    let mut value = vec![0_u8; length];
    input
        .read_exact(&mut value)
        .map_err(|_| Failure::Unavailable)?;
    Ok(value)
}

fn read_wire_field(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>, Failure> {
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .map_err(|_| Failure::Unavailable)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| Failure::Unavailable)?;
    if length > maximum {
        return Err(Failure::Unavailable);
    }
    let mut value = vec![0_u8; length];
    input
        .read_exact(&mut value)
        .map_err(|_| Failure::Unavailable)?;
    Ok(value)
}

fn read_wire_string(input: &mut impl Read, maximum: usize) -> Result<String, Failure> {
    String::from_utf8(read_wire_field(input, maximum)?).map_err(|_| Failure::Unavailable)
}

fn decode_hex_16(value: &Path) -> Result<[u8; 16], Failure> {
    let value = value.to_str().ok_or(Failure::Usage)?.as_bytes();
    if value.len() != 32 {
        return Err(Failure::Usage);
    }
    let mut result = [0_u8; 16];
    for (index, pair) in value.as_chunks::<2>().0.iter().enumerate() {
        result[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(result)
}

fn hex_nibble(value: u8) -> Result<u8, Failure> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Failure::Usage),
    }
}

fn accept_one(
    listener: &UnixListener,
    expected_uid: u32,
    role: Role,
    config: &Arc<ServerConfig>,
    vault: Option<&VaultService>,
) {
    let Ok((stream, _)) = listener.accept() else {
        return;
    };
    let _ = handle_connection(stream, expected_uid, role, config, vault);
}

fn handle_connection(
    stream: UnixStream,
    expected_uid: u32,
    role: Role,
    config: &Arc<ServerConfig>,
    vault: Option<&VaultService>,
) -> Result<(), Failure> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| Failure::Unavailable)?;
    if unix_peer_uid(&stream).map_err(|_| Failure::Unavailable)? != expected_uid {
        return Err(Failure::Unavailable);
    }
    let human_channel = if role == Role::Human && vault.is_some() {
        Some(
            AuthenticatedHumanChannel::authenticate(
                stream.try_clone().map_err(|_| Failure::Unavailable)?,
                expected_uid,
            )
            .map_err(|_| Failure::Unavailable)?,
        )
    } else {
        None
    };
    let connection = ServerConnection::new(config.clone()).map_err(|_| Failure::Unavailable)?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let mut request = [0_u8; 5];
    tls.read_exact(&mut request)
        .map_err(|_| Failure::Unavailable)?;
    if tls.conn.alpn_protocol() != Some(role.alpn()) {
        return Err(Failure::Unavailable);
    }
    if request == *HUMAN_MAGIC && role == Role::Human {
        let service = vault.ok_or(Failure::Unavailable)?;
        return handle_human_rpc(
            &mut tls,
            service,
            human_channel.ok_or(Failure::Unavailable)?,
        );
    }
    if request != *b"PING\n" {
        return Err(Failure::Unavailable);
    }
    tls.write_all(b"READY").map_err(|_| Failure::Unavailable)?;
    tls.flush().map_err(|_| Failure::Unavailable)
}

fn crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    provider
}

fn certified_key(key: &KeyMaterial) -> Result<Arc<CertifiedKey>, Failure> {
    let provider = crypto_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.private.to_vec(),
        )))
        .map_err(|_| Failure::Unavailable)?;
    let derived = signing_key.public_key().ok_or(Failure::Unavailable)?;
    if derived.as_ref() != key.spki {
        return Err(Failure::Unavailable);
    }
    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(key.spki.clone())],
        signing_key,
    )))
}

fn server_config(
    key: Arc<CertifiedKey>,
    expected_client_spki: &[u8],
    role: Role,
) -> Result<Arc<ServerConfig>, Failure> {
    let provider = crypto_provider();
    let algorithms = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinnedClientVerifier {
        expected: expected_client_spki.to_vec(),
        algorithms,
    });
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| Failure::Unavailable)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(key)));
    config.alpn_protocols = vec![role.alpn().to_vec()];
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    Ok(Arc::new(config))
}

fn client_config(
    key: &KeyMaterial,
    expected_server_spki: &[u8],
    role: Role,
) -> Result<ClientConfig, Failure> {
    let certified = certified_key(key)?;
    let provider = crypto_provider();
    let algorithms = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinnedServerVerifier {
        expected: expected_server_spki.to_vec(),
        algorithms,
    });
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|_| Failure::Unavailable)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified)));
    config.alpn_protocols = vec![role.alpn().to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

#[derive(Debug)]
struct PinnedServerVerifier {
    expected: Vec<u8>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        verify_pin(end_entity, intermediates, &self.expected)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_raw_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct PinnedClientVerifier {
    expected: Vec<u8>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        verify_pin(end_entity, intermediates, &self.expected)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_raw_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn verify_pin(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    expected: &[u8],
) -> Result<(), TlsError> {
    if !intermediates.is_empty() || end_entity.as_ref() != expected {
        return Err(TlsError::InvalidCertificate(
            CertificateError::UnknownIssuer,
        ));
    }
    Ok(())
}

fn verify_raw_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    algorithms: &rustls::crypto::WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, TlsError> {
    let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
    verify_tls13_signature_with_raw_key(message, &spki, dss, algorithms)
}

fn read_key(path: &Path, expected_uid: u32) -> Result<KeyMaterial, Failure> {
    let encoded = read_regular(path, expected_uid, 0o400)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(KEY_MAGIC)?;
    let private = Zeroizing::new(cursor.bytes()?);
    let spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    validate_spki(&spki)?;
    Ok(KeyMaterial { private, spki })
}

fn read_bootstrap(path: &Path) -> Result<Bootstrap, Failure> {
    let encoded = read_regular(path, current_uid(), 0o400)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(BOOTSTRAP_MAGIC)?;
    let private = Zeroizing::new(cursor.bytes()?);
    let server_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let agent_uid = cursor.u32()?;
    let agent_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    let human_uid = cursor.u32()?;
    let human_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    for spki in [&server_spki, &agent_spki, &human_spki] {
        validate_spki(spki)?;
    }
    if agent_uid == human_uid
        || agent_uid == current_uid()
        || human_uid == current_uid()
        || agent_spki == human_spki
        || agent_spki == server_spki
        || human_spki == server_spki
    {
        return Err(Failure::Unavailable);
    }
    Ok(Bootstrap {
        server: KeyMaterial {
            private,
            spki: server_spki,
        },
        agent_uid,
        agent_spki,
        human_uid,
        human_spki,
    })
}

fn read_profile(path: &Path) -> Result<Profile, Failure> {
    let encoded = read_regular(path, 0, 0o444)?;
    let mut cursor = Cursor::new(&encoded);
    cursor.expect(PROFILE_MAGIC)?;
    let role = match cursor.fixed(1)?[0] {
        1 => Role::Agent,
        2 => Role::Human,
        _ => return Err(Failure::Unavailable),
    };
    let server_uid = cursor.u32()?;
    let server_spki = cursor.fixed(SPKI_BYTES)?.to_vec();
    cursor.finish()?;
    validate_spki(&server_spki)?;
    if server_uid == 0 {
        return Err(Failure::Unavailable);
    }
    Ok(Profile {
        role,
        server_uid,
        server_spki,
    })
}

fn read_public(path: &Path) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    let encoded = read_regular(path, metadata.uid(), 0o444)?;
    validate_spki(&encoded)?;
    Ok(encoded.to_vec())
}

fn read_regular(
    path: &Path,
    expected_uid: u32,
    expected_mode: u32,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let metadata = file.metadata().map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != expected_mode
        || metadata.nlink() != 1
        || !(1..=MAX_PROTECTED_BYTES).contains(&metadata.len())
    {
        return Err(Failure::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| Failure::Unavailable)?,
    ));
    file.read_to_end(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(Failure::Unavailable);
    }
    Ok(bytes)
}

fn validate_spki(spki: &[u8]) -> Result<(), Failure> {
    if spki.len() != SPKI_BYTES || !spki.starts_with(ED25519_SPKI_PREFIX) {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| Failure::Unavailable)?;
        file.write_all(bytes).map_err(|_| Failure::Unavailable)?;
        file.sync_all().map_err(|_| Failure::Unavailable)?;
        let parent = path.parent().ok_or(Failure::Unavailable)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| Failure::Unavailable)
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}

fn validate_runtime_parent(socket: &Path) -> Result<(), Failure> {
    let parent = socket.parent().ok_or(Failure::Unavailable)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| Failure::Unavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != current_uid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

fn bind_socket(path: &Path) -> Result<UnixListener, Failure> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == current_uid() => {
            fs::remove_file(path).map_err(|_| Failure::Unavailable)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Err(Failure::Unavailable),
    }
    let listener = UnixListener::bind(path).map_err(|_| Failure::Unavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))
        .map_err(|_| Failure::Unavailable)?;
    Ok(listener)
}

fn take_u32(arguments: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<u32, Failure> {
    let value = take_path(arguments, flag)?;
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or(Failure::Usage)
}

fn finish_arguments(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    if arguments.next().is_none() {
        Ok(())
    } else {
        Err(Failure::Usage)
    }
}

fn current_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Failure> {
    let length = u32::try_from(bytes.len()).map_err(|_| Failure::Unavailable)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), Failure> {
        if self.fixed(expected.len())? == expected {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }

    fn u32(&mut self) -> Result<u32, Failure> {
        let bytes: [u8; 4] = self
            .fixed(4)?
            .try_into()
            .map_err(|_| Failure::Unavailable)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Failure> {
        let length = usize::try_from(self.u32()?).map_err(|_| Failure::Unavailable)?;
        Ok(self.fixed(length)?.to_vec())
    }

    fn fixed(&mut self, length: usize) -> Result<&'a [u8], Failure> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Failure::Unavailable)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Failure::Unavailable)?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), Failure> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Failure::Unavailable)
        }
    }
}
