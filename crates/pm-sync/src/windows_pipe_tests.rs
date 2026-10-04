// SPDX-License-Identifier: AGPL-3.0-only
//! Native regression: an authenticated reply remains valid after server close.
use super::*;
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{
    cell::RefCell,
    os::windows::io::{FromRawHandle, IntoRawHandle},
    ptr,
    sync::mpsc,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
    System::{
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
        },
        Threading::GetCurrentProcessId,
    },
};

thread_local! {
    static CLOSE_AFTER_RESPONSE: RefCell<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>> = const { RefCell::new(None) };
}

pub(super) fn after_response(handle: HANDLE) {
    CLOSE_AFTER_RESPONSE.with(|hook| {
        if let Some((close, closed)) = hook.borrow_mut().take() {
            close.send(()).unwrap();
            closed.recv_timeout(Duration::from_secs(30)).unwrap();
            let mut pid = 0;
            let queried = unsafe { GetNamedPipeServerProcessId(handle, &raw mut pid) };
            let query_error = if queried == 0 { unsafe { GetLastError() } } else { 0 };
            let peek = unsafe { PeekNamedPipe(handle, ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
            let peek_error = if peek == 0 { unsafe { GetLastError() } } else { 0 };
            eprintln!("PIPE_LIFECYCLE closed=checked pid_query_ok={} pid_query_error={query_error} pid_same={} peek_ok={} peek_error={peek_error}", queried != 0, pid == unsafe { GetCurrentProcessId() }, peek != 0);
            // The production verification also requires liveness, even if the
            // kernel retains the original PID after the server handle closes.
            assert_eq!(peek, 0);
            assert_eq!(peek_error, ERROR_BROKEN_PIPE);
            if queried != 0 {
                assert_eq!(pid, unsafe { GetCurrentProcessId() });
            }
        }
    });
}

fn key() -> Key {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(pair.public_key().as_ref());
    Key {
        private: ProtectedBytes::new(document.as_ref().to_vec()).unwrap(),
        spki,
    }
}

fn pipe(name: &str) -> fs::File {
    let sid = std::env::var("PMW1_TEST_SID").expect("native harness must supply its creator SID");
    assert!(sid.starts_with("S-1-5-21-"));
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let sddl = wide(&format!("O:{sid}G:{sid}D:P(A;;GA;;;{sid})"));
    let mut descriptor = ptr::null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        },
        0
    );
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name = wide(name);
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            &raw const security,
        )
    };
    assert!(unsafe { LocalFree(descriptor) }.is_null());
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    unsafe { fs::File::from_raw_handle(handle) }
}

#[test]
fn authenticated_response_survives_checked_server_close() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!(r"\\.\pipe\pm-sync-{stamp:032x}");
    let pipe = pipe(&name);
    let server_key = key();
    let client_key = key();
    let server = server_config(
        certified(&server_key).unwrap(),
        vec![client_key.spki.clone()],
    )
    .unwrap();
    let client = client_config(&client_key, &server_key.spki).unwrap();
    let (close, close_requested) = mpsc::channel();
    let (closed, close_finished) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        use std::os::windows::io::AsRawHandle;
        if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) } == 0 {
            assert_eq!(unsafe { GetLastError() }, ERROR_PIPE_CONNECTED);
        }
        let mut tls = rustls::StreamOwned::new(ServerConnection::new(server).unwrap(), pipe);
        assert_eq!(read_frame(&mut tls).unwrap(), br#"{"synthetic":"request"}"#);
        assert_eq!(tls.conn.alpn_protocol(), Some(ALPN));
        write_frame(&mut tls, br#"{"ok":true}"#).unwrap();
        close_requested
            .recv_timeout(Duration::from_secs(30))
            .unwrap();
        assert_ne!(unsafe { CloseHandle(tls.sock.into_raw_handle()) }, 0);
        closed.send(()).unwrap();
    });
    CLOSE_AFTER_RESPONSE.with(|hook| *hook.borrow_mut() = Some((close, close_finished)));
    let response = client_exchange(Path::new(&name), client, br#"{"synthetic":"request"}"#);
    worker.join().unwrap();
    assert_eq!(
        response,
        Ok(br#"{"ok":true}"#.to_vec()),
        "post-response liveness must not reject a completed authenticated exchange"
    );
}

#[test]
fn real_session_rechecks_acl_between_rpcs_without_replay() {
    use pm_sync::{ProcessTlsTransport, SyncTransport};
    use std::os::windows::io::AsRawHandle;

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!(r"\\.\pipe\pm-sync-{stamp:032x}");
    let directory = std::env::temp_dir().join(format!("pmw1g-phase8-session-{stamp:032x}"));
    fs::create_dir(&directory).unwrap();
    let server_key = key();
    let client_key = key();
    let private_path = directory.join("synthetic-client.key");
    let public_path = directory.join("synthetic-server.pub");
    let mut private = pm_native_channel::create_private_file(&private_path, false, true).unwrap();
    private.write_all(MAGIC).unwrap();
    private
        .write_all(
            &u32::try_from(client_key.private.len())
                .unwrap()
                .to_be_bytes(),
        )
        .unwrap();
    private.write_all(&client_key.private).unwrap();
    private.write_all(&client_key.spki).unwrap();
    private.sync_all().unwrap();
    drop(private);
    let mut public = pm_native_channel::create_private_file(&public_path, false, true).unwrap();
    public.write_all(&server_key.spki).unwrap();
    public.sync_all().unwrap();
    drop(public);
    let database_path = directory.join("synthetic-opaque.sqlite3");
    let store = OpaqueSyncStore::create(&database_path).unwrap();
    let namespace = [0x87; 32];
    store.authorize(namespace, &client_key.spki).unwrap();
    let config = server_config(
        certified(&server_key).unwrap(),
        vec![client_key.spki.clone()],
    )
    .unwrap();
    let pipe = pipe(&name);
    let worker = std::thread::spawn(move || {
        let store = store.session_connection().unwrap();
        if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), ptr::null_mut()) } == 0 {
            assert_eq!(unsafe { GetLastError() }, ERROR_PIPE_CONNECTED);
        }
        let mut tls = rustls::StreamOwned::new(ServerConnection::new(config).unwrap(), pipe);
        for ordinal in 0..2 {
            let request = read_frame(&mut tls).unwrap();
            let peer = tls.conn.peer_certificates().unwrap()[0].as_ref().to_vec();
            assert_eq!(peer, client_key.spki);
            assert_eq!(tls.conn.alpn_protocol(), Some(ALPN));
            let response = dispatch(&store, &peer, std::str::from_utf8(&request).unwrap()).unwrap();
            if ordinal == 0 {
                assert_eq!(response, ok());
                // The committed first RPC is visible before replying or closing
                // TLS, through an independent connection that is genuinely RO.
                let observer = rusqlite::Connection::open_with_flags(
                    &database_path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .unwrap();
                let committed: Vec<u8> = observer
                    .query_row("SELECT bytes FROM blocks", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(committed, b"phase8-synthetic-ciphertext");
                observer.close().unwrap();
            } else {
                assert_eq!(response, "{\"ok\":false,\"code\":\"unavailable\"}");
            }
            write_frame(&mut tls, response.as_bytes()).unwrap();
            if ordinal == 0 {
                let database = rusqlite::Connection::open(&database_path).unwrap();
                assert_eq!(
                    database
                        .execute(
                            "DELETE FROM namespaces WHERE namespace=?1 AND client_rpk=?2",
                            rusqlite::params![namespace.as_slice(), peer]
                        )
                        .unwrap(),
                    1
                );
                database.close().unwrap();
            }
        }
        store.close().unwrap();
        assert_ne!(unsafe { CloseHandle(tls.sock.into_raw_handle()) }, 0);
    });
    let program = PathBuf::from(
        std::env::var_os("PMW1_SYNC_BINARY")
            .expect("native harness must supply its inspected sync binary"),
    );
    let transport = ProcessTlsTransport::authenticated_session(
        &program,
        Path::new(&name),
        &private_path,
        &public_path,
    );
    let bytes = b"phase8-synthetic-ciphertext";
    let hash = digest(bytes);
    assert!(transport.put(namespace, hash, bytes).is_ok());
    assert!(matches!(
        transport.get(namespace, hash),
        Err(SyncError::Unavailable)
    ));
    // The failed RPC has already aborted/reaped its one owned session. No
    // follow-up attempt is made; the one server pipe saw exactly two requests.
    transport.finish().unwrap();
    worker.join().unwrap();
    fs::remove_dir_all(directory).unwrap();
}
