// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic fixture client; all mutations use the ordinary authenticated human wire.
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows native fixture requires Windows");
    std::process::exit(2);
}
#[cfg(windows)]
fn main() {
    if fixture::run().is_err() {
        eprintln!("WINDOWS_HUMAN_FIXTURE_FAILED");
        std::process::exit(1);
    }
}
#[cfg(windows)]
#[path = "../../pm-native-channel/examples/windows_tui_fixture/acl.rs"]
mod acl;
#[cfg(windows)]
mod fixture {
    use pm_crypto::{NativeStdin, ProtectedBytes};
    use pm_native_channel::{WindowsClientPipe, WindowsEndpoint};
    use pm_vault::{
        Attachment, AuthRecord, CustomField, Destination, HumanMetadata, LogicalRecord,
        LogicalValue, PrivateKeyFormat, RecordKind, SourceEncoding, SourceField, TotpAlgorithm,
    };
    use rustls::{
        CertificateError, DigitallySignedStruct, Error as TlsError, SignatureScheme,
        client::{
            AlwaysResolvesClientRawPublicKeys, ClientConfig, ClientConnection, Resumption,
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        },
        crypto::{CryptoProvider, verify_tls13_signature_with_raw_key},
        pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
            UnixTime,
        },
        sign::CertifiedKey,
        version,
    };
    use std::{
        io::{Read, Write},
        path::Path,
        sync::Arc,
    };
    #[derive(Debug)]
    pub(super) enum Failure {
        Unavailable,
    }
    struct KeyMaterial {
        private: ProtectedBytes,
        spki: Vec<u8>,
    }
    #[derive(Clone, Copy)]
    enum Role {
        Human,
    }
    impl Role {
        fn alpn(self) -> &'static [u8] {
            b"pm-human/1"
        }
    }
    type Tls = rustls::StreamOwned<ClientConnection, WindowsClientPipe>;
    fn observe<T>(
        stage: &'static str,
        enabled: bool,
        result: Result<T, Failure>,
    ) -> Result<T, Failure> {
        if enabled {
            eprintln!(
                "NATIVE_TRANSFER stage={stage} result={}",
                if result.is_ok() { "pass" } else { "fail" }
            );
        }
        result
    }

    fn io_category(error: &std::io::Error) -> &'static str {
        match error.kind() {
            std::io::ErrorKind::UnexpectedEof => "eof",
            std::io::ErrorKind::BrokenPipe => "broken-pipe",
            std::io::ErrorKind::PermissionDenied => "permission",
            std::io::ErrorKind::InvalidData => "invalid-data",
            std::io::ErrorKind::TimedOut => "timeout",
            std::io::ErrorKind::ConnectionReset => "connection-reset",
            _ => "other",
        }
    }
    fn bytes(request: &mut Vec<u8>, value: &[u8]) -> Result<(), Failure> {
        request.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        );
        request.extend_from_slice(value);
        Ok(())
    }
    fn send(tls: &mut Tls, value: &[u8]) -> Result<(), Failure> {
        if value.len() > 1024 * 1024 {
            return Err(Failure::Unavailable);
        }
        tls.write_all(
            &u32::try_from(value.len())
                .map_err(|_| Failure::Unavailable)?
                .to_be_bytes(),
        )
        .and_then(|()| tls.write_all(value))
        .and_then(|()| tls.flush())
        .map_err(|_| Failure::Unavailable)
    }
    fn receive(tls: &mut Tls) -> Result<ProtectedBytes, Failure> {
        let mut header = [0; 4];
        tls.read_exact(&mut header)
            .map_err(|_| Failure::Unavailable)?;
        let n = u32::from_be_bytes(header) as usize;
        if n > 1024 * 1024 {
            return Err(Failure::Unavailable);
        }
        let mut data = ProtectedBytes::zeroed(n).map_err(|_| Failure::Unavailable)?;
        tls.read_exact(&mut data)
            .map_err(|_| Failure::Unavailable)?;
        Ok(data)
    }
    fn success(tls: &mut Tls) -> Result<ProtectedBytes, Failure> {
        let value = receive(tls)?;
        if value.first() != Some(&0) {
            return Err(Failure::Unavailable);
        }
        Ok(value)
    }
    struct Cursor<'a> {
        value: &'a [u8],
        at: usize,
    }
    impl<'a> Cursor<'a> {
        fn fixed(&mut self, n: usize) -> Result<&'a [u8], Failure> {
            let end = self.at.checked_add(n).ok_or(Failure::Unavailable)?;
            let value = self.value.get(self.at..end).ok_or(Failure::Unavailable)?;
            self.at = end;
            Ok(value)
        }
        fn bytes(&mut self) -> Result<&'a [u8], Failure> {
            let n = u32::from_be_bytes(
                self.fixed(4)?
                    .try_into()
                    .map_err(|_| Failure::Unavailable)?,
            ) as usize;
            self.fixed(n)
        }
        fn finish(&self) -> Result<(), Failure> {
            if self.at == self.value.len() {
                Ok(())
            } else {
                Err(Failure::Unavailable)
            }
        }
    }
    fn read_file(path: &Path) -> Result<Vec<u8>, Failure> {
        use std::os::windows::io::IntoRawHandle;
        let mut file =
            pm_native_channel::open_regular_file(path).map_err(|_| Failure::Unavailable)?;
        let operation = (|| {
            let n = file.metadata().map_err(|_| Failure::Unavailable)?.len();
            if n == 0 || n > 65536 {
                return Err(Failure::Unavailable);
            }
            let mut value = Vec::new();
            file.read_to_end(&mut value)
                .map_err(|_| Failure::Unavailable)?;
            if value.len() as u64 != n {
                return Err(Failure::Unavailable);
            }
            Ok(value)
        })();
        let closed = unsafe { windows_sys::Win32::Foundation::CloseHandle(file.into_raw_handle()) };
        if closed == 0 {
            return Err(Failure::Unavailable);
        }
        operation
    }
    fn connect(profile: &Path, private: &Path, vault: &str) -> Result<Tls, Failure> {
        let p = read_file(profile)?;
        if p.len() != 50 || &p[..6] != b"PMWP1\x02" {
            return Err(Failure::Unavailable);
        }
        let encoded = read_file(private)?;
        let decoded =
            pm_native_channel::dpapi_unprotect(&encoded).map_err(|_| Failure::Unavailable)?;
        let mut c = Cursor {
            value: &decoded,
            at: 0,
        };
        if c.fixed(5)? != b"PMWK1" {
            return Err(Failure::Unavailable);
        }
        let key = KeyMaterial {
            private: ProtectedBytes::copy_from_slice(c.bytes()?)
                .map_err(|_| Failure::Unavailable)?,
            spki: c.fixed(44)?.to_vec(),
        };
        c.finish()?;
        let config = client_config(&key, &p[6..], Role::Human)?;
        let connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("passwordmanager.invalid").map_err(|_| Failure::Unavailable)?,
        )
        .map_err(|_| Failure::Unavailable)?;
        let pipe = WindowsClientPipe::connect_installed(WindowsEndpoint::Human, vault)
            .map_err(|_| Failure::Unavailable)?;
        Ok(rustls::StreamOwned::new(connection, pipe))
    }
    fn close_tls(tls: Tls) -> Result<(), Failure> {
        // Installed mode owns only this pipe handle. Consume it so its inherited
        // unchecked Drop cannot mask the fixture's explicit close result.
        let sock = std::mem::ManuallyDrop::new(tls.sock);
        if unsafe { windows_sys::Win32::Foundation::CloseHandle(sock.raw_handle()) } == 0 {
            Err(Failure::Unavailable)
        } else {
            Ok(())
        }
    }
    fn reject_agent_on_human_pipe(vault: &str) -> Result<(), Failure> {
        use std::ptr;
        use windows_sys::Win32::{
            Foundation::{
                CloseHandle, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, GetLastError,
                INVALID_HANDLE_VALUE,
            },
            Storage::FileSystem::{
                CreateFileW, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
            },
        };
        let name = WindowsEndpoint::Human
            .pipe_name(vault)
            .map_err(|_| Failure::Unavailable)?;
        let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            let closed = unsafe { CloseHandle(handle) } != 0;
            eprintln!(
                "NATIVE_PEER connected-unexpected=true cleanup-failed={}",
                !closed
            );
            return Err(Failure::Unavailable);
        }
        if unsafe { GetLastError() } != ERROR_ACCESS_DENIED {
            return Err(Failure::Unavailable);
        }
        match WindowsClientPipe::connect_installed(WindowsEndpoint::Human, vault) {
            Err(_) => {}
            Ok(pipe) => {
                let pipe = std::mem::ManuallyDrop::new(pipe);
                let closed = unsafe { CloseHandle(pipe.raw_handle()) } != 0;
                eprintln!(
                    "NATIVE_PEER installed-connect-unexpected=true cleanup-failed={}",
                    !closed
                );
                return Err(Failure::Unavailable);
            }
        }
        println!(
            "PASS windows-peer-negative agent-human-pipe=access-denied installed-connect=rejected"
        );
        Ok(())
    }

    fn reject_impostor_server(vault: &str, sddl: &str, service_pid: u32) -> Result<(), Failure> {
        use std::ptr;
        use windows_sys::Win32::{
            Foundation::{
                CloseHandle, ERROR_FILE_NOT_FOUND, GetLastError, INVALID_HANDLE_VALUE, LocalFree,
            },
            Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
                },
                SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::{
                FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
            },
            System::{
                Pipes::{
                    CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
                    WaitNamedPipeW,
                },
                Threading::GetCurrentProcessId,
            },
        };
        let current_pid = unsafe { GetCurrentProcessId() };
        if service_pid == 0 || service_pid == current_pid {
            return Err(Failure::Unavailable);
        }
        let name = WindowsEndpoint::Human
            .pipe_name(vault)
            .map_err(|_| Failure::Unavailable)?;
        let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let sddl = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let attributes_size = u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| Failure::Unavailable)?;
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(Failure::Unavailable);
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: attributes_size,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let server = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                &raw const attributes,
            )
        };
        let descriptor_released = unsafe { LocalFree(descriptor) }.is_null();
        if server == INVALID_HANDLE_VALUE {
            eprintln!(
                "NATIVE_PID stage=create result=fail descriptor-released={descriptor_released}"
            );
            return Err(Failure::Unavailable);
        }
        let operation = (|| {
            if !descriptor_released {
                return Err(Failure::Unavailable);
            }
            eprintln!("NATIVE_PID stage=create result=pass descriptor-released=true");
            let mut observed_pid = 0;
            if unsafe { GetNamedPipeServerProcessId(server, &raw mut observed_pid) } == 0
                || observed_pid != current_pid
                || observed_pid == service_pid
            {
                eprintln!("NATIVE_PID stage=native-server result=fail");
                return Err(Failure::Unavailable);
            }
            if unsafe { WaitNamedPipeW(name.as_ptr(), 0) } == 0 {
                eprintln!("NATIVE_PID stage=available result=fail");
                return Err(Failure::Unavailable);
            }
            eprintln!(
                "NATIVE_PID stage=native-server result=pass differs-from-scm=true available=true"
            );
            match WindowsClientPipe::connect_installed(WindowsEndpoint::Human, vault) {
                Err(_) => {}
                Ok(pipe) => {
                    let pipe = std::mem::ManuallyDrop::new(pipe);
                    let closed = unsafe { CloseHandle(pipe.raw_handle()) } != 0;
                    eprintln!(
                        "NATIVE_PID stage=installed-reject result=fail client-closed={closed}"
                    );
                    return Err(Failure::Unavailable);
                }
            }
            // Require kernel evidence that the installed client actually opened
            // this instance; an unavailable pipe or unrelated error cannot pass.
            let mut client_pid = 0;
            if unsafe { GetNamedPipeClientProcessId(server, &raw mut client_pid) } == 0
                || client_pid != current_pid
            {
                eprintln!("NATIVE_PID stage=native-client result=fail");
                return Err(Failure::Unavailable);
            }
            eprintln!("NATIVE_PID stage=installed-reject result=pass native-client-observed=true");
            Ok(())
        })();
        let closed = unsafe { CloseHandle(server) } != 0;
        let absent = unsafe { WaitNamedPipeW(name.as_ptr(), 0) } == 0
            && unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND;
        eprintln!("NATIVE_PID stage=cleanup server-closed={closed} endpoint-absent={absent}");
        if !closed || !absent {
            return Err(Failure::Unavailable);
        }
        operation?;
        println!(
            "PASS windows-pid-negative native-server=impostor installed-connect=rejected client-observed=1 endpoint-absent=1"
        );
        Ok(())
    }

    pub(super) fn run() -> Result<(), Failure> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() == 2 && args[0] == "--peer-negative" {
            return reject_agent_on_human_pipe(&args[1]);
        }
        if args.len() == 4 && args[0] == "--pid-negative" {
            return reject_impostor_server(
                &args[1],
                &args[2],
                args[3].parse().map_err(|_| Failure::Unavailable)?,
            );
        }
        if !(args.len() == 3 || (args.len() == 5 && args[3] == "--transfer-negative")) {
            return Err(Failure::Unavailable);
        }
        let mut input = NativeStdin::open().map_err(|_| Failure::Unavailable)?;
        let mut password = ProtectedBytes::zeroed(1025).map_err(|_| Failure::Unavailable)?;
        let mut used = 0;
        loop {
            if used == password.len() {
                return Err(Failure::Unavailable);
            }
            let n = input
                .read(&mut password[used..])
                .map_err(|_| Failure::Unavailable)?;
            if n == 0 {
                break;
            }
            used += n;
        }
        if used >= 2 && &password[used - 2..used] == b"\r\n" {
            used -= 2;
        } else if used >= 1 && password[used - 1] == b'\n' {
            used -= 1;
        }
        if used == 0 {
            return Err(Failure::Unavailable);
        }
        let negative = args.len() == 5;
        let mut tls = observe(
            "connect",
            negative,
            connect(Path::new(&args[0]), Path::new(&args[1]), &args[2]),
        )?;
        let operation = (|| {
            observe(
                "magic",
                negative,
                tls.write_all(b"PMH1\n").map_err(|_| Failure::Unavailable),
            )?;
            let mut unlock = zeroize::Zeroizing::new(vec![1]);
            bytes(&mut unlock, &password[..used])?;
            observe("unlock-sent", negative, send(&mut tls, &unlock))?;
            if *observe("unlock-response", negative, success(&mut tls))? != [0] {
                return Err(Failure::Unavailable);
            }
            if args.len() == 5 {
                let token: &[u8] = match args[4].as_str() {
                    "null" => &[0; 8],
                    "invalid-handle" => &[0xff; 8],
                    "thread-pseudohandle" => &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe],
                    "malformed-token" => &[0; 7],
                    _ => return Err(Failure::Unavailable),
                };
                observe("request31", true, send(&mut tls, &[31, 0]))?;
                if *observe("ack31", true, success(&mut tls))? != [0] {
                    return Err(Failure::Unavailable);
                }
                crate::acl::with_exact_human_lease(|| {
                    send(&mut tls, token).map_err(|_| {
                        eprintln!("NATIVE_TRANSFER stage=token-sent result=fail");
                        std::io::Error::other("negative transfer token could not be sent")
                    })?;
                    eprintln!("NATIVE_TRANSFER stage=token-sent result=pass");
                    let mut header = [0; 4];
                    match tls.read_exact(&mut header) {
                        Err(error) => {
                            eprintln!(
                                "NATIVE_TRANSFER stage=peer-read category={}",
                                io_category(&error)
                            );
                            use windows_sys::Win32::{
                                Foundation::{ERROR_BROKEN_PIPE, GetLastError},
                                System::Pipes::PeekNamedPipe,
                            };
                            let native_broken = error.kind() == std::io::ErrorKind::BrokenPipe
                                && error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32);
                            if error.kind() == std::io::ErrorKind::UnexpectedEof || native_broken {
                                // Corroborate transport EOF with the native pipe state:
                                // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe
                                let peer_closed = unsafe {
                                    PeekNamedPipe(tls.sock.raw_handle(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
                                } == 0 && unsafe { GetLastError() } == ERROR_BROKEN_PIPE;
                                eprintln!("NATIVE_TRANSFER stage=peer-closure native-confirmed={peer_closed}");
                                if peer_closed { Ok(()) } else { Err(std::io::Error::other("native pipe did not confirm peer closure")) }
                            } else {
                                Err(std::io::Error::other(
                                    "negative transfer failed outside peer EOF",
                                ))
                            }
                        }
                        Ok(()) => {
                            eprintln!("NATIVE_TRANSFER stage=peer-read category=response");
                            Err(std::io::Error::other(
                                "negative transfer returned a response instead of closing",
                            ))
                        }
                    }
                })
                .map_err(|_| Failure::Unavailable)?;
                return Ok(());
            }
            let records = content_fixture_records()?;
            for expected in records {
                let encoded = expected.to_bytes().map_err(|_| Failure::Unavailable)?;
                let mut request = vec![9];
                bytes(&mut request, &encoded)?;
                send(&mut tls, &request)?;
                let prepared = success(&mut tls)?;
                let mut c = Cursor {
                    value: &prepared,
                    at: 1,
                };
                c.fixed(16)?;
                let id = c.fixed(16)?.to_vec();
                let command = c.bytes()?;
                let body = c.bytes()?;
                let signature = c.fixed(64)?;
                c.finish()?;
                let mut commit = vec![5];
                bytes(&mut commit, command)?;
                commit.extend_from_slice(signature);
                bytes(&mut commit, body)?;
                send(&mut tls, &commit)?;
                success(&mut tls)?;
                let mut read = vec![10];
                read.extend_from_slice(&id);
                send(&mut tls, &read)?;
                let actual = success(&mut tls)?;
                if LogicalRecord::from_bytes(&actual[1..]).map_err(|_| Failure::Unavailable)?
                    != expected
                {
                    return Err(Failure::Unavailable);
                }
            }
            send(&mut tls, &[14])?;
            if *success(&mut tls)? != [0] {
                return Err(Failure::Unavailable);
            }
            Ok(())
        })();
        let closed = observe("close", negative, close_tls(tls));
        operation.and(closed)?;
        if args.len() == 5 {
            println!(
                "PASS windows-transfer-negative case={} ack31=accepted peer-eof=1 dacl-before-during-after=exact",
                args[4]
            );
        } else {
            println!("PASS windows-tui-seed types=7 ordinary-human-wire=1 readback=exact");
        }
        Ok(())
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
        if signing_key
            .public_key()
            .ok_or(Failure::Unavailable)?
            .as_ref()
            != key.spki
        {
            return Err(Failure::Unavailable);
        }
        Ok(Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(key.spki.clone())],
            signing_key,
        )))
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
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            algorithms,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn content_fixture_records() -> Result<Vec<LogicalRecord>, Failure> {
        let metadata = |title: &str, notes: &str| -> Result<HumanMetadata, Failure> {
            Ok(HumanMetadata {
                title: title.to_owned(),
                destinations: vec![Destination {
                    label: "Portal 🌎".to_owned(),
                    value: "https://e2e.invalid/雪".to_owned(),
                }],
                tags: vec!["synthetic".to_owned()],
                favorite: false,
                notes: pm_crypto::ProtectedText::copy_from_str(notes)
                    .map_err(|_| Failure::Unavailable)?,
                fields: vec![CustomField {
                    id: [0x61; 16],
                    label: "extra".to_owned(),
                    value: LogicalValue::Text(
                        pm_crypto::ProtectedText::copy_from_str("exact")
                            .map_err(|_| Failure::Unavailable)?,
                    ),
                    concealed: false,
                }],
                source_fields: vec![SourceField {
                    path: "legacy.unknown".to_owned(),
                    encoding: SourceEncoding::Bytes,
                    value: pm_crypto::ProtectedBytes::copy_from_slice(
                        b"ticket05-e2e-source-canary",
                    )
                    .map_err(|_| Failure::Unavailable)?,
                }],
            })
        };
        let attachment = || {
            Attachment::new(
                [0x71; 16],
                "archivo-雪.txt",
                "text/plain",
                "ticket05-e2e-attachment-canary 🌎".as_bytes(),
            )
            .map_err(|_| Failure::Unavailable)
        };
        let make = |kind, human, auth, attachments| {
            LogicalRecord::new(kind, human, auth, attachments).map_err(|_| Failure::Unavailable)
        };
        Ok(vec![
            make(
                RecordKind::Password,
                metadata("Password", "password")?,
                vec![AuthRecord::Password {
                    username: "e2e".to_owned(),
                    password: pm_crypto::ProtectedBytes::copy_from_slice(
                        b"ticket05-e2e-password-canary",
                    )
                    .map_err(|_| Failure::Unavailable)?,
                    destination_refs: vec![0],
                }],
                vec![attachment()?],
            )?,
            make(
                RecordKind::Totp,
                metadata("TOTP", "totp")?,
                vec![AuthRecord::Totp {
                    secret: pm_crypto::ProtectedBytes::copy_from_slice(b"ticket05-e2e-totp-canary")
                        .map_err(|_| Failure::Unavailable)?,
                    algorithm: TotpAlgorithm::Sha1,
                    digits: 6,
                    period: 30,
                    t0: 0,
                    issuer: "Synthetic".to_owned(),
                    account: "e2e".to_owned(),
                    destination_refs: vec![0],
                }],
                vec![],
            )?,
            make(
                RecordKind::Passkey,
                metadata("Passkey", "stored only")?,
                vec![AuthRecord::Passkey {
                    rp_id: "e2e.invalid".to_owned(),
                    user_handle: b"e2e-user".to_vec(),
                    credential_id: b"e2e-credential".to_vec(),
                    cose_alg: -8,
                    private_key: pm_crypto::ProtectedBytes::copy_from_slice(&([0x73; 32]))
                        .map_err(|_| Failure::Unavailable)?,
                    public_key: [0x74; 32],
                    user_name: "e2e".to_owned(),
                    display_name: "E2E".to_owned(),
                    sign_count: 0,
                    backup_eligible: true,
                    backup_state: true,
                }],
                vec![],
            )?,
            make(
                RecordKind::Ssh,
                metadata("SSH", "ssh")?,
                vec![AuthRecord::Ssh {
                    private_format: PrivateKeyFormat::OpenSsh,
                    private_key: pm_crypto::ProtectedBytes::copy_from_slice(
                        b"ticket05-e2e-ssh-canary",
                    )
                    .map_err(|_| Failure::Unavailable)?,
                    public_key: b"ssh-ed25519 e2e".to_vec(),
                    username: "e2e".to_owned(),
                    destination_refs: vec![0],
                    passphrase: None,
                }],
                vec![],
            )?,
            make(
                RecordKind::Token,
                metadata("Token", "token")?,
                vec![AuthRecord::Token {
                    secret: pm_crypto::ProtectedBytes::copy_from_slice(
                        b"ticket05-e2e-token-canary",
                    )
                    .map_err(|_| Failure::Unavailable)?,
                    provider: "synthetic".to_owned(),
                    profile_id: "e2e".to_owned(),
                    destination_refs: vec![0],
                    expires_at: None,
                }],
                vec![],
            )?,
            make(
                RecordKind::Note,
                metadata(
                    "ticket05-e2e-search-canary 雪\u{1b}]52;c;dGlja2V0MjM=\u{7}",
                    "ticket27-native-note-canary",
                )?,
                vec![],
                vec![],
            )?,
            make(
                RecordKind::File,
                metadata("File", "file")?,
                vec![],
                vec![attachment()?],
            )?,
            make(
                RecordKind::Token,
                HumanMetadata {
                    title: "Exchange Relationship".to_owned(),
                    destinations: vec![Destination {
                        label: "adapter".to_owned(),
                        value: "keycloak-exchange-lab".to_owned(),
                    }],
                    tags: vec!["synthetic".to_owned()],
                    favorite: false,
                    notes: pm_crypto::ProtectedText::copy_from_str("exchange")
                        .map_err(|_| Failure::Unavailable)?,
                    fields: vec![],
                    source_fields: vec![],
                },
                vec![AuthRecord::TokenExchange {
                    subject_token: pm_crypto::ProtectedBytes::copy_from_slice(
                        b"ticket11-e2e-subject-token-canary",
                    )
                    .map_err(|_| Failure::Unavailable)?,
                    requester_client_id: "pm-exchanger".to_owned(),
                    requester_client_secret: pm_crypto::ProtectedBytes::copy_from_slice(
                        b"ticket11-e2e-requester-secret-canary",
                    )
                    .map_err(|_| Failure::Unavailable)?,
                    provider: "keycloak".to_owned(),
                    profile_id: "exchange".to_owned(),
                    destination_refs: vec![0],
                    expires_at: Some(2_000_000_000),
                }],
                vec![],
            )?,
        ])
    }
}
