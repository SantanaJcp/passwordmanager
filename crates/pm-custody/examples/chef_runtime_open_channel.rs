// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic Linux acceptance client: hold one real native+TLS channel across
//! human revocation, then issue a get. No authority shim or provider motor.
#[cfg(unix)]
mod client {
    use rustls::{
        DigitallySignedStruct, Error, SignatureScheme,
        client::{
            AlwaysResolvesClientRawPublicKeys, ClientConfig, ClientConnection, Resumption,
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        },
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
        sign::CertifiedKey,
    };
    use std::{
        io::{Read, Write},
        os::unix::{fs::MetadataExt, net::UnixStream},
        sync::Arc,
        time::Duration,
    };
    #[derive(Debug)]
    struct Pin {
        key: Vec<u8>,
        algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    }
    impl ServerCertVerifier for Pin {
        fn verify_server_cert(
            &self,
            cert: &CertificateDer<'_>,
            chain: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            if cert.as_ref() != self.key || !chain.is_empty() {
                return Err(Error::General("pin".into()));
            }
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("version".into()))
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            rustls::crypto::verify_tls13_signature_with_raw_key(
                message,
                &rustls::pki_types::SubjectPublicKeyInfoDer::from(cert.as_ref()),
                signature,
                &self.algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }
    fn frame(tls: &mut impl Read) -> std::io::Result<Vec<u8>> {
        let mut size = [0; 4];
        tls.read_exact(&mut size)?;
        let len = u32::from_be_bytes(size) as usize;
        assert!(len <= 1024 * 1024);
        let mut bytes = vec![0; len];
        tls.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    pub fn run() {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        assert!(matches!(args.len(), 3 | 4));
        assert!(
            args.get(3)
                .is_none_or(|mode| matches!(mode.as_str(), "tls-only" | "tls-quota-denied"))
        );
        let profile = std::fs::read(&args[0]).unwrap();
        assert_eq!(&profile[..5], b"PMP1\x01");
        let uid = u32::from_be_bytes(profile[5..9].try_into().unwrap());
        let pin = profile[9..].to_vec();
        let metadata = std::fs::metadata(&args[1]).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o400);
        let private = zeroize::Zeroizing::new(std::fs::read(&args[1]).unwrap());
        assert_eq!(&private[..4], b"PMK1");
        let len = u32::from_be_bytes(private[4..8].try_into().unwrap()) as usize;
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        let signing = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                private[8..8 + len].to_vec(),
            )))
            .unwrap();
        let key = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(private[8 + len..].to_vec())],
            signing,
        ));
        let verifier = Arc::new(Pin {
            key: pin,
            algorithms: provider.signature_verification_algorithms,
        });
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(key)));
        config.alpn_protocols = vec![b"pm-agent/1".to_vec()];
        config.resumption = Resumption::disabled();
        let stream = UnixStream::connect(&args[2]).unwrap();
        assert_eq!(pm_custody::unix_peer_uid(&stream).unwrap(), uid);
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        let connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("custodian.invalid").unwrap(),
        )
        .unwrap();
        let mut tls = rustls::StreamOwned::new(connection, stream);
        if args.get(3).is_some() {
            while tls.conn.is_handshaking() {
                tls.conn.complete_io(&mut tls.sock).unwrap();
            }
            if args[3] == "tls-quota-denied" {
                tls.sock
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut byte = [0];
                match tls.read(&mut byte) {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                        ) => {}
                    result => {
                        panic!("quota did not close TLS before application magic: {result:?}")
                    }
                }
                println!("PASS tls-quota-denied no-application-magic=1");
                return;
            }
            println!("READY");
            std::io::stdout().flush().unwrap();
            let mut signal = [0];
            std::io::stdin().read_exact(&mut signal).unwrap();
            return;
        }
        tls.write_all(b"PMA1\n").unwrap();
        tls.flush().unwrap();
        assert_eq!(frame(&mut tls).unwrap()[0], 0);
        // An unknown attempt yields NOT_FOUND before revocation. The same get
        // after revocation must instead yield AGENT_REVOKED on this channel.
        let mut request = [0; 21];
        request[..4].copy_from_slice(&17_u32.to_be_bytes());
        request[4] = 31;
        tls.write_all(&request).unwrap();
        tls.flush().unwrap();
        assert_eq!(frame(&mut tls).unwrap(), [2]);
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut signal = [0];
        std::io::stdin().read_exact(&mut signal).unwrap();
        tls.write_all(&request).unwrap();
        tls.flush().unwrap();
        assert_eq!(frame(&mut tls).unwrap(), [5]);
        println!("PASS hot-revoke same-native-tls-channel=1");
    }
}
fn main() {
    #[cfg(unix)]
    client::run();
    #[cfg(not(unix))]
    panic!("Linux acceptance client only");
}
