// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic enabled-edit client of the existing authenticated human wire.
//! No server policy, grant injection or identity substitution.
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
    #[allow(clippy::too_many_lines)]
    pub fn run() {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        assert_eq!(args.len(), 5);
        let profile = std::fs::read(&args[0]).unwrap();
        assert_eq!(&profile[..5], b"PMP1\x02");
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
        config.alpn_protocols = vec![b"pm-human/1".to_vec()];
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
        assert_eq!(args[3].len(), 32);
        let item: Vec<u8> = args[3]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(item.len(), 16);
        let mut input = zeroize::Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut input).unwrap();
        assert!(input.len() < 4096);
        tls.write_all(b"PMH1\n").unwrap();
        tls.flush().unwrap();
        let mut unlock = zeroize::Zeroizing::new(vec![1]);
        field(&mut unlock, &input);
        send(&mut tls, &unlock);
        assert_eq!(frame(&mut tls).unwrap(), [0]);
        let request = if args[4] == "organize" {
            let mut r = vec![11];
            r.extend_from_slice(&item);
            r.extend_from_slice(&[1, 0, 1]);
            field(&mut r, b"synthetic-r2");
            zeroize::Zeroizing::new(r)
        } else {
            let mut read = vec![10];
            read.extend_from_slice(&item);
            send(&mut tls, &read);
            let response = zeroize::Zeroizing::new(frame(&mut tls).unwrap());
            assert_eq!(response[0], 0);
            let bytes = &response[1..];
            let record = pm_vault::LogicalRecord::from_bytes(bytes).unwrap();
            let [
                pm_vault::AuthRecord::TokenExchange {
                    subject_token,
                    requester_client_id,
                    requester_client_secret,
                    provider,
                    profile_id,
                    destination_refs,
                    expires_at,
                },
            ] = record.auth()
            else {
                panic!("synthetic exchange record required")
            };
            assert!(matches!(args[4].as_str(), "title" | "rotate"));
            let rotation = args[4] == "rotate";
            let updated = pm_vault::LogicalRecord::new(
                pm_vault::RecordKind::Token,
                pm_vault::HumanMetadata {
                    title: if rotation {
                        record.human().title.clone()
                    } else {
                        "Synthetic R2 edited title".into()
                    },
                    destinations: vec![pm_vault::Destination {
                        label: "installed profile".into(),
                        value: profile_id.clone(),
                    }],
                    tags: vec![],
                    favorite: false,
                    notes: pm_crypto::ProtectedText::copy_from_str("").unwrap(),
                    fields: vec![],
                    source_fields: vec![],
                },
                vec![pm_vault::AuthRecord::TokenExchange {
                    subject_token: pm_crypto::ProtectedBytes::copy_from_slice(if rotation {
                        b"synthetic-r2-new-subject"
                    } else {
                        subject_token
                    })
                    .unwrap(),
                    requester_client_id: requester_client_id.clone(),
                    requester_client_secret: pm_crypto::ProtectedBytes::copy_from_slice(
                        if rotation {
                            b"synthetic-r2-new-requester"
                        } else {
                            requester_client_secret
                        },
                    )
                    .unwrap(),
                    provider: provider.clone(),
                    profile_id: profile_id.clone(),
                    destination_refs: destination_refs.clone(),
                    expires_at: *expires_at,
                }],
                vec![],
            )
            .unwrap();
            let mut r = zeroize::Zeroizing::new(vec![29]);
            r.extend_from_slice(&item);
            field(&mut r, &updated.to_bytes().unwrap());
            r
        };
        send(&mut tls, &request);
        let prepared = zeroize::Zeroizing::new(frame(&mut tls).unwrap());
        assert_eq!(prepared[0], 0);
        let transaction = &prepared[1..17];
        let mut cursor = &prepared[33..];
        let command = take(&mut cursor);
        let body = take(&mut cursor);
        assert_eq!(cursor.len(), 64);
        let mut commit = zeroize::Zeroizing::new(vec![5]);
        field(&mut commit, command);
        commit.extend_from_slice(cursor);
        field(&mut commit, body);
        send(&mut tls, &commit);
        let receipt = frame(&mut tls).unwrap();
        assert_eq!(receipt[0], 0);
        let mut query = vec![7];
        query.extend_from_slice(transaction);
        send(&mut tls, &query);
        assert_eq!(frame(&mut tls).unwrap(), receipt);
        send(&mut tls, &[14]);
        assert_eq!(frame(&mut tls).unwrap(), [0]);
        println!(
            "PASS human-enabled-edit action={} transaction_id={} receipt_sha256={} receipt=replayed",
            args[4],
            hex(transaction),
            hex(&pm_crypto::digest(&receipt))
        );
    }
    fn hex(value: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        value
            .iter()
            .flat_map(|byte| {
                [
                    char::from(DIGITS[usize::from(byte >> 4)]),
                    char::from(DIGITS[usize::from(byte & 15)]),
                ]
            })
            .collect()
    }
    fn field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        out.extend_from_slice(value);
    }
    fn take<'a>(cursor: &mut &'a [u8]) -> &'a [u8] {
        let size = u32::from_be_bytes(cursor[..4].try_into().unwrap()) as usize;
        let value = &cursor[4..4 + size];
        *cursor = &cursor[4 + size..];
        value
    }
    fn send(tls: &mut (impl Read + Write), value: &[u8]) {
        tls.write_all(&u32::try_from(value.len()).unwrap().to_be_bytes())
            .unwrap();
        tls.write_all(value).unwrap();
        tls.flush().unwrap();
    }
}
fn main() {
    #[cfg(unix)]
    client::run();
    #[cfg(not(unix))]
    panic!("synthetic Unix human client only");
}
