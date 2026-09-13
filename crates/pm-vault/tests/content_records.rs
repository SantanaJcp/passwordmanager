// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
};

use pm_crypto::KdfProfile;
use pm_vault::{
    Attachment, AttachmentReader, AuthRecord, CustomField, Destination, GeneratorConfig,
    HumanChannel, HumanCommitError, HumanMetadata, HumanVault, LogicalRecord, LogicalValue,
    PasswordRng, PendingVault, PrivateKeyFormat, RecordKind, SearchQuery, SourceEncoding,
    SourceField, TotpAlgorithm,
};
use rusqlite::Connection;

const PASSWORD: &[u8] = b"synthetic ticket 05 master";
const DEVICE: [u8; 16] = [0x55; 16];

struct FailingRng;

impl PasswordRng for FailingRng {
    fn fill(&mut self, _output: &mut [u8]) -> Result<(), HumanCommitError> {
        Err(HumanCommitError::RandomUnavailable)
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn attachment_above_16_mib_streams_atomically_in_bounded_chunks() {
    const SIZE: u64 = 16 * 1024 * 1024 + 4096;
    let directory = tempfile_dir("streaming");
    let path = directory.join("vault.sqlite3");
    persist_test_vault(&path);
    let (mut vault, _peer) = open_human(&path);
    let expected_hash = pattern_hash(SIZE);
    let attachment = Attachment::descriptor(
        [0x79; 16],
        "large-雪.bin",
        "application/octet-stream",
        SIZE,
        expected_hash,
    )
    .unwrap();
    let record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Large".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![attachment],
    )
    .unwrap();
    let mut input = PatternReader {
        remaining: SIZE,
        position: 0,
    };
    let mut sources = [AttachmentReader::new([0x79; 16], &mut input)];
    let prepared = vault
        .prepare_create_record_streaming(&record, &mut sources)
        .unwrap();
    vault
        .commit(
            prepared.command(),
            &vault.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    let metadata = vault.read_record(*prepared.item_id()).unwrap();
    assert_eq!(metadata.attachments()[0].size(), SIZE);
    assert!(metadata.attachments()[0].content().is_empty());
    let mut output = HashingWriter::new();
    vault
        .read_attachment_to(*prepared.item_id(), [0x79; 16], &mut output)
        .unwrap();
    assert_eq!(output.size, SIZE);
    assert_eq!(output.finish(), expected_hash);
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM attachment_stream_chunks", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        17
    );
    assert!(
        connection
            .query_row(
                "SELECT max(length(ciphertext)) FROM attachment_stream_chunks",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap()
            <= 1024 * 1024 + 21
    );

    let failed = Attachment::descriptor(
        [0x7a; 16],
        "short.bin",
        "application/octet-stream",
        SIZE,
        expected_hash,
    )
    .unwrap();
    let failed = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Short".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![failed],
    )
    .unwrap();
    let mut short = PatternReader {
        remaining: 1024,
        position: 0,
    };
    let mut sources = [AttachmentReader::new([0x7a; 16], &mut short)];
    assert!(matches!(
        vault.prepare_create_record_streaming(&failed, &mut sources),
        Err(HumanCommitError::Io(_))
    ));
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM human_staging_streams", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );

    let exact_hash = pattern_hash(1024);
    let excess = Attachment::descriptor(
        [0x7e; 16],
        "excess.bin",
        "application/octet-stream",
        1024,
        exact_hash,
    )
    .unwrap();
    let excess = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Excess".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![excess],
    )
    .unwrap();
    let mut overlong = PatternReader {
        remaining: 1025,
        position: 0,
    };
    let mut sources = [AttachmentReader::new([0x7e; 16], &mut overlong)];
    assert!(matches!(
        vault.prepare_create_record_streaming(&excess, &mut sources),
        Err(HumanCommitError::InvalidInput)
    ));
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM human_staging_streams", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    drop(connection);
    fs::remove_dir_all(directory).unwrap();
}

struct PatternReader {
    remaining: u64,
    position: u64,
}
impl Read for PatternReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = buffer.len().min(usize::try_from(self.remaining).unwrap());
        for byte in &mut buffer[..count] {
            *byte = b'a' + u8::try_from(self.position % 23).unwrap();
            self.position += 1;
        }
        self.remaining -= u64::try_from(count).unwrap();
        Ok(count)
    }
}
struct HashingWriter {
    digest: pm_crypto::DigestState,
    size: u64,
}
impl HashingWriter {
    fn new() -> Self {
        Self {
            digest: pm_crypto::DigestState::new().unwrap(),
            size: 0,
        }
    }
    fn finish(self) -> [u8; 32] {
        self.digest.finish()
    }
}
impl Write for HashingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.digest.update(bytes);
        self.size += u64::try_from(bytes.len()).unwrap();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn pattern_hash(size: u64) -> [u8; 32] {
    let mut reader = PatternReader {
        remaining: size,
        position: 0,
    };
    let mut digest = pm_crypto::DigestState::new().unwrap();
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    digest.finish()
}

#[test]
fn all_logical_types_unknown_fields_and_unicode_attachments_roundtrip_exactly() {
    let directory = tempfile_dir("roundtrip");
    let path = directory.join("vault.sqlite3");
    persist_test_vault(&path);
    let (mut vault, _peer) = open_human(&path);

    let records = all_records();
    for expected in records {
        let prepared = vault.prepare_create_record(&expected).unwrap();
        vault
            .commit(
                prepared.command(),
                &vault.sign(&prepared).unwrap(),
                prepared.body(),
            )
            .unwrap();
        let actual = vault.read_record(*prepared.item_id()).unwrap();
        assert_eq!(actual, expected);
    }

    drop(vault);
    for entry in fs::read_dir(&directory).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        for canary in secret_canaries() {
            assert!(
                !contains(&bytes, canary),
                "plaintext leaked into vault files"
            );
        }
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn configured_generator_uses_native_rng_and_fails_closed_when_rng_fails() {
    let directory = tempfile_dir("generator");
    let path = directory.join("vault.sqlite3");
    persist_test_vault(&path);
    let (vault, _peer) = open_human(&path);
    let config = GeneratorConfig {
        length: 96,
        lowercase: false,
        uppercase: true,
        digits: true,
        symbols: false,
    };
    let generated = vault.generate_password(&config).unwrap();
    assert_eq!(generated.expose().len(), 96);
    assert!(
        generated
            .expose()
            .iter()
            .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit())
    );

    assert!(matches!(
        vault.generate_password_with_rng(&config, &mut FailingRng),
        Err(HumanCommitError::RandomUnavailable)
    ));
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM vault_items", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn staging_and_rejected_limits_never_truncate_or_persist_canaries() {
    let directory = tempfile_dir("limits");
    let path = directory.join("vault.sqlite3");
    persist_test_vault(&path);
    let (mut vault, _peer) = open_human(&path);
    let record = LogicalRecord::new(
        RecordKind::File,
        HumanMetadata {
            title: "Staged".to_owned(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: "ticket05-staging-note-canary".to_owned(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![
            Attachment::new(
                [0x77; 16],
                "附件.bin",
                "application/octet-stream",
                b"ticket05-staging-file-canary",
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let _prepared = vault.prepare_create_record(&record).unwrap();
    for entry in fs::read_dir(&directory).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!contains(&bytes, b"ticket05-staging-note-canary"));
        assert!(!contains(&bytes, b"ticket05-staging-file-canary"));
    }

    let oversized_title = "x".repeat(1025);
    assert!(matches!(
        LogicalRecord::new(
            RecordKind::Note,
            HumanMetadata {
                title: oversized_title,
                destinations: vec![],
                tags: vec![],
                favorite: false,
                notes: String::new(),
                fields: vec![],
                source_fields: vec![]
            },
            vec![],
            vec![]
        ),
        Err(HumanCommitError::InvalidInput)
    ));
    assert!(matches!(
        Attachment::from_parts(
            [0x78; 16],
            "too-large",
            "application/octet-stream",
            16 * 1024 * 1024 * 1024 + 1,
            pm_crypto::digest(&[]),
            &[]
        ),
        Err(HumanCommitError::InvalidInput)
    ));
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT count(*) FROM vault_items", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn human_search_tag_and_favorite_use_complete_encrypted_records() {
    let directory = tempfile_dir("organization");
    let path = directory.join("vault.sqlite3");
    persist_test_vault(&path);
    let (mut vault, _peer) = open_human(&path);
    let record = LogicalRecord::new(
        RecordKind::Note,
        HumanMetadata {
            title: "ticket05-search-canary Proyecto 雪".to_owned(),
            destinations: vec![],
            tags: vec!["inicial".to_owned()],
            favorite: false,
            notes: "hallazgo humano".to_owned(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![],
    )
    .unwrap();
    let prepared = vault.prepare_create_record(&record).unwrap();
    vault
        .commit(
            prepared.command(),
            &vault.sign(&prepared).unwrap(),
            prepared.body(),
        )
        .unwrap();
    let item = *prepared.item_id();

    let organized = vault
        .prepare_organize(item, vec!["equipo-azul".to_owned()], true)
        .unwrap();
    vault
        .commit(
            organized.command(),
            &vault.sign(&organized).unwrap(),
            organized.body(),
        )
        .unwrap();
    let hits = vault
        .search(&SearchQuery {
            text: Some("proyecto 雪".to_owned()),
            tag: Some("equipo-azul".to_owned()),
            favorite: Some(true),
        })
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].item_id(), &item);
    assert_eq!(hits[0].kind(), RecordKind::Note);

    drop(vault);
    for entry in fs::read_dir(&directory).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!contains(&bytes, b"ticket05-search-canary"));
        assert!(!contains(&bytes, b"equipo-azul"));
    }
    fs::remove_dir_all(directory).unwrap();
}

#[allow(clippy::too_many_lines)]
fn all_records() -> Vec<LogicalRecord> {
    let metadata = |title: &str| HumanMetadata {
        title: title.to_owned(),
        destinations: vec![Destination {
            label: "Inicio 🌎".to_owned(),
            value: "https://synthetic.invalid/路径".to_owned(),
        }],
        tags: vec!["equipo-☃".to_owned()],
        favorite: true,
        notes: "nota sintética".to_owned(),
        fields: vec![CustomField {
            id: [0x31; 16],
            label: "campo".to_owned(),
            value: LogicalValue::Text("valor exacto".to_owned()),
            concealed: false,
        }],
        source_fields: vec![SourceField {
            path: "legacy.extra".to_owned(),
            encoding: SourceEncoding::Bytes,
            value: b"ticket05-source-canary".to_vec(),
        }],
    };
    let attachment = || {
        Attachment::new(
            [0x41; 16],
            "evidencia-雪.txt",
            "text/plain; charset=utf-8",
            b"ticket05-attachment-canary \xf0\x9f\x8c\x8d",
        )
        .unwrap()
    };

    vec![
        LogicalRecord::new(
            RecordKind::Password,
            metadata("Contraseña"),
            vec![AuthRecord::Password {
                username: "usuario".to_owned(),
                password: b"ticket05-password-canary".to_vec(),
                destination_refs: vec![0],
            }],
            vec![attachment()],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Totp,
            metadata("TOTP"),
            vec![AuthRecord::Totp {
                secret: b"ticket05-totp-seed-01".to_vec(),
                algorithm: TotpAlgorithm::Sha256,
                digits: 8,
                period: 45,
                t0: 0,
                issuer: "Synthetic Issuer".to_owned(),
                account: "synthetic@example.invalid".to_owned(),
                destination_refs: vec![0],
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Passkey,
            metadata("Passkey conservada"),
            vec![AuthRecord::Passkey {
                rp_id: "synthetic.invalid".to_owned(),
                user_handle: b"ticket05-user-handle".to_vec(),
                credential_id: b"ticket05-credential-id".to_vec(),
                cose_alg: -8,
                private_key: [0x53; 32],
                public_key: [0x54; 32],
                user_name: "synthetic-user".to_owned(),
                display_name: "Synthetic User".to_owned(),
                sign_count: 0,
                backup_eligible: true,
                backup_state: true,
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Ssh,
            metadata("SSH"),
            vec![AuthRecord::Ssh {
                private_format: PrivateKeyFormat::OpenSsh,
                private_key: b"ticket05-ssh-private-canary".to_vec(),
                public_key: b"ssh-ed25519 synthetic-public".to_vec(),
                username: "synthetic".to_owned(),
                destination_refs: vec![0],
                passphrase: Some(b"ticket05-ssh-passphrase-canary".to_vec()),
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Token,
            metadata("Token"),
            vec![AuthRecord::Token {
                secret: b"ticket05-token-canary".to_vec(),
                provider: "synthetic-provider".to_owned(),
                profile_id: "synthetic-profile".to_owned(),
                destination_refs: vec![0],
                expires_at: Some(2_000_000),
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(RecordKind::Note, metadata("Nota"), vec![], vec![]).unwrap(),
        LogicalRecord::new(
            RecordKind::File,
            metadata("Archivo"),
            vec![],
            vec![attachment()],
        )
        .unwrap(),
    ]
}

fn secret_canaries() -> [&'static [u8]; 7] {
    [
        b"ticket05-source-canary",
        b"ticket05-attachment-canary",
        b"ticket05-password-canary",
        b"ticket05-totp-seed-01",
        &[0x53; 32],
        b"ticket05-ssh-private-canary",
        b"ticket05-token-canary",
    ]
}

fn persist_test_vault(path: &Path) {
    let pending = PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let confirmation = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &confirmation).unwrap();
}

fn open_human(path: &Path) -> (HumanVault, UnixStream) {
    let (server, client) = UnixStream::pair().unwrap();
    let uid = unsafe { libc::geteuid() };
    let channel = HumanChannel::authenticate(server, uid).unwrap();
    (
        HumanVault::unlock(path, PASSWORD, DEVICE, channel).unwrap(),
        client,
    )
}

fn tempfile_dir(suffix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("pm-ticket-05-{}-{suffix}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    path
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
