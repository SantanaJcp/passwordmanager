// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Cursor, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use pm_crypto::KdfProfile;
use pm_vault::{
    Attachment, AttachmentReader, AuthRecord, BackupArchive, Destination, HumanChannel,
    HumanMetadata, HumanVault, LogicalRecord, PendingVault, PrivateKeyFormat, RecordKind,
    SourceEncoding, SourceField, TotpAlgorithm,
};

const MASTER: &[u8] = b"synthetic ticket21 master password";
const DEVICE: [u8; 16] = [0x21; 16];
const LARGE: u64 = 2 * 1024 * 1024 + 73;

#[test]
#[allow(clippy::too_many_lines)]
fn pmb1_roundtrip_has_exact_inventory_history_streams_and_both_root_paths() {
    let dir = TestDir::new("roundtrip");
    let (path, recovery) = persist(&dir);
    let (mut vault, _peer) = open_human(&path);

    let first = password_record("primera", b"ticket21-old-secret-canary");
    let created = vault.prepare_create_record(&first).unwrap();
    let item = *created.item_id();
    commit(&mut vault, &created);
    let edited = vault
        .prepare_edit_record(
            item,
            &password_record("visible", b"ticket21-new-secret-canary"),
        )
        .unwrap();
    commit(&mut vault, &edited);
    let deleted = vault.prepare_delete(item).unwrap();
    commit(&mut vault, &deleted);

    let descriptor = Attachment::descriptor(
        [0x72; 16],
        "respaldo-雪.bin",
        "application/octet-stream",
        LARGE,
        pattern_hash(LARGE),
    )
    .unwrap();
    let file = LogicalRecord::new_streaming(
        RecordKind::File,
        metadata("archivo grande"),
        vec![],
        vec![descriptor],
    )
    .unwrap();
    let mut input = PatternReader::new(LARGE);
    let mut sources = [AttachmentReader::new([0x72; 16], &mut input)];
    let streamed = vault
        .prepare_create_record_streaming(&file, &mut sources)
        .unwrap();
    commit(&mut vault, &streamed);

    let purged = vault
        .prepare_create_record(
            &LogicalRecord::new(
                RecordKind::Note,
                metadata("partial history marker"),
                vec![],
                vec![],
            )
            .unwrap(),
        )
        .unwrap();
    let purged_item = *purged.item_id();
    commit(&mut vault, &purged);
    let deleted = vault.prepare_delete(purged_item).unwrap();
    commit(&mut vault, &deleted);
    let purge = vault.prepare_purge_item(purged_item).unwrap();
    commit(&mut vault, purge.prepared());

    let mut output = BoundedWriter::default();
    let written = vault.write_native_backup(&mut output).unwrap();
    assert_eq!(written.items(), 2);
    assert_eq!(written.revisions(), 3);
    assert_eq!(written.attachments(), 1);
    assert_eq!(written.attachment_bytes(), LARGE);
    assert!(written.audit_bundles() > 0);
    assert!(written.authority_events() >= 4);
    assert!(output.max_write <= 1024 * 1024 + 64);
    assert!(output.bytes.starts_with(b"PMB1"));
    assert!(!contains(&output.bytes, b"ticket21-old-secret-canary"));
    assert!(!contains(&output.bytes, b"ticket21-new-secret-canary"));

    let mut bounded = BoundedReader::new(&output.bytes, 1024 * 1024 + 64);
    let opened = vault.verify_native_backup(&mut bounded).unwrap();
    assert_eq!(opened, written);
    assert!(bounded.max_requested <= 1024 * 1024 + 64);

    let recovery = recovery.parse().unwrap();
    let by_recovery =
        BackupArchive::verify_with_recovery(&mut Cursor::new(&output.bytes), &recovery).unwrap();
    assert_eq!(by_recovery, written);
    assert!(
        BackupArchive::verify_with_password(
            &mut Cursor::new(&output.bytes),
            b"synthetic wrong backup password",
        )
        .is_err()
    );

    let plaintext = vault.prepare_plaintext_export().unwrap();
    let plaintext_signature = vault.sign(&plaintext).unwrap();
    let mut plaintext_output = Vec::new();
    vault
        .write_plaintext_export(
            plaintext.command(),
            &plaintext_signature,
            plaintext.body(),
            &mut plaintext_output,
        )
        .unwrap();
    assert!(contains(&plaintext_output, br#""type":"partial_history""#));

    let mut altered = output.bytes.clone();
    let middle = altered.len() / 2;
    altered[middle] ^= 1;
    assert!(
        vault
            .verify_native_backup(&mut Cursor::new(altered))
            .is_err()
    );
    assert!(
        vault
            .verify_native_backup(&mut Cursor::new(&output.bytes[..output.bytes.len() - 1]))
            .is_err()
    );
    let mut trailing = output.bytes.clone();
    trailing.push(0);
    assert!(
        vault
            .verify_native_backup(&mut Cursor::new(trailing))
            .is_err()
    );
    let reordered = reorder_first_two_cipher_frames(&output.bytes);
    assert!(
        vault
            .verify_native_backup(&mut Cursor::new(reordered))
            .is_err()
    );
    let omitted = omit_second_cipher_frame(&output.bytes);
    assert!(
        vault
            .verify_native_backup(&mut Cursor::new(omitted))
            .is_err()
    );
}

#[test]
fn plaintext_export_needs_a_fresh_signed_human_confirmation() {
    let dir = TestDir::new("plaintext");
    let (path, _) = persist(&dir);
    let (mut vault, _peer) = open_human(&path);
    let created = vault
        .prepare_create_record(&password_record(
            "plain export",
            b"ticket21-plaintext-export-canary",
        ))
        .unwrap();
    commit(&mut vault, &created);

    let prepared = vault.prepare_plaintext_export().unwrap();
    let signature = vault.sign(&prepared).unwrap();
    let mut output = BoundedWriter::default();
    let summary = vault
        .write_plaintext_export(prepared.command(), &signature, prepared.body(), &mut output)
        .unwrap();
    assert_eq!(summary.items(), 1);
    assert!(output.bytes.starts_with(b"PM-LOGICAL-JSONL/1\n"));
    assert!(!contains(
        &output.bytes,
        b"ticket21-plaintext-export-canary"
    ));
    assert!(plaintext_payloads_contain(
        &output.bytes,
        b"ticket21-plaintext-export-canary"
    ));
    assert!(
        vault
            .write_plaintext_export(
                prepared.command(),
                &signature,
                prepared.body(),
                &mut Vec::new(),
            )
            .is_err()
    );

    let next = vault.prepare_plaintext_export().unwrap();
    let next_signature = vault.sign(&next).unwrap();
    let mut changed = next.body().to_vec();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        vault
            .write_plaintext_export(next.command(), &next_signature, &changed, &mut Vec::new(),)
            .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_restore_is_one_signed_commit_with_new_ids_and_no_active_authority() {
    let source_dir = TestDir::new("restore-source");
    let (source_path, _) = persist(&source_dir);
    let (mut source, _peer) = open_human(&source_path);
    let first = password_record("restored-old", b"ticket21-restore-old");
    let created = source.prepare_create_record(&first).unwrap();
    let source_item = *created.item_id();
    commit(&mut source, &created);
    let edited = source
        .prepare_edit_record(
            source_item,
            &password_record("restored-visible", b"ticket21-restore-visible"),
        )
        .unwrap();
    commit(&mut source, &edited);
    let deleted = source.prepare_delete(source_item).unwrap();
    commit(&mut source, &deleted);

    let descriptor = Attachment::descriptor(
        [0x74; 16],
        "restore-large.bin",
        "application/octet-stream",
        LARGE,
        pattern_hash(LARGE),
    )
    .unwrap();
    let file = LogicalRecord::new_streaming(
        RecordKind::File,
        metadata("restored file"),
        vec![],
        vec![descriptor],
    )
    .unwrap();
    let mut source_bytes = PatternReader::new(LARGE);
    let mut sources = [AttachmentReader::new([0x74; 16], &mut source_bytes)];
    let file_created = source
        .prepare_create_record_streaming(&file, &mut sources)
        .unwrap();
    commit(&mut source, &file_created);
    let mut archive = Vec::new();
    source.write_native_backup(&mut archive).unwrap();

    let destination_dir = TestDir::new("restore-destination");
    let (destination_path, _) = persist(&destination_dir);
    let (mut destination, peer) = open_human(&destination_path);
    let prepared = destination
        .prepare_native_restore(&mut Cursor::new(&archive), MASTER)
        .unwrap();
    assert_eq!(prepared.summary().items(), 2);
    assert_eq!(prepared.summary().revisions(), 3);
    assert_eq!(prepared.item_ids().len(), 2);
    assert!(prepared.item_ids().iter().all(|id| id != &source_item));
    let signed = destination.sign(prepared.prepared()).unwrap();
    drop(destination);
    drop(peer);

    let database = rusqlite::Connection::open(&destination_path).unwrap();
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM vault_items", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM backup_restore_items", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    drop(database);

    let (mut destination, _peer) = open_human(&destination_path);
    let database = rusqlite::Connection::open(&destination_path).unwrap();
    database
        .execute_batch(
            "CREATE TRIGGER ticket21_fail_restore_audit
             BEFORE INSERT ON encrypted_audit_records
             BEGIN SELECT raise(abort,'ticket21 audit failure'); END;",
        )
        .unwrap();
    drop(database);
    assert!(
        destination
            .commit(
                prepared.prepared().command(),
                &signed,
                prepared.prepared().body(),
            )
            .is_err()
    );
    let database = rusqlite::Connection::open(&destination_path).unwrap();
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM vault_items", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM backup_restore_items", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        2
    );
    database
        .execute_batch("DROP TRIGGER ticket21_fail_restore_audit;")
        .unwrap();
    drop(database);
    destination
        .commit(
            prepared.prepared().command(),
            &signed,
            prepared.prepared().body(),
        )
        .unwrap();
    let database = rusqlite::Connection::open(&destination_path).unwrap();
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM vault_items", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM revision_parts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM credential_authorizations", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM agent_authorizations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM authentication_attempts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(
        database
            .query_row("SELECT count(*) FROM imported_backup_history", [], |r| r
                .get::<_, i64>(0))
            .unwrap()
            > 0
    );
    let active: Vec<u8> = database
        .query_row(
            "SELECT item_id FROM vault_items WHERE status='active'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let active: [u8; 16] = active.try_into().unwrap();
    drop(database);
    let record = destination.read_record(active).unwrap();
    assert_eq!(record.kind(), RecordKind::File);
    assert_eq!(record.attachments()[0].size(), LARGE);
    assert_ne!(record.attachments()[0].id(), &[0x74; 16]);
    let mut restored = HashingWriter::new();
    destination
        .read_attachment_to(active, *record.attachments()[0].id(), &mut restored)
        .unwrap();
    assert_eq!(restored.size, LARGE);
    assert_eq!(restored.finish(), pattern_hash(LARGE));

    let before = fs::read(&destination_path).unwrap();
    let mut corrupt = archive.clone();
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    assert!(
        destination
            .prepare_native_restore(&mut Cursor::new(corrupt), MASTER)
            .is_err()
    );
    assert_eq!(fs::read(&destination_path).unwrap(), before);
}

#[test]
fn native_restore_preserves_every_logical_record_type_and_private_field() {
    let source_dir = TestDir::new("all-types-source");
    let (source_path, _) = persist(&source_dir);
    let (mut source, _peer) = open_human(&source_path);
    let expected = all_type_records();
    for record in &expected {
        let prepared = source.prepare_create_record(record).unwrap();
        commit(&mut source, &prepared);
    }
    let mut archive = Vec::new();
    source.write_native_backup(&mut archive).unwrap();

    let destination_dir = TestDir::new("all-types-destination");
    let (destination_path, _) = persist(&destination_dir);
    let (mut destination, _peer) = open_human(&destination_path);
    let prepared = destination
        .prepare_native_restore(&mut Cursor::new(archive), MASTER)
        .unwrap();
    let ids = prepared.item_ids().to_vec();
    let signature = destination.sign(prepared.prepared()).unwrap();
    destination
        .commit(
            prepared.prepared().command(),
            &signature,
            prepared.prepared().body(),
        )
        .unwrap();
    let mut observed = ids
        .into_iter()
        .map(|item| destination.read_record(item).unwrap())
        .collect::<Vec<_>>();
    observed.sort_by(|left, right| left.human().title.cmp(&right.human().title));
    let mut expected = expected;
    expected.sort_by(|left, right| left.human().title.cmp(&right.human().title));
    for (restored, source) in observed.iter().zip(&expected) {
        assert_eq!(restored.kind(), source.kind());
        assert_eq!(restored.human(), source.human());
        assert_eq!(restored.auth(), source.auth());
        assert_eq!(restored.attachments().len(), source.attachments().len());
        for (restored, source) in restored.attachments().iter().zip(source.attachments()) {
            assert_ne!(restored.id(), source.id());
            assert_eq!(restored.name(), source.name());
            assert_eq!(restored.mime(), source.mime());
            assert_eq!(restored.size(), source.size());
            assert_eq!(restored.sha256(), source.sha256());
        }
    }
}

#[test]
fn exact_inventory_spans_multiple_pages_with_empty_attachment_chunks() {
    let dir = TestDir::new("inventory-pages");
    let (path, _) = persist(&dir);
    let (mut vault, _peer) = open_human(&path);
    let attachments = (0..520_u16)
        .map(|index| {
            let mut id = [0x52; 16];
            id[14..].copy_from_slice(&index.to_be_bytes());
            Attachment::new(
                id,
                &format!("empty-{index}.bin"),
                "application/octet-stream",
                &[],
            )
            .unwrap()
        })
        .collect();
    let record = LogicalRecord::new(
        RecordKind::File,
        metadata("multipage inventory"),
        vec![],
        attachments,
    )
    .unwrap();
    let prepared = vault.prepare_create_record(&record).unwrap();
    commit(&mut vault, &prepared);
    let mut archive = BoundedWriter::default();
    let summary = vault.write_native_backup(&mut archive).unwrap();
    assert!(summary.records() > 1024);
    assert_eq!(summary.attachments(), 520);
    assert_eq!(summary.attachment_bytes(), 0);
    assert_eq!(
        vault
            .verify_native_backup(&mut Cursor::new(&archive.bytes))
            .unwrap(),
        summary
    );
}

fn password_record(title: &str, password: &[u8]) -> LogicalRecord {
    LogicalRecord::new(
        RecordKind::Password,
        metadata(title),
        vec![AuthRecord::Password {
            username: "backup-user".to_owned(),
            password: password.to_vec(),
            destination_refs: vec![0],
        }],
        vec![],
    )
    .unwrap()
}

fn all_type_records() -> Vec<LogicalRecord> {
    let human = |title: &str| {
        let mut value = metadata(title);
        value.source_fields.push(SourceField {
            path: "synthetic.private.unknown".to_owned(),
            encoding: SourceEncoding::Bytes,
            value: format!("ticket21-source-{title}").into_bytes(),
        });
        value
    };
    vec![
        LogicalRecord::new(
            RecordKind::Password,
            human("1-password"),
            vec![AuthRecord::Password {
                username: "backup-user".to_owned(),
                password: b"ticket21-password".to_vec(),
                destination_refs: vec![0],
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Totp,
            human("2-totp"),
            vec![AuthRecord::Totp {
                secret: b"ticket21-totp".to_vec(),
                algorithm: TotpAlgorithm::Sha512,
                digits: 8,
                period: 45,
                t0: 0,
                issuer: "Synthetic issuer".to_owned(),
                account: "backup@example.invalid".to_owned(),
                destination_refs: vec![0],
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Passkey,
            human("3-passkey"),
            vec![AuthRecord::Passkey {
                rp_id: "ticket21.invalid".to_owned(),
                user_handle: b"ticket21-user".to_vec(),
                credential_id: b"ticket21-credential".to_vec(),
                cose_alg: -8,
                private_key: [0x21; 32],
                public_key: [0x22; 32],
                user_name: "backup".to_owned(),
                display_name: "Backup Fixture".to_owned(),
                sign_count: 19,
                backup_eligible: true,
                backup_state: true,
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Ssh,
            human("4-ssh"),
            vec![AuthRecord::Ssh {
                private_format: PrivateKeyFormat::OpenSsh,
                private_key: b"ticket21-synthetic-ssh-private".to_vec(),
                public_key: b"ssh-ed25519 ticket21-synthetic".to_vec(),
                username: "backup".to_owned(),
                destination_refs: vec![0],
                passphrase: Some(b"ticket21-passphrase".to_vec()),
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(
            RecordKind::Token,
            human("5-token"),
            vec![AuthRecord::Token {
                secret: b"ticket21-token".to_vec(),
                provider: "synthetic".to_owned(),
                profile_id: "ticket21-profile".to_owned(),
                destination_refs: vec![0],
                expires_at: Some(1_900_000_000_000_000),
            }],
            vec![],
        )
        .unwrap(),
        LogicalRecord::new(RecordKind::Note, human("6-note"), vec![], vec![]).unwrap(),
        LogicalRecord::new(
            RecordKind::File,
            human("7-file"),
            vec![],
            vec![
                Attachment::new(
                    [0x27; 16],
                    "ticket21-inline.bin",
                    "application/octet-stream",
                    b"ticket21-inline-attachment",
                )
                .unwrap(),
            ],
        )
        .unwrap(),
    ]
}

fn metadata(title: &str) -> HumanMetadata {
    HumanMetadata {
        title: title.to_owned(),
        destinations: vec![Destination {
            label: "primary".to_owned(),
            value: "https://ticket21.invalid/login".to_owned(),
        }],
        tags: vec!["respaldo".to_owned()],
        favorite: true,
        notes: "ticket21-private-note-canary".to_owned(),
        fields: vec![],
        source_fields: vec![],
    }
}

fn commit(vault: &mut HumanVault, prepared: &pm_vault::PreparedHumanCommand) {
    let signature = vault.sign(prepared).unwrap();
    vault
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
}

fn persist(dir: &TestDir) -> (PathBuf, String) {
    let path = dir.0.join("vault.sqlite3");
    let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = pending.recovery_code().to_string();
    pending.persist(&path, &recovery.parse().unwrap()).unwrap();
    (path, recovery)
}

fn open_human(path: &Path) -> (HumanVault, UnixStream) {
    let (server, client) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock(path, MASTER, DEVICE, channel).unwrap(),
        client,
    )
}

#[derive(Default)]
struct BoundedWriter {
    bytes: Vec<u8>,
    max_write: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.max_write = self.max_write.max(bytes.len());
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct BoundedReader<'a> {
    input: Cursor<&'a [u8]>,
    limit: usize,
    max_requested: usize,
}
impl<'a> BoundedReader<'a> {
    fn new(bytes: &'a [u8], limit: usize) -> Self {
        Self {
            input: Cursor::new(bytes),
            limit,
            max_requested: 0,
        }
    }
}
impl Read for BoundedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.max_requested = self.max_requested.max(output.len());
        if output.len() > self.limit {
            return Err(std::io::Error::other("unbounded read"));
        }
        self.input.read(output)
    }
}

struct PatternReader {
    remaining: u64,
    position: u64,
}

struct HashingWriter {
    state: pm_crypto::DigestState,
    size: u64,
}

impl HashingWriter {
    fn new() -> Self {
        Self {
            state: pm_crypto::DigestState::new().unwrap(),
            size: 0,
        }
    }

    fn finish(self) -> [u8; 32] {
        self.state.finish()
    }
}

impl Write for HashingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.state.update(bytes);
        self.size += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl PatternReader {
    const fn new(size: u64) -> Self {
        Self {
            remaining: size,
            position: 0,
        }
    }
}
impl Read for PatternReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = usize::try_from(self.remaining.min(output.len() as u64)).unwrap();
        for (offset, value) in output[..count].iter_mut().enumerate() {
            *value = ((self.position + offset as u64) % 251) as u8;
        }
        self.remaining -= count as u64;
        self.position += count as u64;
        Ok(count)
    }
}

fn pattern_hash(size: u64) -> [u8; 32] {
    let mut state = pm_crypto::DigestState::new().unwrap();
    let mut reader = PatternReader::new(size);
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        state.update(&buffer[..count]);
    }
    state.finish()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn cipher_frame_ranges(archive: &[u8]) -> Vec<std::ops::Range<usize>> {
    let outer = u32::from_be_bytes(archive[4..8].try_into().unwrap()) as usize;
    let pmf_start = 8 + outer;
    let pmf =
        u32::from_be_bytes(archive[pmf_start + 4..pmf_start + 8].try_into().unwrap()) as usize;
    let mut offset = pmf_start + 8 + pmf;
    let mut ranges = vec![];
    while offset < archive.len() {
        let length = u32::from_be_bytes(archive[offset..offset + 4].try_into().unwrap()) as usize;
        ranges.push(offset..offset + 4 + length);
        offset += 4 + length;
    }
    assert_eq!(offset, archive.len());
    ranges
}

fn reorder_first_two_cipher_frames(archive: &[u8]) -> Vec<u8> {
    let ranges = cipher_frame_ranges(archive);
    assert!(ranges.len() >= 3);
    let mut output = archive[..ranges[0].start].to_vec();
    output.extend_from_slice(&archive[ranges[1].clone()]);
    output.extend_from_slice(&archive[ranges[0].clone()]);
    output.extend_from_slice(&archive[ranges[1].end..]);
    output
}

fn omit_second_cipher_frame(archive: &[u8]) -> Vec<u8> {
    let ranges = cipher_frame_ranges(archive);
    assert!(ranges.len() >= 3);
    let mut output = archive[..ranges[1].start].to_vec();
    output.extend_from_slice(&archive[ranges[1].end..]);
    output
}

fn plaintext_payloads_contain(export: &[u8], needle: &[u8]) -> bool {
    std::str::from_utf8(export).unwrap().lines().any(|line| {
        let Some(encoded) = line
            .split("\"payload\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
        else {
            return false;
        };
        decode_base64(encoded).is_some_and(|decoded| contains(&decoded, needle))
    })
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    fn digit(value: u8) -> Option<u8> {
        match value {
            b'A'..=b'Z' => Some(value - b'A'),
            b'a'..=b'z' => Some(value - b'a' + 26),
            b'0'..=b'9' => Some(value - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if !value.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for group in value.as_bytes().as_chunks::<4>().0 {
        let a = digit(group[0])?;
        let b = digit(group[1])?;
        let c = if group[2] == b'=' {
            0
        } else {
            digit(group[2])?
        };
        let d = if group[3] == b'=' {
            0
        } else {
            digit(group[3])?
        };
        output.push((a << 2) | (b >> 4));
        if group[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if group[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    Some(output)
}

struct TestDir(PathBuf);
impl TestDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "pm-ticket21-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
