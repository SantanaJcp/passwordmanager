// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use pm_crypto::KdfProfile;
use pm_vault::{
    AuditDeviceCustody, CsvImportDecision, CsvRowStatus, HumanChannel, HumanVault, PendingVault,
    RecordKind,
};
use rusqlite::Connection;
use std::{
    fs,
    io::Write,
    os::unix::{fs::symlink, net::UnixStream},
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const MASTER: &[u8] = b"synthetic ticket20 master";
const DEVICE: [u8; 16] = [0x20; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
#[allow(clippy::too_many_lines)]
fn onepux_v3_maps_login_totp_notes_and_streamed_files_through_common_import_commit() {
    let dir = TestDir::new();
    let vault_path = dir.path("vault.sqlite3");
    persist(&vault_path);
    let (mut vault, _peer) = open_human(&vault_path);
    let source = dir.path("synthetic.1pux");
    let file_bytes = synthetic_bytes(2 * 1024 * 1024 + 17);
    let data = r#"{"accounts":[{"attrs":{"uuid":"account-20","name":"Synthetic Account"},"vaults":[{"attrs":{"uuid":"vault-20","name":"Private"},"items":[{"uuid":"login-20","favIndex":1,"createdAt":1700000000,"updatedAt":1700000001,"state":"archived","categoryUuid":"001","details":{"loginFields":[{"value":"synthetic-user","designation":"username"},{"value":"synthetic-ticket20-password","designation":"password"}],"notesPlain":"synthetic note","sections":[{"title":"Security","name":"security","fields":[{"title":"OTP","id":"otp","value":{"totp":"otpauth://totp/Issuer:acct?secret=JBSWY3DPEHPK3PXP"}},{"title":"PIN","id":"pin","value":{"concealed":"synthetic-pin"}}]}],"passwordHistory":[{"value":"synthetic-old-password","time":1600000000}]},"overview":{"title":"Login 🔐","url":"https://primary.invalid","urls":[{"label":"web","url":"https://example.invalid"}],"tags":["migrated","unicode-ñ"]}},{"uuid":"doc-20","favIndex":0,"createdAt":1700000002,"updatedAt":1700000003,"state":"active","categoryUuid":"004","details":{"documentAttributes":{"fileName":"résumé.bin","documentId":"document-20","decryptedSize":2097169},"notesPlain":"document note"},"overview":{"title":"Document"}}]}]}]}"#;
    write_archive(
        &source,
        data.as_bytes(),
        &[("files/document-20___hostile-name.bin", &file_bytes)],
        CompressionMethod::Deflated,
    );
    let original = fs::read(&source).unwrap();
    let preview = vault.preview_1pux(&source).unwrap();
    assert_eq!(preview.total(), 2);
    assert_eq!(preview.page(0, 10).unwrap()[0].status(), CsvRowStatus::New);
    assert_eq!(preview.record(0).unwrap().kind(), RecordKind::Password);
    assert_eq!(preview.record(0).unwrap().title(), "Login 🔐");
    assert!(preview.record(0).unwrap().preserved_fields() >= 3);
    assert_eq!(preview.record(1).unwrap().kind(), RecordKind::File);
    assert_eq!(preview.record(1).unwrap().attachment_count(), 1);
    let staged = vault
        .prepare_1pux_import(
            preview,
            vec![CsvImportDecision::ImportNew, CsvImportDecision::ImportNew],
        )
        .unwrap();
    assert_eq!(staged.report().total(), 2);
    assert!(staged.report().preserved_fields() >= 3);
    let items = staged.item_ids().to_vec();
    let signature = vault.sign(staged.prepared()).unwrap();
    vault
        .commit(
            staged.prepared().command(),
            &signature,
            staged.prepared().body(),
        )
        .unwrap();
    let login = vault.read_record(items[0]).unwrap();
    assert_eq!(login.kind(), RecordKind::Password);
    assert_eq!(login.auth().len(), 2);
    assert!(
        login
            .human()
            .tags
            .iter()
            .any(|tag| tag == "source:archived")
    );
    assert!(login.human().source_fields.iter().any(|field| {
        field.path == "1pux.passwordHistory" && contains(&field.value, b"synthetic-old-password")
    }));
    let document = vault.read_record(items[1]).unwrap();
    assert_eq!(document.attachments()[0].name(), "résumé.bin");
    let mut restored = Vec::new();
    vault
        .read_attachment_to(items[1], *document.attachments()[0].id(), &mut restored)
        .unwrap();
    assert_eq!(restored, file_bytes);
    let database = Connection::open(&vault_path).unwrap();
    assert_eq!(count(&database, "credential_authorizations"), 0);
    assert_eq!(count(&database, "attachment_parts"), 0);
    assert_eq!(count(&database, "attachment_streams"), 1);
    assert_eq!(count(&database, "import_reports"), 1);
    drop(database);
    assert!(
        vault
            .preview_1pux(&source)
            .unwrap()
            .page(0, 10)
            .unwrap()
            .iter()
            .all(|row| row.status() == CsvRowStatus::ExactDuplicate)
    );
    assert_eq!(fs::read(&source).unwrap(), original);
    for path in dir.files() {
        if path != source && path.is_file() {
            let bytes = fs::read(path).unwrap();
            assert!(!contains(&bytes, b"synthetic-ticket20-password"));
            assert!(!contains(&bytes, b"synthetic-old-password"));
        }
    }
}

#[test]
fn totp_note_ambiguous_and_unreferenced_types_remain_loss_visible() {
    let dir = TestDir::new();
    let vault_path = dir.path("vault.sqlite3");
    persist(&vault_path);
    let (mut vault, _peer) = open_human(&vault_path);
    let source = dir.path("types.1pux");
    let data = br#"{"accounts":[{"attrs":{"uuid":"account-types"},"vaults":[{"attrs":{"uuid":"vault-types"},"items":[{"uuid":"totp","categoryUuid":"005","details":{"sections":[{"name":"otp","fields":[{"title":"OTP","value":{"totp":"otpauth://totp/Issuer:types?secret=JBSWY3DPEHPK3PXP"}}]}]},"overview":{"title":"OTP only"}},{"uuid":"unknown","categoryUuid":"999","details":{"loginFields":[{"designation":"username","value":"one"},{"designation":"username","value":"two"},{"designation":"password","value":"synthetic-ambiguous"}],"sections":[{"name":"card","fields":[{"title":"unknown typed","value":{"creditCardNumber":"synthetic-card"}}]}]},"overview":{"title":"Preserved note"}}]}]}]}"#;
    write_entries(
        &source,
        data,
        &[("files/icon-unreferenced", b"synthetic-icon-bytes")],
        CompressionMethod::Stored,
    );
    let preview = vault.preview_1pux(&source).unwrap();
    assert_eq!(preview.total(), 3);
    assert_eq!(preview.record(0).unwrap().kind(), RecordKind::Totp);
    assert_eq!(preview.record(1).unwrap().kind(), RecordKind::Note);
    assert!(preview.record(1).unwrap().preserved_fields() >= 3);
    assert_eq!(preview.record(2).unwrap().kind(), RecordKind::File);
    assert_eq!(preview.record(2).unwrap().attachment_count(), 1);
    let staged = vault
        .prepare_1pux_import(preview, vec![CsvImportDecision::ImportNew; 3])
        .unwrap();
    let items = staged.item_ids().to_vec();
    let signature = vault.sign(staged.prepared()).unwrap();
    vault
        .commit(
            staged.prepared().command(),
            &signature,
            staged.prepared().body(),
        )
        .unwrap();
    assert_eq!(
        vault.read_record(items[0]).unwrap().kind(),
        RecordKind::Totp
    );
    let note = vault.read_record(items[1]).unwrap();
    assert!(note.human().source_fields.iter().any(|field| {
        field.path == "1pux.ambiguous_loginFields" && contains(&field.value, b"synthetic-ambiguous")
    }));
    let mut icon = Vec::new();
    let file = vault.read_record(items[2]).unwrap();
    vault
        .read_attachment_to(items[2], *file.attachments()[0].id(), &mut icon)
        .unwrap();
    assert_eq!(icon, b"synthetic-icon-bytes");
    assert_eq!(
        count(
            &Connection::open(&vault_path).unwrap(),
            "credential_authorizations"
        ),
        0
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn hostile_archives_and_json_fail_closed_without_extracting_any_entry() {
    let dir = TestDir::new();
    let vault_path = dir.path("vault.sqlite3");
    persist(&vault_path);
    let (vault, _peer) = open_human(&vault_path);
    let empty = br#"{"accounts":[{"attrs":{"uuid":"a"},"vaults":[{"attrs":{"uuid":"v"},"items":[{"uuid":"n","details":{},"overview":{"title":"note"}}]}]}]}"#;

    let traversal = dir.path("traversal.1pux");
    write_entries(
        &traversal,
        empty,
        &[
            ("../ticket20-outside-canary", b"escape"),
            ("files\\alt", b"x"),
        ],
        CompressionMethod::Stored,
    );
    assert!(vault.preview_1pux(&traversal).is_err());
    assert!(!dir.path("ticket20-outside-canary").exists());

    let duplicate = dir.path("duplicate.1pux");
    write_entries(
        &duplicate,
        empty,
        &[("files/duplicate", b"one"), ("files/duplicatf", b"two")],
        CompressionMethod::Stored,
    );
    replace_all(&duplicate, b"files/duplicatf", b"files/duplicate");
    assert!(vault.preview_1pux(&duplicate).is_err());

    let symlink_archive = dir.path("symlink-entry.1pux");
    let output = fs::File::create(&symlink_archive).unwrap();
    let mut zip = ZipWriter::new(output);
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    add_metadata(&mut zip, empty, stored);
    zip.add_symlink("files/link", "/synthetic/target", stored)
        .unwrap();
    zip.finish().unwrap();
    assert!(vault.preview_1pux(&symlink_archive).is_err());

    let nested = dir.path("nested.1pux");
    write_entries(
        &nested,
        empty,
        &[("files/hostile", b"PK\x03\x04synthetic")],
        CompressionMethod::Stored,
    );
    assert!(vault.preview_1pux(&nested).is_err());
    let bomb = dir.path("bomb.1pux");
    let bomb_bytes = vec![0_u8; 1024 * 1024];
    write_entries(
        &bomb,
        empty,
        &[("files/hostile", &bomb_bytes)],
        CompressionMethod::Deflated,
    );
    assert!(vault.preview_1pux(&bomb).is_err());

    let truncated = dir.path("truncated.1pux");
    write_entries(&truncated, empty, &[], CompressionMethod::Stored);
    let length = fs::metadata(&truncated).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&truncated)
        .unwrap()
        .set_len(length - 9)
        .unwrap();
    assert!(vault.preview_1pux(&truncated).is_err());

    let duplicate_json = dir.path("duplicate-json.1pux");
    write_entries(
        &duplicate_json,
        br#"{"accounts":[],"accounts":[]}"#,
        &[],
        CompressionMethod::Stored,
    );
    assert!(vault.preview_1pux(&duplicate_json).is_err());
    let base = std::str::from_utf8(empty).unwrap();
    let trailing_json = format!("{base}false");
    let number_json = root_field(
        base,
        r#""future":999999999999999999999999999999999999999999999999999999999999"#,
    );
    let depth_json = root_field(
        base,
        &format!("\"future\":{}0{}", "[".repeat(33), "]".repeat(33)),
    );
    for (name, json) in [
        ("trailing-json.1pux", trailing_json.as_bytes()),
        ("number-range.1pux", number_json.as_bytes()),
        ("depth.1pux", depth_json.as_bytes()),
    ] {
        let path = dir.path(name);
        write_entries(&path, json, &[], CompressionMethod::Stored);
        assert!(vault.preview_1pux(&path).is_err());
    }

    let missing = dir.path("missing-attachment.1pux");
    let missing_data = document_data(7);
    write_entries(
        &missing,
        missing_data.as_bytes(),
        &[],
        CompressionMethod::Stored,
    );
    assert!(vault.preview_1pux(&missing).is_err());

    let wrong_version = dir.path("v2.1pux");
    write_archive_with_attributes(
        &wrong_version,
        br#"{"version":2}"#,
        empty,
        &[],
        CompressionMethod::Stored,
    );
    assert!(vault.preview_1pux(&wrong_version).is_err());

    let oversized_archive = dir.path("oversized-sparse.1pux");
    fs::File::create(&oversized_archive)
        .unwrap()
        .set_len(1024_u64.pow(4) + 256 * 1024 * 1024 + 1)
        .unwrap();
    assert!(vault.preview_1pux(&oversized_archive).is_err());

    let source_link = dir.path("source-link.1pux");
    symlink(&truncated, &source_link).unwrap();
    assert!(vault.preview_1pux(&source_link).is_err());
    let hard_target = dir.path("hard-target.1pux");
    let hard_link = dir.path("hard-link.1pux");
    write_entries(&hard_target, empty, &[], CompressionMethod::Stored);
    fs::hard_link(&hard_target, &hard_link).unwrap();
    assert!(vault.preview_1pux(&hard_target).is_err());
    assert!(vault.preview_1pux(&hard_link).is_err());
    assert_eq!(
        count(&Connection::open(&vault_path).unwrap(), "vault_items"),
        0
    );
}

#[test]
fn changed_source_and_failed_commit_never_publish_partial_attachment_state() {
    let dir = TestDir::new();
    let vault_path = dir.path("vault.sqlite3");
    persist(&vault_path);
    let (mut vault, _peer) = open_human(&vault_path);
    let source = dir.path("atomic.1pux");
    let bytes = synthetic_bytes(1024 * 1024 + 9);
    let data = document_data(bytes.len());
    write_archive(
        &source,
        data.as_bytes(),
        &[("files/document-atomic___name.bin", &bytes)],
        CompressionMethod::Deflated,
    );
    let changed = vault.preview_1pux(&source).unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(b"changed")
        .unwrap();
    assert!(matches!(
        vault.prepare_1pux_import(changed, vec![CsvImportDecision::ImportNew]),
        Err(pm_vault::HumanCommitError::StateChanged)
    ));

    write_archive(
        &source,
        data.as_bytes(),
        &[("files/document-atomic___name.bin", &bytes)],
        CompressionMethod::Deflated,
    );
    let preview = vault.preview_1pux(&source).unwrap();
    let staged = vault
        .prepare_1pux_import(preview, vec![CsvImportDecision::ImportNew])
        .unwrap();
    let prepared = staged.prepared();
    let signature = vault.sign(prepared).unwrap();
    Connection::open(&vault_path)
        .unwrap()
        .execute_batch("CREATE TRIGGER fail_ticket20_audit BEFORE INSERT ON encrypted_audit_records BEGIN SELECT RAISE(ABORT,'ticket20 audit'); END;")
        .unwrap();
    assert!(
        vault
            .commit(prepared.command(), &signature, prepared.body())
            .is_err()
    );
    let database = Connection::open(&vault_path).unwrap();
    for table in [
        "vault_items",
        "revision_parts",
        "attachment_streams",
        "attachment_stream_chunks",
        "authority_events",
        "import_reports",
    ] {
        assert_eq!(count(&database, table), 0, "partial publication in {table}");
    }
    database
        .execute_batch("DROP TRIGGER fail_ticket20_audit;")
        .unwrap();
    drop(database);
    let receipt = vault
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    assert_eq!(vault.receipt(*prepared.transaction_id()).unwrap(), receipt);
    assert_eq!(
        count(&Connection::open(&vault_path).unwrap(), "vault_items"),
        1
    );
}

fn write_archive(path: &Path, data: &[u8], files: &[(&str, &[u8])], method: CompressionMethod) {
    write_archive_with_attributes(
        path,
        br#"{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}"#,
        data,
        files,
        method,
    );
}

fn write_entries(path: &Path, data: &[u8], files: &[(&str, &[u8])], method: CompressionMethod) {
    write_archive_with_attributes(path, br#"{"version":3}"#, data, files, method);
}

fn write_archive_with_attributes(
    path: &Path,
    attributes: &[u8],
    data: &[u8],
    files: &[(&str, &[u8])],
    method: CompressionMethod,
) {
    let output = fs::File::create(path).unwrap();
    let mut zip = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(method);
    zip.start_file("export.attributes", options).unwrap();
    zip.write_all(attributes).unwrap();
    zip.start_file("export.data", options).unwrap();
    zip.write_all(data).unwrap();
    for (name, bytes) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

fn add_metadata(zip: &mut ZipWriter<fs::File>, data: &[u8], options: SimpleFileOptions) {
    zip.start_file("export.attributes", options).unwrap();
    zip.write_all(br#"{"version":3}"#).unwrap();
    zip.start_file("export.data", options).unwrap();
    zip.write_all(data).unwrap();
}

fn document_data(size: usize) -> String {
    format!(
        r#"{{"accounts":[{{"attrs":{{"uuid":"account-atomic"}},"vaults":[{{"attrs":{{"uuid":"vault-atomic"}},"items":[{{"uuid":"item-atomic","details":{{"documentAttributes":{{"fileName":"atomic.bin","documentId":"document-atomic","decryptedSize":{size}}}}},"overview":{{"title":"Atomic"}}}}]}}]}}]}}"#
    )
}

fn root_field(base: &str, field: &str) -> String {
    format!("{},{}{}", &base[..base.len() - 1], field, '}')
}

fn persist(path: &Path) {
    let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &recovery).unwrap();
}
fn open_human(path: &Path) -> (HumanVault, UnixStream) {
    let (socket, peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(socket, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock(
            path,
            MASTER,
            DEVICE,
            channel,
            Arc::new(AuditDeviceCustody::generate().unwrap()),
        )
        .unwrap(),
        peer,
    )
}
fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
fn synthetic_bytes(length: usize) -> Vec<u8> {
    let mut state = 0x20_1a_1b_c3_d4_e5_f6_07_u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}
fn replace_all(path: &Path, from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let mut bytes = fs::read(path).unwrap();
    let mut count = 0;
    for index in 0..=bytes.len() - from.len() {
        if &bytes[index..index + from.len()] == from {
            bytes[index..index + to.len()].copy_from_slice(to);
            count += 1;
        }
    }
    assert_eq!(count, 2);
    fs::write(path, bytes).unwrap();
}
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pm-ticket20-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn files(&self) -> impl Iterator<Item = PathBuf> {
        fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
