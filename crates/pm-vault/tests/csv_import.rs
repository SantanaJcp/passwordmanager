// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use pm_crypto::KdfProfile;
use pm_vault::{
    AuditDeviceCustody, CausalReducer, CsvDelimiter, CsvEncoding, CsvField, CsvImportDecision,
    CsvImportProfile, CsvMapping, CsvRowStatus, HumanChannel, HumanVault, PendingVault, RecordKind,
};
use rusqlite::Connection;
use std::{
    fmt::Write as _,
    fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

const MASTER: &[u8] = b"synthetic ticket19 master";
const DEVICE: [u8; 16] = [0x19; 16];
static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
#[allow(clippy::too_many_lines)]
fn chrome_apple_and_mappable_csv_preserve_unicode_unknowns_and_require_signed_confirmation() {
    let dir = TestDir::new();
    let path = dir.vault();
    persist(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut vault, _peer) = open_human(&path, custody);
    let chrome="name,url,username,password,note,Future Column\r\n\"Cuenta, 🔐\",https://chrome.invalid/login,usuario,synthetic-chrome-secret,\"linea 1\nlinea 2\",future-value\r\n".as_bytes();
    let preview = vault
        .preview_csv(chrome, &CsvImportProfile::chrome())
        .unwrap();
    assert_eq!(preview.total(), 1);
    assert_eq!(preview.page(0, 10).unwrap()[0].status(), CsvRowStatus::New);
    assert_eq!(preview.page(0, 10).unwrap()[0].unknown_fields(), 1);
    assert_eq!(preview.record(0).unwrap().title(), "Cuenta, 🔐");
    assert_eq!(
        preview
            .record(0)
            .unwrap()
            .unknown_field_paths()
            .collect::<Vec<_>>(),
        vec!["Future Column"]
    );
    let staged = vault
        .prepare_csv_import(preview, vec![CsvImportDecision::ImportNew])
        .unwrap();
    assert_eq!(staged.report().new_items(), 1);
    let item = staged.item_ids()[0];
    commit(&mut vault, staged.prepared());
    let record = vault.read_record(item).unwrap();
    assert_eq!(record.human().title, "Cuenta, 🔐");
    assert_eq!(record.human().notes, "linea 1\nlinea 2");
    assert_eq!(record.human().source_fields[0].path, "Future Column");
    assert_eq!(record.human().source_fields[0].value, b"future-value");
    let apple_map = CsvMapping::new(
        CsvDelimiter::Comma,
        CsvEncoding::Utf8,
        true,
        RecordKind::Password,
        vec![
            (0, CsvField::Title),
            (1, CsvField::Destination),
            (2, CsvField::Username),
            (3, CsvField::Password),
            (4, CsvField::Notes),
            (5, CsvField::OtpAuth),
        ],
    )
    .unwrap();
    let apple="Title,URL,Username,Password,Notes,OTPAuth,Campo futuro\nApple 🍎,https://apple.invalid,u,synthetic-apple-secret,nota,otpauth://totp/Issuer:account?secret=JBSWY3DPEHPK3PXP,preservar\n".as_bytes();
    let preview = vault
        .preview_csv(apple, &CsvImportProfile::apple(apple_map))
        .unwrap();
    assert_eq!(preview.page(0, 1).unwrap()[0].unknown_fields(), 2);
    let staged = vault
        .prepare_csv_import(preview, vec![CsvImportDecision::ImportNew])
        .unwrap();
    let apple_item = staged.item_ids()[0];
    commit(&mut vault, staged.prepared());
    assert_eq!(vault.read_record(apple_item).unwrap().auth().len(), 2);
    let mapped = CsvMapping::new(
        CsvDelimiter::Semicolon,
        CsvEncoding::Utf8,
        true,
        RecordKind::Password,
        vec![
            (0, CsvField::Title),
            (2, CsvField::Destination),
            (1, CsvField::Username),
            (3, CsvField::Password),
        ],
    )
    .unwrap();
    let custom="title;user;site;secret;opaque\nMapeable;ñ;https://mapped.invalid;synthetic-mapped-secret;未知\n".as_bytes();
    let preview = vault
        .preview_csv(custom, &CsvImportProfile::mappable(mapped))
        .unwrap();
    let staged = vault
        .prepare_csv_import(preview, vec![CsvImportDecision::ImportNew])
        .unwrap();
    commit(&mut vault, staged.prepared());
    let db = Connection::open(&path).unwrap();
    assert_eq!(count(&db, "vault_items"), 3);
    assert_eq!(count(&db, "credential_authorizations"), 0);
    assert_eq!(count(&db, "import_reports"), 3);
    assert_eq!(count(&db, "authority_events"), 3);
    drop(db);
    assert!(
        CausalReducer::open(&path)
            .unwrap()
            .view()
            .unwrap()
            .item(&item)
            .is_some()
    );
    for p in dir.files() {
        let bytes = fs::read(p).unwrap();
        for secret in [
            b"synthetic-chrome-secret".as_slice(),
            b"synthetic-apple-secret",
            b"synthetic-mapped-secret",
        ] {
            assert!(!contains(&bytes, secret));
        }
    }
}

#[test]
fn duplicate_decisions_pagination_and_audit_failure_are_atomic() {
    let dir = TestDir::new();
    let path = dir.vault();
    persist(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut vault, _peer) = open_human(&path, custody);
    let mut csv = String::from("name,url,username,password,note\n");
    for i in 0..70 {
        writeln!(
            csv,
            "item-{i},https://batch.invalid/{i},user-{i},synthetic-batch-{i},note"
        )
        .unwrap();
    }
    let preview = vault
        .preview_csv(csv.as_bytes(), &CsvImportProfile::chrome())
        .unwrap();
    assert_eq!(preview.total(), 70);
    assert_eq!(preview.page(64, 64).unwrap().len(), 6);
    let staged = vault
        .prepare_csv_import(preview, vec![CsvImportDecision::ImportNew; 70])
        .unwrap();
    assert_eq!(staged.report().event_pages(), 2);
    let prepared = staged.prepared();
    let signature = vault.sign(prepared).unwrap();
    Connection::open(&path).unwrap().execute_batch("CREATE TRIGGER fail_ticket19_audit BEFORE INSERT ON encrypted_audit_records BEGIN SELECT RAISE(ABORT,'ticket19 audit'); END;").unwrap();
    assert!(
        vault
            .commit(prepared.command(), &signature, prepared.body())
            .is_err()
    );
    let db = Connection::open(&path).unwrap();
    assert_eq!(count(&db, "vault_items"), 0);
    assert_eq!(count(&db, "authority_events"), 0);
    drop(db);
    Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TRIGGER fail_ticket19_audit;")
        .unwrap();
    let receipt = vault
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    let db = Connection::open(&path).unwrap();
    assert_eq!(count(&db, "authority_events"), 70);
    assert_eq!(count(&db, "encrypted_audit_records"), 1);
    drop(db);
    assert_eq!(vault.receipt(*prepared.transaction_id()).unwrap(), receipt);
    assert_eq!(
        vault
            .commit(prepared.command(), &signature, prepared.body())
            .unwrap(),
        receipt
    );
    let preview = vault
        .preview_csv(csv.as_bytes(), &CsvImportProfile::chrome())
        .unwrap();
    assert!(
        preview
            .page(0, 70)
            .unwrap()
            .iter()
            .all(|r| r.status() == CsvRowStatus::ExactDuplicate)
    );
    let staged = vault
        .prepare_csv_import(preview, vec![CsvImportDecision::SkipExact; 70])
        .unwrap();
    assert_eq!(staged.report().skipped_exact(), 70);
    commit(&mut vault, staged.prepared());
    assert_eq!(count(&Connection::open(&path).unwrap(), "vault_items"), 70);
    let malformed = b"name,url,username,password\nunterminated,https://x.invalid,u,\"secret";
    assert!(
        vault
            .preview_csv(malformed, &CsvImportProfile::chrome())
            .is_err()
    );
    assert_eq!(count(&Connection::open(&path).unwrap(), "vault_items"), 70);
}

#[test]
#[allow(clippy::too_many_lines)]
fn explicit_replace_disables_prior_delegation_and_input_limits_fail_closed() {
    let dir = TestDir::new();
    let path = dir.vault();
    persist(&path);
    let custody = Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut vault, _peer) = open_human(&path, custody);
    let original =
        b"name,url,username,password,note\nSame,https://same.invalid,user,synthetic-old,note\n";
    let preview = vault
        .preview_csv(original, &CsvImportProfile::chrome())
        .unwrap();
    let staged = vault
        .prepare_csv_import(preview, vec![CsvImportDecision::ImportNew])
        .unwrap();
    let item = staged.item_ids()[0];
    commit(&mut vault, staged.prepared());
    let db = Connection::open(&path).unwrap();
    let revision: Vec<u8> = db
        .query_row(
            "SELECT visible_revision FROM vault_items WHERE item_id=?1",
            [item.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    db.execute(
        "INSERT INTO credential_authorizations(item_id,revision_id,status,event_digest,control_package,grant,grant_commitment) VALUES(?1,?2,'enabled',?3,x'01',x'01',?4)",
        rusqlite::params![item.as_slice(),revision, [1_u8;32].as_slice(),[2_u8;32].as_slice()],
    ).unwrap();
    drop(db);
    let changed =
        b"name,url,username,password,note\nSame,https://same.invalid,user,synthetic-new,note\n";
    let preview = vault
        .preview_csv(changed, &CsvImportProfile::chrome())
        .unwrap();
    assert_eq!(
        preview.page(0, 1).unwrap()[0].status(),
        CsvRowStatus::CandidateDuplicate
    );
    assert!(
        vault
            .prepare_csv_import(preview, vec![CsvImportDecision::ImportNew])
            .is_err()
    );
    let preview = vault
        .preview_csv(changed, &CsvImportProfile::chrome())
        .unwrap();
    let staged = vault
        .prepare_csv_import(preview, vec![CsvImportDecision::Replace(item)])
        .unwrap();
    assert_eq!(staged.report().replaced(), 1);
    commit(&mut vault, staged.prepared());
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT status FROM credential_authorizations WHERE item_id=?1",
            [item.as_slice()],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "disabled"
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM authority_events WHERE subject=?1 AND kind='disable'",
            [item.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    drop(db);
    let reduced = CausalReducer::open(&path).unwrap().view().unwrap();
    assert!(reduced.item(&item).is_some());
    assert!(!reduced.item_enabled(&item, 1));

    let mapping = CsvMapping::new(
        CsvDelimiter::Tab,
        CsvEncoding::Utf16Le,
        false,
        RecordKind::Password,
        vec![
            (0, CsvField::Title),
            (1, CsvField::Destination),
            (2, CsvField::Username),
            (3, CsvField::Password),
        ],
    )
    .unwrap();
    let mut utf16 = vec![0xff, 0xfe];
    for unit in "UTF16\thttps://utf16.invalid\tu\tsynthetic-utf16\n".encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    assert_eq!(
        vault
            .preview_csv(&utf16, &CsvImportProfile::mappable(mapping.clone()))
            .unwrap()
            .total(),
        1
    );
    assert!(
        vault
            .preview_csv(&utf16[2..], &CsvImportProfile::mappable(mapping))
            .is_err()
    );
    let mut too_many = (0..257).map(|i| format!("c{i}")).collect::<Vec<_>>();
    too_many[0] = "url".into();
    too_many[1] = "username".into();
    too_many[2] = "password".into();
    let oversized_columns = format!("{}\n{}\n", too_many.join(","), vec!["x"; 257].join(","));
    assert!(
        vault
            .preview_csv(oversized_columns.as_bytes(), &CsvImportProfile::chrome())
            .is_err()
    );
    let oversized_row = vec![b'x'; 16 * 1024 * 1024 + 1];
    assert!(
        vault
            .preview_csv(&oversized_row, &CsvImportProfile::chrome())
            .is_err()
    );
}

fn commit(v: &mut HumanVault, p: &pm_vault::PreparedHumanCommand) {
    let s = v.sign(p).unwrap();
    v.commit(p.command(), &s, p.body()).unwrap();
}
fn open_human(path: &Path, c: Arc<AuditDeviceCustody>) -> (HumanVault, UnixStream) {
    let (s, p) = UnixStream::pair().unwrap();
    let ch = HumanChannel::authenticate(s, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock_with_audit_custody(path, MASTER, DEVICE, ch, c).unwrap(),
        p,
    )
}
fn persist(path: &Path) {
    let p = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let r = p.recovery_code().to_string().parse().unwrap();
    p.persist(path, &r).unwrap();
}
fn count(c: &Connection, t: &str) -> i64 {
    c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
        .unwrap()
}
fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "pm-ticket19-{}-{}",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn vault(&self) -> PathBuf {
        self.0.join("vault.sqlite3")
    }
    fn files(&self) -> impl Iterator<Item = PathBuf> {
        fs::read_dir(&self.0).unwrap().map(|e| e.unwrap().path())
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
