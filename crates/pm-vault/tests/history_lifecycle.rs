// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use std::{fs, os::unix::net::UnixStream, path::Path};

use pm_crypto::KdfProfile;
use pm_vault::{
    Attachment, AuthRecord, CausalReducer, Destination, HumanChannel, HumanCommitError,
    HumanMetadata, HumanVault, ItemLifecycle, LogicalRecord, PendingVault, RecordKind,
};
use rusqlite::Connection;

const MASTER: &[u8] = b"synthetic ticket18 master";
const DEVICE: [u8; 16] = [0x18; 16];

#[test]
fn losing_history_restores_as_a_new_revision_without_implicit_enable() {
    let dir = TestDir::new("restore");
    let path = dir.path();
    persist(&path);
    let (mut vault, _peer) = open_human(&path);
    let first = record("primera", b"ticket18-first-canary");
    let created = vault.prepare_create_record(&first).unwrap();
    let item = *created.item_id();
    commit(&mut vault, &created);
    let first_revision = *vault.history(item).unwrap().entries()[0].revision_id();

    let second = record("segunda", b"ticket18-second-canary");
    let edited = vault.prepare_edit_record(item, &second).unwrap();
    commit(&mut vault, &edited);
    let history = vault.history(item).unwrap();
    assert_eq!(history.lifecycle(), ItemLifecycle::Active);
    assert_eq!(history.entries().len(), 2);
    assert_eq!(history.entries().iter().filter(|e| e.visible()).count(), 1);
    assert_eq!(vault.read_revision(item, first_revision).unwrap(), first);

    let deleted = vault.prepare_delete(item).unwrap();
    commit(&mut vault, &deleted);
    assert_eq!(
        vault.history(item).unwrap().lifecycle(),
        ItemLifecycle::Trash
    );
    let restored = vault.prepare_restore(item, first_revision).unwrap();
    let restored_id = *restored.item_id();
    assert_eq!(restored_id, item);
    let receipt = commit(&mut vault, &restored);
    assert_eq!(vault.receipt(*restored.transaction_id()).unwrap(), receipt);
    assert_eq!(vault.read_record(item).unwrap(), first);
    let after = vault.history(item).unwrap();
    assert_eq!(after.lifecycle(), ItemLifecycle::Active);
    assert_eq!(after.entries().len(), 3);
    let new_revision = *after
        .entries()
        .iter()
        .find(|e| e.visible())
        .unwrap()
        .revision_id();
    assert_ne!(new_revision, first_revision);
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT status FROM credential_authorizations WHERE item_id=?1",
                [item.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_else(|_| "absent".to_owned()),
        "absent"
    );
    let view = CausalReducer::open(&path).unwrap().view().unwrap();
    assert_eq!(view.item(&item).unwrap().lifecycle(), ItemLifecycle::Active);
    assert_eq!(view.item(&item).unwrap().history().len(), 3);
    assert!(!view.item_enabled(&item, 1));
}

#[test]
fn revision_and_item_purge_are_scoped_atomic_and_leave_only_replay_markers() {
    let dir = TestDir::new("purge");
    let path = dir.path();
    persist(&path);
    let (mut vault, _peer) = open_human(&path);
    let first = record("historial", b"ticket18-purged-history-canary");
    let created = vault.prepare_create_record(&first).unwrap();
    let item = *created.item_id();
    commit(&mut vault, &created);
    let first_revision = *vault.history(item).unwrap().entries()[0].revision_id();
    let edited = vault
        .prepare_edit_record(item, &record("visible", b"ticket18-visible-canary"))
        .unwrap();
    commit(&mut vault, &edited);

    let purge = vault
        .prepare_purge_revisions(item, vec![first_revision])
        .unwrap();
    assert_eq!(purge.scope().revision_ids(), &[first_revision]);
    assert_eq!(purge.scope().attachment_count(), 1);
    assert!(!purge.scope().terminal());
    let before = database_counts(&path);
    Connection::open(&path).unwrap().execute_batch("CREATE TRIGGER ticket18_fail_audit BEFORE INSERT ON encrypted_audit_records BEGIN SELECT RAISE(ABORT,'ticket18 audit'); END;").unwrap();
    let signature = vault.sign(purge.prepared()).unwrap();
    assert!(matches!(
        vault.commit(
            purge.prepared().command(),
            &signature,
            purge.prepared().body()
        ),
        Err(HumanCommitError::Storage(_))
    ));
    assert_eq!(database_counts(&path), before);
    assert_eq!(vault.read_revision(item, first_revision).unwrap(), first);
    Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TRIGGER ticket18_fail_audit")
        .unwrap();
    commit(&mut vault, purge.prepared());
    assert!(matches!(
        vault.read_revision(item, first_revision),
        Err(HumanCommitError::ItemNotFound)
    ));
    assert!(
        vault
            .prepare_purge_revisions(item, vec![first_revision])
            .is_err()
    );
    let visible = *vault
        .history(item)
        .unwrap()
        .entries()
        .iter()
        .find(|e| e.visible())
        .unwrap()
        .revision_id();
    assert!(vault.prepare_purge_revisions(item, vec![visible]).is_err());

    let deleted = vault.prepare_delete(item).unwrap();
    commit(&mut vault, &deleted);
    let purge_item = vault.prepare_purge_item(item).unwrap();
    assert!(purge_item.scope().terminal());
    assert_eq!(purge_item.scope().revision_ids(), &[visible]);
    assert_eq!(purge_item.scope().attachment_count(), 1);
    commit(&mut vault, purge_item.prepared());
    assert!(matches!(
        vault.history(item),
        Err(HumanCommitError::ItemNotFound)
    ));
    let db = Connection::open(&path).unwrap();
    assert_eq!(count(&db, "vault_items"), 0);
    assert_eq!(count(&db, "revision_parts"), 0);
    assert_eq!(count(&db, "attachment_parts"), 0);
    assert_eq!(count(&db, "purged_items"), 1);
    assert_eq!(count(&db, "purged_revisions"), 1);
    assert_eq!(count(&db, "authority_events"), 5);
    drop(db);
    let view = CausalReducer::open(&path).unwrap().view().unwrap();
    assert_eq!(view.item(&item).unwrap().lifecycle(), ItemLifecycle::Purged);
    assert!(view.item(&item).unwrap().visible_revision().is_none());
    for file in dir.files() {
        let bytes = fs::read(file).unwrap();
        assert!(!contains(&bytes, b"ticket18-purged-history-canary"));
        assert!(!contains(&bytes, b"ticket18-visible-canary"));
    }
}

fn record(title: &str, attachment: &[u8]) -> LogicalRecord {
    LogicalRecord::new(
        RecordKind::Password,
        HumanMetadata {
            title: title.to_owned(),
            destinations: vec![Destination {
                label: "inicio".to_owned(),
                value: "https://ticket18.invalid".to_owned(),
            }],
            tags: vec![],
            favorite: false,
            notes: String::new(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![AuthRecord::Password {
            username: "synthetic".to_owned(),
            password: format!("ticket18-{title}-secret").into_bytes(),
            destination_refs: vec![0],
        }],
        vec![
            Attachment::new(
                [title.as_bytes()[0]; 16],
                "adjunto.bin",
                "application/octet-stream",
                attachment,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn commit(
    vault: &mut HumanVault,
    prepared: &pm_vault::PreparedHumanCommand,
) -> pm_vault::HumanReceipt {
    vault
        .commit(
            prepared.command(),
            &vault.sign(prepared).unwrap(),
            prepared.body(),
        )
        .unwrap()
}

fn database_counts(path: &Path) -> Vec<i64> {
    let db = Connection::open(path).unwrap();
    [
        "vault_items",
        "revision_parts",
        "attachment_parts",
        "authority_events",
        "outbox",
        "human_receipts",
        "encrypted_audit_records",
    ]
    .iter()
    .map(|table| count(&db, table))
    .collect()
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn persist(path: &Path) {
    let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let recovery = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(path, &recovery).unwrap();
}

fn open_human(path: &Path) -> (HumanVault, UnixStream) {
    let (server, peer) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock(path, MASTER, DEVICE, channel).unwrap(),
        peer,
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

struct TestDir(std::path::PathBuf);
impl TestDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pm-ticket18-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("vault.sqlite3")
    }
    fn files(&self) -> impl Iterator<Item = std::path::PathBuf> + '_ {
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
