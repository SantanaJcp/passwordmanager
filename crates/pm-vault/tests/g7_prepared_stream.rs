// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(target_os = "linux")]

use std::{fs, io::Cursor, os::unix::net::UnixStream, path::Path};

use pm_crypto::KdfProfile;
use pm_vault::{
    Attachment, AttachmentReader, AuditDeviceCustody, HumanChannel, HumanCommitError,
    HumanMetadata, HumanVault, LogicalRecord, PendingVault, RecordKind,
};
use rusqlite::{Connection, types::Value};

const PASSWORD: &[u8] = b"synthetic chef G7 master";
const DEVICE: [u8; 16] = [0x71; 16];
const ATTACHMENT: [u8; 16] = [0x72; 16];
const TABLES: [&str; 15] = [
    "vault_items",
    "revision_parts",
    "attachment_streams",
    "attachment_stream_chunks",
    "authority_events",
    "outbox",
    "human_receipts",
    "human_challenges",
    "human_staging",
    "human_staging_streams",
    "human_staging_stream_chunks",
    "audit_keys",
    "audit_state",
    "encrypted_audit_records",
    "vault_metadata",
];

// This is a policy discriminator, not a fix: losing these encrypted rows on
// final-commit failure would make the already-signed G4 retry impossible.
#[test]
#[allow(clippy::too_many_lines)]
fn failed_final_commit_retains_exact_stream_for_same_signed_retry_and_receipt() {
    let directory = OwnedDirectory::new();
    let path = directory.0.join("vault.sqlite3");
    let pending = PendingVault::new(PASSWORD, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
    let confirmation = pending.recovery_code().to_string().parse().unwrap();
    pending.persist(&path, &confirmation).unwrap();
    let custody = std::sync::Arc::new(AuditDeviceCustody::generate().unwrap());
    let (mut vault, peer) = unlock(&path, &custody);
    let content = vec![0x75; 1024 * 1024 + 4096];
    let attachment = Attachment::new(
        ATTACHMENT,
        "synthetic-g7.bin",
        "application/octet-stream",
        &content,
    )
    .unwrap();
    let descriptor = Attachment::descriptor(
        ATTACHMENT,
        attachment.name(),
        attachment.mime(),
        attachment.size(),
        *attachment.sha256(),
    )
    .unwrap();
    let record = LogicalRecord::new_streaming(
        RecordKind::File,
        HumanMetadata {
            title: "Synthetic G7".into(),
            destinations: vec![],
            tags: vec![],
            favorite: false,
            notes: pm_crypto::ProtectedText::copy_from_str("").unwrap(),
            fields: vec![],
            source_fields: vec![],
        },
        vec![],
        vec![descriptor],
    )
    .unwrap();
    let mut source = Cursor::new(&content);
    let prepared = vault
        .prepare_create_record_streaming(
            &record,
            &mut [AttachmentReader::new(ATTACHMENT, &mut source)],
        )
        .unwrap();
    let signature = vault.sign(&prepared).unwrap();
    let db = Connection::open(&path).unwrap();
    let before = snapshot(&db);
    assert_eq!(
        before[10].len(),
        2,
        "two encrypted staged chunks must exist"
    );
    db.execute_batch(
        "CREATE TRIGGER chef_fail_audit BEFORE INSERT ON encrypted_audit_records
        BEGIN SELECT RAISE(ABORT, 'synthetic chef G7 audit failure'); END;",
    )
    .unwrap();
    assert!(matches!(
        vault.commit(prepared.command(), &signature, prepared.body()),
        Err(HumanCommitError::Storage(_))
    ));
    assert_eq!(
        snapshot(&db),
        before,
        "failed final transaction changed durable rows"
    );
    assert!(matches!(
        vault.receipt(*prepared.transaction_id()),
        Err(HumanCommitError::ItemNotFound)
    ));
    db.execute_batch("DROP TRIGGER chef_fail_audit").unwrap();
    drop(db);
    drop(vault);
    drop(peer);

    let (mut vault, peer) = unlock(&path, &custody);
    let db = Connection::open(&path).unwrap();
    let reopened = snapshot(&db);
    for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14] {
        assert_eq!(
            reopened[index], before[index],
            "reopen changed {}",
            TABLES[index]
        );
    }
    assert_eq!(
        reopened[13].len(),
        before[13].len() + 1,
        "human unlock adds one audit event"
    );
    let receipt = vault
        .commit(prepared.command(), &signature, prepared.body())
        .unwrap();
    let committed = snapshot(&db);
    for index in [0, 4, 5, 6] {
        assert_eq!(
            committed[index].len(),
            1,
            "single committed {}",
            TABLES[index]
        );
    }
    for index in [8, 9, 10] {
        assert!(
            committed[index].is_empty(),
            "success retained {}",
            TABLES[index]
        );
    }
    let mut output = Vec::new();
    vault
        .read_attachment_to(*prepared.item_id(), ATTACHMENT, &mut output)
        .unwrap();
    assert_eq!(output, content, "retry corrupted attachment content");
    assert_eq!(vault.receipt(*prepared.transaction_id()).unwrap(), receipt);
    assert_eq!(
        vault
            .commit(prepared.command(), &signature, prepared.body())
            .unwrap(),
        receipt
    );
    assert_eq!(
        snapshot(&db),
        committed,
        "receipt or replay repeated a durable effect"
    );
    drop(db);
    drop(vault);
    drop(peer);
    directory.close();
}

fn snapshot(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    TABLES
        .iter()
        .map(|table| {
            let mut statement = db
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let width = statement.column_count();
            statement
                .query_map([], |row| (0..width).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        })
        .collect()
}

fn unlock(path: &Path, custody: &std::sync::Arc<AuditDeviceCustody>) -> (HumanVault, UnixStream) {
    let (server, client) = UnixStream::pair().unwrap();
    let channel = HumanChannel::authenticate(server, unsafe { libc::geteuid() }).unwrap();
    (
        HumanVault::unlock(
            path,
            PASSWORD,
            DEVICE,
            channel,
            std::sync::Arc::clone(custody),
        )
        .unwrap(),
        client,
    )
}

struct OwnedDirectory(std::path::PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("chef-g7-stream-{}", std::process::id()));
        fs::create_dir(&path).unwrap(); // Collision fails; never remove an existing fixture.
        Self(path)
    }
    fn close(self) {
        fs::remove_dir_all(&self.0).expect("owned G7 fixture cleanup");
        assert!(!self.0.exists());
    }
}
