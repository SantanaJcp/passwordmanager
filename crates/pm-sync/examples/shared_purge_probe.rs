// SPDX-License-Identifier: AGPL-3.0-only
//! Regression probe of pending purged revision publication over real TLS/RPK.

#[cfg(target_os = "linux")]
pub mod probe {
    use std::{
        fmt::Write as _,
        fs,
        os::unix::{fs::PermissionsExt, net::UnixStream},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use pm_crypto::KdfProfile;
    use pm_sync::{ProcessTlsTransport, SyncReplica};
    use pm_vault::{
        AuditDeviceCustody, CausalReducer, HumanChannel, HumanMetadata, HumanVault, LogicalRecord,
        PendingVault, PreparedHumanCommand, RecordKind,
    };

    const MASTER: &[u8] = b"synthetic pmshared purge master";

    struct Fixture {
        root: PathBuf,
        server: Option<Child>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(server) = self.server.as_mut() {
                server.kill().expect("stop the owned TLS server");
                server.wait().expect("reap the owned TLS server");
            }
            fs::remove_dir_all(&self.root).expect("remove only the owned probe directory");
            assert!(!self.root.exists());
        }
    }

    fn tls_key(root: &Path, name: &str) -> (PathBuf, PathBuf) {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut public = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        public.extend_from_slice(pair.public_key().as_ref());
        let private = root.join(format!("{name}.key"));
        let public_path = root.join(format!("{name}.pub"));
        let mut bytes = b"PMK1".to_vec();
        bytes.extend_from_slice(
            &u32::try_from(document.as_ref().len())
                .unwrap()
                .to_be_bytes(),
        );
        bytes.extend_from_slice(document.as_ref());
        bytes.extend_from_slice(&public);
        fs::write(&private, bytes).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o400)).unwrap();
        fs::write(&public_path, public).unwrap();
        (private, public_path)
    }

    fn commit(human: &mut HumanVault, prepared: &PreparedHumanCommand) {
        let signature = human.sign(prepared).unwrap();
        human
            .commit(prepared.command(), &signature, prepared.body())
            .unwrap();
    }

    fn record(title: &str) -> LogicalRecord {
        LogicalRecord::new(
            RecordKind::Note,
            HumanMetadata {
                title: title.into(),
                destinations: vec![],
                tags: vec![],
                favorite: false,
                notes: pm_crypto::ProtectedText::copy_from_str("synthetic pmshared purged payload")
                    .expect("locked synthetic notes"),
                fields: vec![],
                source_fields: vec![],
            },
            vec![],
            vec![],
        )
        .unwrap()
    }

    fn count(db: &rusqlite::Connection, table: &str) -> i64 {
        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    /// Runs the synthetic regression against the supplied server executable.
    ///
    /// # Panics
    /// Panics if fixture prerequisites, invariants, or owned cleanup fail.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn run(program: &Path) -> bool {
        let root = std::env::temp_dir().join(format!("pmshared-purge-{}", std::process::id()));
        fs::create_dir(&root).expect("exclusive fixture directory");
        let mut fixture = Fixture { root, server: None };
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        let vault = fixture.root.join("vault.sqlite3");
        let pending = PendingVault::new(MASTER, KdfProfile::confirmed(64, 3).unwrap()).unwrap();
        let recovery = pending.recovery_code().to_string().parse().unwrap();
        pending.persist(&vault, &recovery).unwrap();
        let (channel, _peer) = UnixStream::pair().unwrap();
        let mut human = HumanVault::unlock(
            &vault,
            MASTER,
            [0x63; 16],
            HumanChannel::authenticate(channel, unsafe { libc::geteuid() }).unwrap(),
            Arc::new(AuditDeviceCustody::generate().unwrap()),
        )
        .unwrap();
        let (server_key, server_public) = tls_key(&fixture.root, "server");
        let (client_key, client_public) = tls_key(&fixture.root, "client");
        let pin: [u8; 44] = fs::read(&server_public).unwrap().try_into().unwrap();
        let client: [u8; 44] = fs::read(&client_public).unwrap().try_into().unwrap();
        let pairing = human.create_sync_pairing(pin).unwrap();
        let mut namespace = String::new();
        for byte in pairing.namespace() {
            write!(&mut namespace, "{byte:02x}").unwrap();
        }
        let prepared = human
            .prepare_create_record(&record("synthetic pmshared create"))
            .unwrap();
        let item = *prepared.item_id();
        commit(&mut human, &prepared);
        let prepared = human
            .prepare_edit_record(item, &record("synthetic pmshared edit"))
            .unwrap();
        commit(&mut human, &prepared);
        let prepared = human.prepare_delete(item).unwrap();
        commit(&mut human, &prepared);
        let purge = human.prepare_purge_item(item).unwrap();
        commit(&mut human, purge.prepared());
        let db = rusqlite::Connection::open(&vault).unwrap();
        let headers = count(&db, "authority_events");
        let pending = count(&db, "outbox");
        assert_eq!(count(&db, "vault_items"), 0);
        assert_eq!(count(&db, "revision_parts"), 0);
        assert_eq!(count(&db, "purged_items"), 1);
        assert_eq!(pending, headers);
        let revisions: i64 = db
            .query_row(
                "SELECT count(*) FROM authority_events WHERE kind='item-revision'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        println!(
            "PRE push items=0 payloads=0 purge-markers=1 signed-headers={headers} pending={pending} revisions={revisions}"
        );
        let mut reducer = CausalReducer::open(&vault).unwrap();
        let events = reducer.pending_outbox().unwrap();
        let graphless = reducer.apply_received_package(&events, &[]);
        println!(
            "PRE independent graphless-reception-accepted={}",
            graphless.is_ok()
        );
        assert_eq!(count(&db, "authority_events"), headers);
        assert_eq!(count(&db, "outbox"), pending);
        let socket = fixture.root.join("sync.sock");
        let server_db = fixture.root.join("opaque.sqlite3");
        fixture.server = Some(
            Command::new(program)
                .arg("serve")
                .arg("--db")
                .arg(&server_db)
                .arg("--socket")
                .arg(&socket)
                .arg("--server-key")
                .arg(server_key)
                .arg("--namespace")
                .arg(namespace)
                .arg("--client-pub")
                .arg(client_public)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "owned TLS server readiness");
            assert!(
                fixture
                    .server
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_none()
            );
            thread::sleep(Duration::from_millis(10));
        }
        let transport = ProcessTlsTransport::new(program, &socket, &client_key, &server_public);
        let mut replica = SyncReplica::new(&vault, pairing, client, pin).unwrap();
        let result = replica.push(&transport);
        let server = rusqlite::Connection::open(&server_db).unwrap();
        println!(
            "POST push result={result:?} pending={} signed-headers={} opaque-blocks={} roots={}",
            count(&db, "outbox"),
            count(&db, "authority_events"),
            count(&server, "blocks"),
            count(&server, "roots")
        );
        assert_eq!(count(&db, "authority_events"), headers);
        let valid = matches!(result, Ok(n) if i64::try_from(n).unwrap() == pending)
            && count(&db, "outbox") == 0
            && count(&server, "roots") > 0;
        if !valid {
            assert_eq!(count(&db, "outbox"), pending, "no false acknowledgement");
            println!("RED pending purged revision headers must publish without deleted payloads");
        }
        let view = CausalReducer::open(&vault).unwrap().view().unwrap();
        assert_eq!(
            view.item(&item).unwrap().lifecycle(),
            pm_vault::ItemLifecycle::Purged
        );
        drop(server);
        drop(db);
        drop(human);
        drop(fixture);
        valid
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        let program = std::env::args_os()
            .nth(1)
            .expect("explicit path to pm-sync binary");
        if probe::run(std::path::Path::new(&program)) {
            return std::process::ExitCode::SUCCESS;
        }
    }
    std::process::ExitCode::from(1)
}
