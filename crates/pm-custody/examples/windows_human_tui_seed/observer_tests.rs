// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Database(std::path::PathBuf);

impl Database {
    fn create(schema: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "pm-chef-observer-{}-{}.sqlite3",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!path.exists(), "synthetic fixture collision");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(schema).unwrap();
        db.close().unwrap();
        Self(path)
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

fn retire_rows(rows: &[(&str, u8)]) -> Database {
    let fixture = Database::create("CREATE TABLE authority_events(kind TEXT, subject BLOB);");
    let db = rusqlite::Connection::open(&fixture.0).unwrap();
    for (kind, subject) in rows {
        db.execute(
            "INSERT INTO authority_events VALUES(?1,?2)",
            rusqlite::params![kind, vec![*subject; 16]],
        )
        .unwrap();
    }
    db.close().unwrap();
    fixture
}

#[test]
fn missing_table_reports_actual_query_error_without_sql_or_path() {
    let fixture = Database::create("CREATE TABLE unrelated(value TEXT);");
    let error = observe(&fixture.0, Operation::Retire).unwrap_err();
    assert_eq!(
        error,
        "WINDOWS_SQLITE_OBSERVER operation=retire phase=retire-query category=sqlite sqlite-primary=1 sqlite-extended=1"
    );
}

#[test]
fn retirement_controls_preserve_exact_subject_kind_and_count() {
    for (rows, count) in [
        (vec![], 0),
        (vec![("device-retire", 0x28)], 1),
        (vec![("device-retire", 0x28), ("device-retire", 0x28)], 2),
        (vec![("device-retire", 0x29)], 0),
        (vec![("device-grant", 0x28)], 0),
    ] {
        let fixture = retire_rows(&rows);
        let result = observe(&fixture.0, Operation::Retire);
        if count == 1 {
            assert_eq!(
                result.unwrap(),
                "PASS device-retire signed-event=1 subject=second-device close=checked"
            );
        } else {
            assert_eq!(
                result.unwrap_err(),
                format!(
                    "WINDOWS_SQLITE_OBSERVER operation=retire phase=retire-count category=count-mismatch observed-count={count}"
                )
            );
        }
    }
}

#[test]
fn sync_success_and_failed_roots_query_are_distinct() {
    let complete = Database::create(
        "CREATE TABLE blocks(value BLOB); INSERT INTO blocks VALUES(x'27'); CREATE TABLE roots(value BLOB); INSERT INTO roots VALUES(x'28');",
    );
    assert_eq!(
        observe(&complete.0, Operation::Sync).unwrap(),
        "NATIVE_SYNC blocks=1 roots=1 close=checked"
    );
    let missing =
        Database::create("CREATE TABLE blocks(value BLOB); INSERT INTO blocks VALUES(x'27');");
    assert_eq!(
        observe(&missing.0, Operation::Sync).unwrap_err(),
        "WINDOWS_SQLITE_OBSERVER operation=sync phase=roots-query category=sqlite sqlite-primary=1 sqlite-extended=1"
    );
}

#[test]
fn readonly_open_failure_has_actual_codes_and_creates_nothing() {
    let fixture = Database::create("CREATE TABLE unrelated(value TEXT);");
    let absent = fixture.0.with_extension("absent");
    assert!(!absent.exists());
    let error = observe(&absent, Operation::Retire).unwrap_err();
    assert_eq!(
        error,
        "WINDOWS_SQLITE_OBSERVER operation=retire phase=open category=sqlite sqlite-primary=14 sqlite-extended=14"
    );
    assert!(!absent.exists());
}

#[test]
fn read_type_error_never_prints_the_value_or_invents_sqlite_codes() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE probe(value TEXT); INSERT INTO probe VALUES('synthetic-secret-not-for-output');").unwrap();
    let error = query_count(
        &db,
        Operation::Retire,
        "retire-query",
        "SELECT value FROM probe",
        [],
    )
    .unwrap_err();
    db.close().unwrap();
    assert_eq!(
        error,
        "WINDOWS_SQLITE_OBSERVER operation=retire phase=retire-query category=read-type sqlite-primary=not-available sqlite-extended=not-available"
    );
}

fn busy_close_error(db: rusqlite::Connection) -> rusqlite::Error {
    let mut statement = std::ptr::null_mut();
    // SAFETY: this test owns db throughout; the raw statement is finalized below
    // before the recovered connection is closed. No application data is used.
    let result = unsafe {
        rusqlite::ffi::sqlite3_prepare_v2(
            db.handle(),
            c"SELECT 1".as_ptr(),
            -1,
            &raw mut statement,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    let (recovered, error) = db.close().unwrap_err();
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_finalize(statement) },
        rusqlite::ffi::SQLITE_OK
    );
    recovered.close().unwrap();
    error
}

#[test]
fn actual_busy_close_suppresses_success() {
    let error = finish(
        Operation::Retire,
        Ok("PASS must not escape".to_owned()),
        Err(busy_close_error(
            rusqlite::Connection::open_in_memory().unwrap(),
        )),
    )
    .unwrap_err();
    assert_eq!(
        error,
        "WINDOWS_SQLITE_OBSERVER operation=retire phase=close category=sqlite sqlite-primary=5 sqlite-extended=5"
    );
    assert!(!error.contains("PASS"));
}

#[test]
fn primary_and_actual_busy_close_errors_survive_together() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    let primary = query_count(
        &db,
        Operation::Retire,
        "retire-query",
        "SELECT count(*) FROM authority_events",
        [],
    );
    let error = finish(
        Operation::Retire,
        primary.map(|count| count.to_string()),
        Err(busy_close_error(db)),
    )
    .unwrap_err();
    assert_eq!(
        error,
        "WINDOWS_SQLITE_OBSERVER operation=retire phase=retire-query category=sqlite sqlite-primary=1 sqlite-extended=1\nWINDOWS_SQLITE_OBSERVER operation=retire phase=close category=sqlite sqlite-primary=5 sqlite-extended=5"
    );
}
