// SPDX-License-Identifier: AGPL-3.0-only
//! Local fixture observer shared by Windows execution and host-side example tests.
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Operation {
    Sync,
    Retire,
}

impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Retire => "retire",
        }
    }
}

const RETIRE_QUERY: &str =
    "SELECT count(*) FROM authority_events WHERE kind='device-retire' AND subject=?1";
const RETIRE_SUBJECT: [u8; 16] = [0x28; 16];

// Render only fixed categories and actual numeric codes. rusqlite error text can
// contain paths, SQL or row values, so neither Display nor Debug is used here.
fn sqlite_diagnostic(operation: Operation, phase: &'static str, error: &rusqlite::Error) -> String {
    let prefix = format!(
        "WINDOWS_SQLITE_OBSERVER operation={} phase={phase}",
        operation.label()
    );
    match error {
        rusqlite::Error::SqliteFailure(code, _) => format!(
            "{prefix} category=sqlite sqlite-primary={} sqlite-extended={}",
            code.extended_code & 0xff,
            code.extended_code
        ),
        other => {
            let category = match other {
                rusqlite::Error::InvalidColumnType(..)
                | rusqlite::Error::FromSqlConversionFailure(..)
                | rusqlite::Error::IntegralValueOutOfRange(..) => "read-type",
                _ => "sqlite-api",
            };
            format!(
                "{prefix} category={category} sqlite-primary=not-available sqlite-extended=not-available"
            )
        }
    }
}

fn count_diagnostic(operation: Operation, phase: &'static str, count: i64) -> String {
    format!(
        "WINDOWS_SQLITE_OBSERVER operation={} phase={phase} category=count-mismatch observed-count={count}",
        operation.label()
    )
}

fn query_count(
    db: &rusqlite::Connection,
    operation: Operation,
    phase: &'static str,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<i64, String> {
    db.query_row(sql, params, |row| row.get(0))
        .map_err(|error| sqlite_diagnostic(operation, phase, &error))
}

fn finish(
    operation: Operation,
    observation: Result<String, String>,
    closed: rusqlite::Result<()>,
) -> Result<String, String> {
    match (observation, closed) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(close)) => Err(sqlite_diagnostic(operation, "close", &close)),
        (Err(primary), Err(close)) => Err(format!(
            "{primary}\n{}",
            sqlite_diagnostic(operation, "close", &close)
        )),
    }
}

pub(super) fn observe(path: &Path, operation: Operation) -> Result<String, String> {
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| sqlite_diagnostic(operation, "open", &error))?;
    let observation = (|| {
        if operation == Operation::Sync {
            let blocks = query_count(
                &db,
                operation,
                "blocks-query",
                "SELECT count(*) FROM blocks",
                [],
            )?;
            let roots = query_count(
                &db,
                operation,
                "roots-query",
                "SELECT count(*) FROM roots",
                [],
            )?;
            if blocks <= 0 {
                return Err(count_diagnostic(operation, "blocks-count", blocks));
            }
            if roots <= 0 {
                return Err(count_diagnostic(operation, "roots-count", roots));
            }
            Ok(format!(
                "NATIVE_SYNC blocks={blocks} roots={roots} close=checked"
            ))
        } else {
            let count = query_count(
                &db,
                operation,
                "retire-query",
                RETIRE_QUERY,
                [RETIRE_SUBJECT.as_slice()],
            )?;
            if count != 1 {
                return Err(count_diagnostic(operation, "retire-count", count));
            }
            Ok("PASS device-retire signed-event=1 subject=second-device close=checked".to_owned())
        }
    })();
    // Always attempt the same checked close, even if the query/count failed.
    // On Err, the returned Connection is dropped as in the inherited observer;
    // its Drop behavior is unchanged. Preserve the explicit close error here.
    let closed = db.close().map_err(|(_, error)| error);
    finish(operation, observation, closed)
}

#[cfg(test)]
#[path = "observer_tests.rs"]
mod tests;
