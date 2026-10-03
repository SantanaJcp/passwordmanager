// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in, payload-free sync phase measurements for native acceptance.
use std::{io::Write, time::Instant};

#[must_use]
pub fn enabled() -> bool {
    std::env::var_os("PMW2_TIMING").as_deref() == Some(std::ffi::OsStr::new("1"))
}

pub struct Span {
    category: &'static str,
    started: Option<Instant>,
}
impl Span {
    #[must_use]
    pub fn new(category: &'static str) -> Self {
        Self {
            category,
            started: enabled().then(Instant::now),
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            emit(self.category, 1, started.elapsed().as_micros());
        }
    }
}
pub fn count(category: &'static str, count: usize) {
    if enabled() {
        emit(category, count, 0);
    }
}
fn emit(category: &str, count: usize, us: u128) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "PMW2_TIMING category={category} count={count} us={us}"
    );
}
#[must_use]
pub fn valid_line(line: &[u8]) -> bool {
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    let fields: Vec<_> = line.split(' ').collect();
    fields.len() == 4
        && fields[0] == "PMW2_TIMING"
        && fields[1].strip_prefix("category=").is_some_and(|c| {
            !c.is_empty() && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        })
        && fields[2]
            .strip_prefix("count=")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        && fields[3]
            .strip_prefix("us=")
            .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}
