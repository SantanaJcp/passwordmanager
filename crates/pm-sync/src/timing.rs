// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in, payload-free sync phase measurements for native acceptance.
use std::{io::Write, time::Instant};

#[must_use]
pub fn enabled() -> bool {
    w1_enabled() || std::env::var_os("PMW2_TIMING").as_deref() == Some(std::ffi::OsStr::new("1"))
}

#[must_use]
pub fn w1_enabled() -> bool {
    std::env::var_os("PMW1_TIMING").as_deref() == Some(std::ffi::OsStr::new("1"))
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
pub fn duration(category: &'static str, elapsed: std::time::Duration) {
    if enabled() {
        emit(category, 1, elapsed.as_micros());
    }
}
fn emit(category: &str, count: usize, us: u128) {
    // A selected measurement sink never falls back to another destination.
    // It must already exist; the native harness owns and validates its ACL.
    if w1_enabled() {
        static FILE: std::sync::OnceLock<Result<std::sync::Mutex<std::fs::File>, std::io::Error>> =
            std::sync::OnceLock::new();
        let file = FILE.get_or_init(|| {
            let path = std::env::var_os("PMW1_TIMING_FILE").ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing timing sink")
            })?;
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .map(std::sync::Mutex::new)
        });
        let line = format!("PMW2_TIMING category={category} count={count} us={us}\n");
        if !file.as_ref().is_ok_and(|file| {
            file.lock()
                .is_ok_and(|mut file| file.write_all(line.as_bytes()).is_ok())
        }) {
            eprintln!("PMW1_TIMING_FAILED");
        }
        return;
    }
    #[cfg(not(windows))]
    let _ = writeln!(
        std::io::stderr().lock(),
        "PMW2_TIMING category={category} count={count} us={us}"
    );
    #[cfg(windows)]
    {
        let logging = Instant::now();
        // Windows stderr is a synchronous pipe when redirected by the native
        // harness. Formatting directly into it issues a write per fragment;
        // form the same bounded, payload-free line before acquiring the sink.
        let line = format!("PMW2_TIMING category={category} count={count} us={us}\n");
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
        STDERR_MICROS.with(|total| {
            total.set(total.get() + logging.elapsed().as_micros());
        });
    }
}

#[cfg(windows)]
thread_local! {
    static STDERR_MICROS: std::cell::Cell<u128> = const { std::cell::Cell::new(0) };
}

/// Windows-only diagnostic: measure the inherited formatted stderr sink itself.
#[cfg(windows)]
pub fn windows_stderr_summary() {
    if enabled() {
        STDERR_MICROS.with(|total| emit("server_timing_emit", 1, total.replace(0)));
    }
}

thread_local! {
    static PUTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LAST_RPC: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

pub fn put_started() {
    if w1_enabled() {
        PUTS.set(PUTS.get() + 1);
        count("put_started", 1);
    }
}

pub struct EventPuts(Option<usize>);
impl Default for EventPuts {
    fn default() -> Self {
        Self(w1_enabled().then(|| PUTS.get()))
    }
}
impl Drop for EventPuts {
    fn drop(&mut self) {
        if let Some(started) = self.0 {
            count("event_puts", PUTS.get() - started);
        }
    }
}

pub struct RpcGap(bool);
impl Default for RpcGap {
    fn default() -> Self {
        let active = w1_enabled();
        if active && let Some(last) = LAST_RPC.get() {
            duration("between_rpc", last.elapsed());
        }
        Self(active)
    }
}
impl Drop for RpcGap {
    fn drop(&mut self) {
        if self.0 {
            LAST_RPC.set(Some(Instant::now()));
        }
    }
}

pub fn process_entry() {
    if !w1_enabled() {
        return;
    }
    if let Some(started) = std::env::var("PMW1_SPAWN_US")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
    {
        if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            && let Some(us) = now.as_micros().checked_sub(started)
        {
            emit("spawn_to_main", 1, us);
        } else {
            count("startup_clock_invalid", 1);
        }
    }
}

/// Delegate the original write and flush calls without adding any TLS I/O.
pub struct FirstWrite<'a, W> {
    pub writer: &'a mut W,
    pub first: bool,
}
impl<W: Write> Write for FirstWrite<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let span = self.first.then(|| Span::new("tls_handshake_first_write"));
        self.first = false;
        let result = self.writer.write(bytes);
        drop(span);
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
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
