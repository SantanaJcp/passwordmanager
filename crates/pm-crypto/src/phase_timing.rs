// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in categorical timing for synthetic native W6 diagnostics.
//! No payload, identifier, password length, salt or path is recorded.

use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A phase clock enabled only on macOS with `PMW6_TIMING=1`.
/// Labels must be fixed categories, never values derived from an input.
pub struct PhaseTimer {
    log: Option<File>,
    operation: &'static str,
    clocks: Option<(Instant, Instant)>,
}

impl PhaseTimer {
    /// Starts a diagnostic without changing the operation being measured.
    ///
    /// # Panics
    /// In opt-in diagnostics, a missing/unwritable private log or invalid wall
    /// clock is a fatal diagnostic prerequisite failure.
    #[must_use]
    pub fn new(operation: &'static str) -> Self {
        let now = Instant::now();
        let enabled = cfg!(target_os = "macos")
            && std::env::var_os("PMW6_TIMING").as_deref() == Some(std::ffi::OsStr::new("1"));
        let log = enabled.then(|| {
            let path = std::env::var_os("PMW6_TIMING_FILE")
                .expect("native diagnostic requires its owned private log");
            let mut options = OpenOptions::new();
            options.append(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_NOFOLLOW);
            options
                .open(path)
                .expect("native diagnostic log must exist and be writable")
        });
        let mut timer = Self {
            log,
            operation,
            clocks: enabled.then_some((now, now)),
        };
        timer.phase("start");
        timer
    }

    /// Records only a fixed phase and elapsed microseconds.
    ///
    /// # Panics
    /// Fails explicitly when the opt-in diagnostic clock or private log fails.
    pub fn phase(&mut self, phase: &'static str) {
        if let Some((started, previous)) = self.clocks.as_mut() {
            let now = Instant::now();
            let at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("native diagnostic requires a post-epoch clock")
                .as_micros();
            writeln!(
                self.log.as_mut().expect("enabled diagnostic owns a log"),
                "PMW6_PHASE operation={} phase={} elapsed_us={} total_us={} at_us={}",
                self.operation,
                phase,
                now.duration_since(*previous).as_micros(),
                now.duration_since(*started).as_micros(),
                at
            )
            .expect("native diagnostic phase write failed");
            *previous = now;
        }
    }

    /// Reports the validated effective Argon2id profile, never salt or input.
    ///
    /// # Panics
    /// Fails explicitly if the opt-in private diagnostic log cannot be written.
    pub fn kdf_profile(&mut self, memory_mib: u64, passes: u64) {
        if self.clocks.is_some() {
            writeln!(self.log.as_mut().expect("enabled diagnostic owns a log"),
                "PMW6_KDF algorithm=argon2id13 memory_mib={memory_mib} passes={passes} parallelism=1 output_bytes=32"
            ).expect("native diagnostic profile write failed");
        }
    }

    /// Marks successful completion. Early return instead emits `aborted`.
    ///
    /// # Panics
    /// Fails explicitly if the opt-in diagnostic clock or private log fails.
    pub fn finish(mut self) {
        self.phase("complete");
        self.clocks = None;
    }
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        self.phase("aborted");
    }
}
