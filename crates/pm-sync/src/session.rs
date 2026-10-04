// SPDX-License-Identifier: AGPL-3.0-only
//! One bounded ciphertext RPC at a time over an owned TLS client process.
use std::{
    io::{Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
mod windows_io;

use crate::{SyncError, timing};

const MAX_FRAME: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct Session {
    child: Child,
    #[cfg(unix)]
    input: Option<ChildStdin>,
    #[cfg(unix)]
    output: ChildStdout,
    #[cfg(windows)]
    io: windows_io::PipeIo,
}

impl Session {
    pub(super) fn spawn(command: &mut Command) -> Result<Self, SyncError> {
        #[cfg(windows)]
        if timing::w1_enabled() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SyncError::Unavailable)?;
            command.env("PMW1_SPAWN_US", now.as_micros().to_string());
        }
        #[cfg(unix)]
        let _spawn = timing::Span::new("process_spawn");
        #[cfg(windows)]
        let spawning = timing::Span::new("process_spawn");
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| SyncError::Unavailable)?;
        #[cfg(windows)]
        drop(spawning);
        #[cfg(windows)]
        timing::count("process_started", 1);
        let input = child.stdin.take().expect("piped session input");
        let output = child.stdout.take().expect("piped session output");
        #[cfg(windows)]
        let io = match windows_io::PipeIo::spawn(input, output) {
            Ok(io) => io,
            Err(error) => {
                child.kill().map_err(|_| SyncError::Unavailable)?;
                child.wait().map_err(|_| SyncError::Unavailable)?;
                return Err(error);
            }
        };
        #[allow(unused_mut)]
        let mut session = Self {
            child,
            #[cfg(unix)]
            input: Some(input),
            #[cfg(unix)]
            output,
            #[cfg(windows)]
            io,
        };
        #[cfg(unix)]
        let configured = nonblocking(session.input.as_ref().unwrap())
            .and_then(|()| nonblocking(&session.output));
        #[cfg(unix)]
        if configured.is_err() {
            session.abort()?;
            return Err(SyncError::Unavailable);
        }
        Ok(session)
    }

    pub(super) fn exchange(&mut self, request: &[u8]) -> Result<String, SyncError> {
        if request.len() > MAX_FRAME {
            return Err(SyncError::Backpressure);
        }
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut frame = Vec::with_capacity(request.len() + 4);
        frame.extend_from_slice(
            &u32::try_from(request.len())
                .map_err(|_| SyncError::Backpressure)?
                .to_be_bytes(),
        );
        frame.extend_from_slice(request);
        #[cfg(windows)]
        {
            self.io.exchange(frame, deadline)
        }
        #[cfg(unix)]
        {
            let input = self.input.as_mut().ok_or(SyncError::Unavailable)?;
            let mut remaining = frame.as_slice();
            while !remaining.is_empty() {
                ready(input, libc::POLLOUT, deadline)?;
                match input.write(remaining) {
                    Ok(0) => return Err(SyncError::Unavailable),
                    Ok(n) => remaining = &remaining[n..],
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(SyncError::Unavailable),
                }
            }
            let mut length = [0; 4];
            read_exact(&mut self.output, &mut length, deadline)?;
            let length = u32::from_be_bytes(length) as usize;
            if length > MAX_FRAME {
                return Err(SyncError::Integrity);
            }
            let mut response = vec![0; length];
            read_exact(&mut self.output, &mut response, deadline)?;
            String::from_utf8(response).map_err(|_| SyncError::Integrity)
        }
    }

    pub(super) fn abort(&mut self) -> Result<(), SyncError> {
        #[cfg(unix)]
        drop(self.input.take());
        #[cfg(windows)]
        self.io.shutdown();
        if self
            .child
            .try_wait()
            .map_err(|_| SyncError::Unavailable)?
            .is_none()
        {
            self.child.kill().map_err(|_| SyncError::Unavailable)?;
        }
        self.child.wait().map_err(|_| SyncError::Unavailable)?;
        #[cfg(windows)]
        self.io.join()?;
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<(), SyncError> {
        #[cfg(unix)]
        drop(self.input.take());
        #[cfg(windows)]
        self.io.shutdown();
        let _close = timing::Span::new("process_close");
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|_| SyncError::Unavailable)? {
                #[cfg(windows)]
                self.io.join()?;
                #[cfg(windows)]
                timing::count(
                    if status.success() {
                        "process_exit_success"
                    } else {
                        "process_exit_unavailable"
                    },
                    1,
                );
                return status.success().then_some(()).ok_or(SyncError::Unavailable);
            }
            if Instant::now() >= deadline {
                self.abort()?;
                return Err(SyncError::Unavailable);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Drop cannot return an error. Explicit finish is used before job success;
        // abandoned/error sessions still report an unsuccessful owned cleanup.
        if self.abort().is_err() {
            eprintln!("SYNC_SESSION_CLEANUP_FAILED");
        }
    }
}

#[cfg(unix)]
fn nonblocking(file: &impl AsRawFd) -> Result<(), SyncError> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(SyncError::Unavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn ready(file: &impl AsRawFd, events: libc::c_short, deadline: Instant) -> Result<(), SyncError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(SyncError::Unavailable)?;
        let milliseconds = libc::c_int::try_from(remaining.as_millis().max(1))
            .map_err(|_| SyncError::Unavailable)?;
        let mut fd = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&raw mut fd, 1, milliseconds) };
        if result > 0 && fd.revents & events != 0 {
            return Ok(());
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(SyncError::Unavailable);
    }
}

#[cfg(unix)]
fn read_exact(
    file: &mut (impl Read + AsRawFd),
    mut output: &mut [u8],
    deadline: Instant,
) -> Result<(), SyncError> {
    while !output.is_empty() {
        ready(file, libc::POLLIN, deadline)?;
        match file.read(output) {
            Ok(0) => return Err(SyncError::Unavailable),
            Ok(n) => output = &mut output[n..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(SyncError::Unavailable),
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn malformed_local_response_frames_fail_without_unbounded_allocation() {
        for (script, integrity) in [
            ("IFS= read -r line; printf '\\001\\000\\000\\000'", true),
            ("IFS= read -r line; printf '\\000\\000'", false),
        ] {
            let mut session =
                Session::spawn(Command::new("/bin/sh").arg("-c").arg(script)).unwrap();
            let response = session.exchange(b"\n");
            if integrity {
                assert!(matches!(response, Err(SyncError::Integrity)));
            } else {
                assert!(matches!(response, Err(SyncError::Unavailable)));
            }
            session.abort().unwrap();
        }
    }

    #[test]
    fn elapsed_deadline_does_not_wait_for_an_idle_client() {
        let mut session =
            Session::spawn(Command::new("/bin/sh").arg("-c").arg("IFS= read -r line")).unwrap();
        assert!(matches!(
            ready(&session.output, libc::POLLIN, Instant::now()),
            Err(SyncError::Unavailable)
        ));
        session.abort().unwrap();
    }
}
