// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded IPC for the shared session engine using synchronous Windows stdio.
//!
//! One worker owns both pipes. The parent enforces an absolute RPC deadline;
//! abort kills/reaps the owned child before joining, releasing blocked I/O.
use super::*;
use std::sync::mpsc::{self, Receiver, Sender};

pub(super) struct PipeIo {
    requests: Option<Sender<Vec<u8>>>,
    responses: Receiver<Result<String, SyncError>>,
    worker: Option<thread::JoinHandle<Result<(), SyncError>>>,
}

impl PipeIo {
    pub(super) fn spawn(mut input: ChildStdin, mut output: ChildStdout) -> Result<Self, SyncError> {
        let (requests, incoming) = mpsc::channel::<Vec<u8>>();
        let (outgoing, responses) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("pm-sync-windows-stdio".to_owned())
            .spawn(move || {
                while let Ok(frame) = incoming.recv() {
                    let response = input
                        .write_all(&frame)
                        .map_err(|_| SyncError::Unavailable)
                        .and_then(|()| read_response(&mut output));
                    let failed = response.is_err();
                    outgoing
                        .send(response)
                        .map_err(|_| SyncError::Unavailable)?;
                    if failed {
                        break;
                    }
                }
                Ok(())
            })
            .map_err(|_| SyncError::Unavailable)?;
        Ok(Self {
            requests: Some(requests),
            responses,
            worker: Some(worker),
        })
    }

    pub(super) fn exchange(&self, frame: Vec<u8>, deadline: Instant) -> Result<String, SyncError> {
        if Instant::now() >= deadline {
            return Err(SyncError::Unavailable);
        }
        self.requests
            .as_ref()
            .ok_or(SyncError::Unavailable)?
            .send(frame)
            .map_err(|_| SyncError::Unavailable)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(SyncError::Unavailable)?;
        let response = self
            .responses
            .recv_timeout(remaining)
            .map_err(|_| SyncError::Unavailable)?;
        // Never accept a reply which completed after the request deadline.
        if Instant::now() >= deadline {
            return Err(SyncError::Unavailable);
        }
        response
    }

    pub(super) fn shutdown(&mut self) {
        drop(self.requests.take());
    }

    pub(super) fn join(&mut self) -> Result<(), SyncError> {
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| SyncError::Unavailable)??;
        }
        Ok(())
    }
}

fn read_response(output: &mut impl Read) -> Result<String, SyncError> {
    let mut length = [0; 4];
    output
        .read_exact(&mut length)
        .map_err(|_| SyncError::Unavailable)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(SyncError::Integrity);
    }
    let mut response = vec![0; length];
    output
        .read_exact(&mut response)
        .map_err(|_| SyncError::Unavailable)?;
    String::from_utf8(response).map_err(|_| SyncError::Integrity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_ipc_frames_fail_before_unbounded_allocation() {
        assert!(matches!(
            read_response(&mut std::io::Cursor::new([1, 0, 0, 0])),
            Err(SyncError::Integrity)
        ));
        assert!(matches!(
            read_response(&mut std::io::Cursor::new([0, 0])),
            Err(SyncError::Unavailable)
        ));
        assert!(matches!(
            read_response(&mut std::io::Cursor::new([0, 0, 0, 1, 0xff])),
            Err(SyncError::Integrity)
        ));
    }

    #[test]
    fn elapsed_deadline_does_not_send_to_an_owned_child() {
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit", "0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut io =
            PipeIo::spawn(child.stdin.take().unwrap(), child.stdout.take().unwrap()).unwrap();
        assert!(matches!(
            io.exchange(vec![0; 4], Instant::now()),
            Err(SyncError::Unavailable)
        ));
        io.shutdown();
        assert!(child.wait().unwrap().success());
        io.join().unwrap();
    }
}
