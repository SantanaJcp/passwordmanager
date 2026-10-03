// SPDX-License-Identifier: AGPL-3.0-only

//! Native acceptors share this per-agent connection policy. Domain requests
//! remain serialized by each connection and by the existing vault transactions.

use std::thread::{Builder, JoinHandle};

use crate::Failure;

pub(crate) const MAX_AGENT_CONNECTIONS: usize = 4;

pub(crate) struct AgentConnections {
    workers: Vec<JoinHandle<()>>,
}

impl AgentConnections {
    pub(crate) fn new() -> Self {
        Self {
            workers: Vec::with_capacity(MAX_AGENT_CONNECTIONS),
        }
    }

    pub(crate) fn reap(&mut self) -> Result<(), Failure> {
        let mut index = 0;
        while index < self.workers.len() {
            if self.workers[index].is_finished() {
                self.workers
                    .swap_remove(index)
                    .join()
                    .map_err(|_| Failure::Unavailable)?;
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    /// False drops the unstarted connection: no unbounded task queue, eviction
    /// of existing clients, or substitute execution path when the limit is full.
    pub(crate) fn dispatch(
        &mut self,
        handler: impl FnOnce() + Send + 'static,
    ) -> Result<bool, Failure> {
        self.reap()?;
        if self.workers.len() == MAX_AGENT_CONNECTIONS {
            return Ok(false);
        }
        let worker = Builder::new()
            .name("pm-agent-connection".to_owned())
            .spawn(handler)
            .map_err(|_| Failure::Unavailable)?;
        self.workers.push(worker);
        Ok(true)
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn finish(self) -> Result<(), Failure> {
        let mut failed = false;
        for worker in self.workers {
            failed |= worker.join().is_err();
        }
        if failed {
            Err(Failure::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn full_connections_reject_without_running_or_displacing_clients() {
        let mut connections = AgentConnections::new();
        let (started, observed) = mpsc::channel();
        let mut releases = Vec::new();
        for _ in 0..MAX_AGENT_CONNECTIONS {
            let (release, wait) = mpsc::channel();
            releases.push(release);
            let started = started.clone();
            assert!(
                connections
                    .dispatch(move || {
                        started.send(()).unwrap();
                        wait.recv().unwrap();
                    })
                    .unwrap()
            );
        }
        for _ in 0..MAX_AGENT_CONNECTIONS {
            observed
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
        assert!(
            !connections
                .dispatch(|| panic!("rejected work must not run"))
                .unwrap()
        );
        for release in releases {
            release.send(()).unwrap();
        }
        for worker in connections.workers.drain(..) {
            worker.join().unwrap();
        }
        assert!(connections.dispatch(|| {}).unwrap());
        connections.workers.pop().unwrap().join().unwrap();
    }

    #[test]
    fn a_panicked_worker_is_a_fatal_orchestration_error() {
        let mut connections = AgentConnections::new();
        connections
            .workers
            .push(std::thread::spawn(|| panic!("synthetic worker panic")));
        while !connections.workers[0].is_finished() {
            std::thread::yield_now();
        }
        assert!(connections.reap().is_err());
    }
}
