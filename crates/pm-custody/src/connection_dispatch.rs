// SPDX-License-Identifier: AGPL-3.0-only

//! Native acceptors share this per-agent connection policy. Domain requests
//! remain serialized by each connection and by the existing vault transactions.

use std::thread::{Builder, JoinHandle};

use crate::Failure;

pub(crate) const MAX_AGENT_CONNECTIONS: usize = 4;

pub(crate) struct AgentConnections {
    workers: Vec<JoinHandle<()>>,
    capacity: usize,
}

impl AgentConnections {
    pub(crate) fn new() -> Self {
        Self {
            workers: Vec::with_capacity(MAX_AGENT_CONNECTIONS),
            capacity: MAX_AGENT_CONNECTIONS,
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
        if self.workers.len() == self.capacity {
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

// Native identity is known before TLS; it bounds incomplete handshakes without
// mistaking a UID shared by multiple installed RPKs for one agent. The second
// permit is acquired only for the authenticated TLS RPK, never a client label.
#[cfg(unix)]
mod registered {
    use super::{AgentConnections, Failure, MAX_AGENT_CONNECTIONS};
    use std::{
        collections::BTreeMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    struct Budget {
        active: AtomicUsize,
        maximum: usize,
    }

    impl Budget {
        fn new(maximum: usize) -> Arc<Self> {
            Arc::new(Self {
                active: AtomicUsize::new(0),
                maximum,
            })
        }
        fn reserve(self: &Arc<Self>) -> Option<Permit> {
            self.active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                    (active < self.maximum).then(|| active + 1)
                })
                .ok()?;
            Some(Permit(Arc::clone(self)))
        }
    }

    pub(crate) struct Permit(Arc<Budget>);
    impl Drop for Permit {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub(crate) struct AuthenticatedAgents {
        peers: BTreeMap<Vec<u8>, Arc<Budget>>,
    }
    impl AuthenticatedAgents {
        pub(crate) fn admit(&self, authenticated_rpk: &[u8]) -> Option<Permit> {
            self.peers.get(authenticated_rpk)?.reserve()
        }
    }

    pub(crate) struct RegisteredConnections {
        workers: AgentConnections,
        native: BTreeMap<u32, Arc<Budget>>,
        authenticated: Arc<AuthenticatedAgents>,
    }
    impl RegisteredConnections {
        // Callers supply only the already validated installed registry (16 KiB
        // serialized) or the explicit single-pair transport lab. No live peer
        // adds a key, principal, map entry, queue or worker budget.
        pub(crate) fn new(bindings: &[(Vec<u8>, u32)]) -> Result<Self, Failure> {
            let capacity = bindings
                .len()
                .checked_mul(MAX_AGENT_CONNECTIONS)
                .ok_or(Failure::Unavailable)?;
            let mut counts = BTreeMap::<u32, usize>::new();
            let mut peers = BTreeMap::new();
            for (rpk, uid) in bindings {
                if peers
                    .insert(rpk.clone(), Budget::new(MAX_AGENT_CONNECTIONS))
                    .is_some()
                {
                    return Err(Failure::Unavailable);
                }
                let count = counts.entry(*uid).or_default();
                *count = count
                    .checked_add(MAX_AGENT_CONNECTIONS)
                    .ok_or(Failure::Unavailable)?;
            }
            let native = counts
                .into_iter()
                .map(|(uid, count)| (uid, Budget::new(count)))
                .collect();
            let mut workers = AgentConnections::new();
            workers.capacity = capacity;
            Ok(Self {
                workers,
                native,
                authenticated: Arc::new(AuthenticatedAgents { peers }),
            })
        }
        pub(crate) fn reap(&mut self) -> Result<(), Failure> {
            self.workers.reap()
        }
        pub(crate) fn dispatch(
            &mut self,
            observed_uid: u32,
            handler: impl FnOnce(Arc<AuthenticatedAgents>) + Send + 'static,
        ) -> Result<bool, Failure> {
            let Some(permit) = self.native.get(&observed_uid).and_then(Budget::reserve) else {
                return Ok(false);
            };
            let authenticated = Arc::clone(&self.authenticated);
            self.workers.dispatch(move || {
                let _native = permit;
                handler(authenticated);
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn shared_native_principal_has_separate_authenticated_rpk_budgets() {
            let pool = RegisteredConnections::new(&[(vec![1], 3), (vec![2], 3)]).unwrap();
            assert_eq!(pool.workers.capacity, 8);
            let a = (0..4)
                .map(|_| pool.authenticated.admit(&[1]).unwrap())
                .collect::<Vec<_>>();
            assert!(pool.authenticated.admit(&[1]).is_none());
            assert!(pool.authenticated.admit(&[2]).is_some());
            assert!(pool.authenticated.admit(&[9]).is_none());
            drop(a);
            assert!(pool.authenticated.admit(&[1]).is_some());
            assert!(RegisteredConnections::new(&[(vec![1], 3), (vec![1], 4)]).is_err());
        }
        #[test]
        fn panic_releases_both_budgets_and_keeps_orchestration_fatal() {
            let mut pool = RegisteredConnections::new(&[(vec![1], 3)]).unwrap();
            assert!(
                pool.dispatch(3, |peers| {
                    let _identity = peers.admit(&[1]).unwrap();
                    panic!("synthetic registered handler panic");
                })
                .unwrap()
            );
            while !pool.workers.workers[0].is_finished() {
                std::thread::yield_now();
            }
            assert!(pool.reap().is_err());
            assert_eq!(pool.native[&3].active.load(Ordering::Acquire), 0);
            assert_eq!(
                pool.authenticated.peers[&vec![1]]
                    .active
                    .load(Ordering::Acquire),
                0
            );
        }
        #[test]
        fn native_pre_admission_is_bounded_and_drained_without_learning_peers() {
            let mut pool = RegisteredConnections::new(&[(vec![1], 3), (vec![2], 4)]).unwrap();
            let (release, wait) = std::sync::mpsc::channel::<()>();
            assert!(
                !pool
                    .dispatch(99, |_| panic!("unknown native peer ran"))
                    .unwrap()
            );
            assert!(
                pool.dispatch(3, move |peers| {
                    let _identity = peers.admit(&[1]).unwrap();
                    wait.recv().unwrap();
                })
                .unwrap()
            );
            release.send(()).unwrap();
            for worker in pool.workers.workers.drain(..) {
                worker.join().unwrap();
            }
            assert_eq!(pool.native[&3].active.load(Ordering::Acquire), 0);
            assert_eq!(
                pool.authenticated.peers[&vec![1]]
                    .active
                    .load(Ordering::Acquire),
                0
            );
        }
    }
}
#[cfg(unix)]
pub(crate) use registered::{
    AuthenticatedAgents, Permit as AuthenticatedPermit, RegisteredConnections,
};

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
