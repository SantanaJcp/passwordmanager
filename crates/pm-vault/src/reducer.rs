// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic reduction of the repository's one signed G5 event DAG.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt, fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use minicbor::{Decoder, Encoder, data::Type};
use pm_crypto::{
    AuditKeyPackage, TrustedRoot, UnlockedRoot, digest, verify_audit_key_package,
    verify_device_event, verify_human_event,
};
use rusqlite::{OptionalExtension, params};

use crate::{
    HumanCommitError, VaultError,
    audit::AuditDeviceCustody,
    authorization::{G5EventInput, encode_g5_event},
};

/// Authenticated ciphertext graph staged by sync before atomic activation.
pub struct ReceivedCiphertextGraph {
    pub item: [u8; 16],
    pub revision: [u8; 16],
    pub kind: String,
    pub package: PathBuf,
    pub attachments: Vec<ReceivedCiphertextAttachment>,
    pub streams: Vec<ReceivedCiphertextStream>,
}
pub struct ReceivedCiphertextAttachment {
    pub id: [u8; 16],
    pub package: PathBuf,
}
pub struct ReceivedCiphertextStream {
    pub id: [u8; 16],
    pub header: Vec<u8>,
    pub chunks: Vec<PathBuf>,
}

/// One device-generation prefix accepted by a human device retirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedPrefix {
    pub generation: u64,
    pub seq: u64,
    pub tip_digest: [u8; 32],
}

/// Human-confirmed logical purge scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurgeScopeKind {
    Item,
    Revisions,
}

/// Closed G5 event kinds implemented by the v1 reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalEventKind {
    ItemRevision,
    AgentGrant,
    AgentRevoke,
    Enable,
    Disable,
    Suspend,
    Resume,
    DeviceRetire,
    Trash,
    Restore,
    PurgeItem,
    PurgeRevisions,
    Join,
    CheckpointCache,
    AuditPurge,
}

impl CausalEventKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ItemRevision => "item-revision",
            Self::AgentGrant => "agent-grant",
            Self::AgentRevoke => "agent-revoke",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Suspend => "suspend",
            Self::Resume => "resume",
            Self::DeviceRetire => "device-retire",
            Self::Trash => "trash",
            Self::Restore => "restore",
            Self::PurgeItem => "purge-item",
            Self::PurgeRevisions => "purge-revisions",
            Self::Join => "join",
            Self::CheckpointCache => "checkpoint-cache",
            Self::AuditPurge => "audit-purge",
        }
    }

    const fn technical(self) -> bool {
        matches!(self, Self::Join | Self::CheckpointCache)
    }
}

/// Exact kind-specific data used by deterministic reduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CausalEventBody {
    Revision {
        revision_id: [u8; 16],
        modified_at: i64,
        manifest_digest: [u8; 32],
        previous_revisions: Vec<[u8; 16]>,
    },
    Reason,
    Positive {
        prior_positive_events: Vec<[u8; 32]>,
        withdrawals_seen: Vec<[u8; 32]>,
    },
    Retire {
        accepted_prefixes: Vec<AcceptedPrefix>,
    },
    Lifecycle {
        deletions_seen: Vec<[u8; 32]>,
    },
    Purge {
        revision_ids: Vec<[u8; 16]>,
    },
    PurgeScoped {
        item_id: [u8; 16],
        revision_ids: Vec<[u8; 16]>,
        scope: PurgeScopeKind,
    },
    Join,
    Checkpoint {
        covered_heads: Vec<[u8; 32]>,
        state_digest: [u8; 32],
        index_parts: Vec<[u8; 32]>,
    },
}

/// Human-reviewed event data before vault/device signatures are attached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalEventDraft {
    pub(crate) event_id: [u8; 16],
    pub(crate) issuer_generation: u64,
    pub(crate) seq: u64,
    pub(crate) previous: Option<[u8; 32]>,
    pub(crate) parents: Vec<[u8; 32]>,
    pub(crate) kind: CausalEventKind,
    pub(crate) subject: [u8; 16],
    pub(crate) subject_generation: u64,
    pub(crate) body: CausalEventBody,
}

impl CausalEventDraft {
    /// Creates a canonical draft; parents and body references must already be sorted.
    ///
    /// # Errors
    /// Rejects zero counters, duplicate/unsorted references and kind/body mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: [u8; 16],
        issuer_generation: u64,
        seq: u64,
        previous: Option<[u8; 32]>,
        parents: Vec<[u8; 32]>,
        kind: CausalEventKind,
        subject: [u8; 16],
        subject_generation: u64,
        body: CausalEventBody,
    ) -> Result<Self, ReductionError> {
        let valid_body = matches!(
            (kind, &body),
            (
                CausalEventKind::ItemRevision,
                CausalEventBody::Revision { .. }
            ) | (
                CausalEventKind::AgentGrant | CausalEventKind::Enable | CausalEventKind::Resume,
                CausalEventBody::Positive { .. }
            ) | (
                CausalEventKind::AgentRevoke | CausalEventKind::Disable | CausalEventKind::Suspend,
                CausalEventBody::Reason
            ) | (
                CausalEventKind::DeviceRetire,
                CausalEventBody::Retire { .. }
            ) | (
                CausalEventKind::Trash | CausalEventKind::Restore,
                CausalEventBody::Lifecycle { .. }
            ) | (
                CausalEventKind::PurgeItem | CausalEventKind::PurgeRevisions,
                CausalEventBody::Purge { .. }
            ) | (
                CausalEventKind::PurgeItem,
                CausalEventBody::PurgeScoped {
                    scope: PurgeScopeKind::Item,
                    ..
                }
            ) | (
                CausalEventKind::PurgeRevisions,
                CausalEventBody::PurgeScoped {
                    scope: PurgeScopeKind::Revisions,
                    ..
                }
            ) | (CausalEventKind::Join, CausalEventBody::Join)
                | (
                    CausalEventKind::CheckpointCache,
                    CausalEventBody::Checkpoint { .. }
                )
        );
        let sorted_body_references = match &body {
            CausalEventBody::Revision {
                previous_revisions, ..
            }
            | CausalEventBody::Purge {
                revision_ids: previous_revisions,
            }
            | CausalEventBody::PurgeScoped {
                revision_ids: previous_revisions,
                ..
            } => strictly_sorted(previous_revisions),
            CausalEventBody::Positive {
                prior_positive_events,
                withdrawals_seen,
            } => strictly_sorted(prior_positive_events) && strictly_sorted(withdrawals_seen),
            CausalEventBody::Retire { accepted_prefixes } => {
                accepted_prefixes
                    .windows(2)
                    .all(|pair| pair[0].generation < pair[1].generation)
                    && accepted_prefixes
                        .iter()
                        .all(|prefix| prefix.generation > 0 && prefix.seq > 0)
            }
            CausalEventBody::Lifecycle { deletions_seen } => strictly_sorted(deletions_seen),
            CausalEventBody::Checkpoint {
                covered_heads,
                index_parts,
                ..
            } => strictly_sorted(covered_heads) && strictly_sorted(index_parts),
            CausalEventBody::Reason | CausalEventBody::Join => true,
        };
        if event_id == [0; 16]
            || issuer_generation == 0
            || seq == 0
            || subject_generation == 0
            || parents.len() > 4096
            || !strictly_sorted(&parents)
            || previous.is_some_and(|value| !parents.contains(&value))
            || (seq == 1) != previous.is_none()
            || !valid_body
            || !sorted_body_references
        {
            return Err(ReductionError::InvalidEvent);
        }
        Ok(Self {
            event_id,
            issuer_generation,
            seq,
            previous,
            parents,
            kind,
            subject,
            subject_generation,
            body,
        })
    }
}

/// Canonical G5 event plus device provenance and optional human authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCausalEvent {
    pub(crate) event: Vec<u8>,
    pub(crate) device_signature: [u8; 64],
    pub(crate) human_signature: Option<[u8; 64]>,
}

impl SignedCausalEvent {
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        digest(&self.event)
    }

    /// Encodes this signed event for a bounded transport.
    ///
    /// # Panics
    /// Encoding into an in-memory `Vec` is infallible.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(&self.event)
            .unwrap()
            .bytes(&self.device_signature)
            .unwrap();
        match self.human_signature {
            Some(value) => {
                e.bytes(&value).unwrap();
            }
            None => {
                e.null().unwrap();
            }
        }
        e.into_writer()
    }

    /// Decodes a canonical, bounded transport envelope. Signatures are checked
    /// only by [`CausalReducer::apply`], at the publication boundary.
    ///
    /// # Errors
    /// Rejects oversized, malformed, trailing, or non-canonical envelopes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReductionError> {
        if bytes.len() > 263_000 {
            return Err(ReductionError::ResourceLimit);
        }
        let mut d = Decoder::new(bytes);
        if d.array().map_err(|_| ReductionError::InvalidEvent)? != Some(3) {
            return Err(ReductionError::InvalidEvent);
        }
        let event = d
            .bytes()
            .map_err(|_| ReductionError::InvalidEvent)?
            .to_vec();
        let device_signature = decode_fixed(&mut d)?;
        let human_signature = decode_optional_fixed(&mut d)?;
        let value = Self {
            event,
            device_signature,
            human_signature,
        };
        if d.position() != bytes.len() || value.to_bytes() != bytes {
            return Err(ReductionError::InvalidEvent);
        }
        Ok(value)
    }
}

pub(crate) fn sign_draft(
    vault: &[u8; 16],
    device: [u8; 16],
    root: &UnlockedRoot,
    custody: &AuditDeviceCustody,
    draft: &CausalEventDraft,
) -> Result<SignedCausalEvent, ReductionError> {
    let body = encode_body(&draft.body);
    let event = encode_g5_event(&G5EventInput {
        vault,
        event_id: draft.event_id,
        authority_epoch: 1,
        issuer_device: device,
        issuer_generation: draft.issuer_generation,
        seq: draft.seq,
        previous: draft.previous,
        parents: &draft.parents,
        kind: draft.kind.name(),
        subject: draft.subject,
        subject_generation: draft.subject_generation,
        body: &body,
    });
    if event.len() > 256 * 1024 {
        return Err(ReductionError::InvalidEvent);
    }
    let human_signature = if draft.kind.technical() {
        None
    } else {
        Some(
            root.sign_human_event(&event)
                .map_err(HumanCommitError::from)?,
        )
    };
    let device_signature = custody.sign_device_event(&event)?;
    Ok(SignedCausalEvent {
        event,
        device_signature,
        human_signature,
    })
}

/// Item lifecycle after reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemLifecycle {
    Active,
    Trash,
    Purged,
}

/// Reduced item winner and recoverable losing revision IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReducedItem {
    lifecycle: ItemLifecycle,
    visible_revision: Option<[u8; 16]>,
    history: Vec<[u8; 16]>,
}

impl ReducedItem {
    #[must_use]
    pub const fn lifecycle(&self) -> ItemLifecycle {
        self.lifecycle
    }
    #[must_use]
    pub const fn visible_revision(&self) -> Option<&[u8; 16]> {
        self.visible_revision.as_ref()
    }
    #[must_use]
    pub fn history(&self) -> &[[u8; 16]] {
        &self.history
    }
}

/// Deterministic state exposed to authorization and human lifecycle callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReducedView {
    digest: [u8; 32],
    items: BTreeMap<[u8; 16], ReducedItem>,
    pending: usize,
    headers: usize,
    active: BTreeSet<[u8; 32]>,
    forks: usize,
    agents: BTreeSet<([u8; 16], u64)>,
    enabled_items: BTreeSet<([u8; 16], u64)>,
    delegated_resumed: bool,
    retired_devices: BTreeSet<[u8; 16]>,
}

impl ReducedView {
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub fn item(&self, id: &[u8; 16]) -> Option<&ReducedItem> {
        self.items.get(id)
    }
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.pending
    }
    #[must_use]
    pub const fn retained_header_count(&self) -> usize {
        self.headers
    }
    #[must_use]
    pub fn event_active(&self, digest: &[u8; 32]) -> bool {
        self.active.contains(digest)
    }
    #[must_use]
    pub const fn unresolved_fork_count(&self) -> usize {
        self.forks
    }
    #[must_use]
    pub fn agent_authorized(&self, subject: &[u8; 16], generation: u64) -> bool {
        self.agents.contains(&(*subject, generation))
    }
    #[must_use]
    pub fn item_enabled(&self, subject: &[u8; 16], generation: u64) -> bool {
        self.enabled_items.contains(&(*subject, generation))
    }
    #[must_use]
    pub const fn delegated_resumed(&self) -> bool {
        self.delegated_resumed
    }
    #[must_use]
    pub fn device_retired(&self, device: &[u8; 16]) -> bool {
        self.retired_devices.contains(device)
    }
}

/// Persistent verifier/reducer over the single `authority_events` DAG.
pub struct CausalReducer {
    path: PathBuf,
    trusted: TrustedRoot,
}

impl CausalReducer {
    /// Opens the vault's existing signed event store.
    ///
    /// # Errors
    /// Returns an error for invalid vault metadata or storage.
    pub fn open(path: &Path) -> Result<Self, ReductionError> {
        let connection = rusqlite::Connection::open(path)?;
        let (_, trusted) = crate::load_and_validate_bundle(&connection)?;
        Ok(Self {
            path: path.to_owned(),
            trusted,
        })
    }

    /// Verifies and idempotently adds signed events, then reduces the complete set.
    ///
    /// # Errors
    /// Returns an error without partial insertion when an event is invalid.
    pub fn apply(&mut self, events: &[SignedCausalEvent]) -> Result<ReducedView, ReductionError> {
        self.apply_internal(events, true)
    }

    /// Applies remotely received events without echoing them into the local outbox.
    ///
    /// # Errors
    /// Returns an error without partial insertion when an event is invalid.
    pub fn apply_received(
        &mut self,
        events: &[SignedCausalEvent],
    ) -> Result<ReducedView, ReductionError> {
        self.apply_internal(events, false)
    }

    /// Validates complete staged ciphertext graphs and publishes them with their
    /// signed events in one SQLite transaction.
    ///
    /// # Errors
    /// Rejects missing, altered, oversized, or event-unbound graph parts atomically.
    pub fn apply_received_package(
        &mut self,
        events: &[SignedCausalEvent],
        graphs: &[ReceivedCiphertextGraph],
    ) -> Result<ReducedView, ReductionError> {
        if events.len() > 256 || graphs.len() > 256 {
            return Err(ReductionError::ResourceLimit);
        }
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction()?;
        for event in events {
            let parsed = decode_event(&event.event)?;
            if parsed.bound_graph {
                let CausalEventBody::Revision {
                    revision_id: revision,
                    ..
                } = parsed.body
                else {
                    return Err(ReductionError::Integrity);
                };
                if graphs
                    .iter()
                    .filter(|g| g.item == parsed.subject && g.revision == revision)
                    .count()
                    != 1
                {
                    return Err(ReductionError::Integrity);
                }
            }
        }
        for graph in graphs {
            insert_graph(&transaction, graph)?;
        }
        Self::insert_events(&transaction, &self.trusted, events, false)?;
        for graph in graphs {
            let expected = events
                .iter()
                .filter_map(|event| decode_event(&event.event).ok())
                .find_map(|parsed| match parsed.body {
                    CausalEventBody::Revision {
                        revision_id,
                        manifest_digest,
                        ..
                    } if parsed.subject == graph.item && revision_id == graph.revision => {
                        Some(manifest_digest)
                    }
                    _ => None,
                })
                .ok_or(ReductionError::Integrity)?;
            if graph_digest(graph)? != expected {
                return Err(ReductionError::Integrity);
            }
        }
        let view = view_connection(&transaction, &self.trusted)?;
        let items: BTreeSet<_> = graphs.iter().map(|g| g.item).collect();
        for item in items {
            let reduced = view.item(&item).ok_or(ReductionError::Integrity)?;
            let revision = *reduced
                .visible_revision()
                .ok_or(ReductionError::Integrity)?;
            let kind = graphs
                .iter()
                .find(|g| g.item == item && g.revision == revision)
                .map(|g| g.kind.as_str())
                .or_else(|| {
                    graphs
                        .iter()
                        .find(|g| g.item == item)
                        .map(|g| g.kind.as_str())
                })
                .ok_or(ReductionError::Integrity)?;
            let status = if reduced.lifecycle() == ItemLifecycle::Trash {
                "trash"
            } else {
                "active"
            };
            transaction.execute("INSERT INTO vault_items(item_id,visible_revision,kind,status)VALUES(?1,?2,?3,?4) ON CONFLICT(item_id) DO UPDATE SET visible_revision=excluded.visible_revision,kind=excluded.kind,status=excluded.status",params![item.as_slice(),revision.as_slice(),kind,status])?;
        }
        transaction.commit()?;
        self.view()
    }

    fn apply_internal(
        &mut self,
        events: &[SignedCausalEvent],
        enqueue: bool,
    ) -> Result<ReducedView, ReductionError> {
        if events.len() > 256 {
            return Err(ReductionError::ResourceLimit);
        }
        let mut connection = open_connection(&self.path)?;
        let transaction = connection.transaction()?;
        Self::insert_events(&transaction, &self.trusted, events, enqueue)?;
        transaction.commit()?;
        self.view()
    }

    fn insert_events(
        transaction: &rusqlite::Transaction<'_>,
        trusted: &TrustedRoot,
        events: &[SignedCausalEvent],
        enqueue: bool,
    ) -> Result<(), ReductionError> {
        for signed in events {
            let parsed = decode_event(&signed.event)?;
            verify_signed(transaction, trusted, signed, &parsed)?;
            let digest_value = digest(&signed.event);
            let conflicting: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT event_digest FROM authority_events WHERE event_id=?1",
                    [parsed.event_id.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if conflicting.as_deref().is_some_and(|v| v != digest_value) {
                return Err(ReductionError::Integrity);
            }
            transaction.execute(
                "INSERT OR IGNORE INTO authority_events
                 (event_digest,event_id,transaction_id,issuer_device,issuer_generation,seq,previous_digest,parents,kind,subject,subject_generation,event,human_signature,device_signature)
                 VALUES (?1,?2,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![digest_value.as_slice(), parsed.event_id.as_slice(), parsed.issuer_device.as_slice(), sql_i64(parsed.issuer_generation)?, sql_i64(parsed.seq)?, parsed.previous.as_ref().map(<[u8; 32]>::as_slice), encode_ids32_value(&parsed.parents), parsed.kind.name(), parsed.subject.as_slice(), sql_i64(parsed.subject_generation)?, signed.event, signed.human_signature.as_ref().map(<[u8; 64]>::as_slice), signed.device_signature.as_slice()],
            )?;
            if enqueue {
                transaction.execute(
                    "INSERT OR IGNORE INTO outbox(event_digest,event) VALUES(?1,?2)",
                    params![digest_value.as_slice(), signed.to_bytes()],
                )?;
            }
        }
        Ok(())
    }

    /// Returns at most one reducer batch from the durable local outbox.
    ///
    /// # Errors
    /// Returns an error if persisted signatures or bounded fields are corrupt.
    pub fn pending_outbox(&self) -> Result<Vec<SignedCausalEvent>, ReductionError> {
        let c = open_connection(&self.path)?;
        let mut s=c.prepare("SELECT a.event,a.device_signature,a.human_signature FROM outbox o JOIN authority_events a ON a.event_digest=o.event_digest ORDER BY a.event_digest LIMIT 256")?;
        let rows = s.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (event, device, human) = row?;
            out.push(SignedCausalEvent {
                event,
                device_signature: fixed(&device)?,
                human_signature: human.map(|v| fixed(&v)).transpose()?,
            });
        }
        Ok(out)
    }

    /// Exports the ciphertext graph cryptographically bound by one local revision event.
    ///
    /// # Errors
    /// Rejects non-revision, missing, corrupt, or digest-mismatched local state.
    pub fn export_ciphertext_graph(
        &self,
        event: &SignedCausalEvent,
        directory: &Path,
    ) -> Result<Option<ReceivedCiphertextGraph>, ReductionError> {
        let parsed = decode_event(&event.event)?;
        if !parsed.bound_graph {
            return Ok(None);
        }
        let CausalEventBody::Revision {
            revision_id: revision,
            manifest_digest: expected,
            ..
        } = parsed.body
        else {
            return Err(ReductionError::InvalidEvent);
        };
        fs::create_dir_all(directory).map_err(|_| ReductionError::Integrity)?;
        let c = open_connection(&self.path)?;
        let (kind,package):(String,Vec<u8>)=c.query_row("SELECT i.kind,r.package FROM revision_parts r JOIN vault_items i ON i.item_id=r.item_id WHERE r.item_id=?1 AND r.revision_id=?2",params![parsed.subject.as_slice(),revision.as_slice()],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let package_path = write_stage(directory, "revision", &package)?;
        let mut attachments = Vec::new();
        let mut statement=c.prepare("SELECT attachment_id,package FROM attachment_parts WHERE revision_id=?1 ORDER BY attachment_id")?;
        let rows = statement.query_map([revision.as_slice()], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (id, bytes) = row?;
            let id: [u8; 16] = id.try_into().map_err(|_| ReductionError::Integrity)?;
            attachments.push(ReceivedCiphertextAttachment {
                id,
                package: write_stage(directory, &format!("attachment-{}", hex_id(&id)), &bytes)?,
            });
        }
        let mut streams = Vec::new();
        let mut statement=c.prepare("SELECT attachment_id,header,chunk_count FROM attachment_streams WHERE revision_id=?1 ORDER BY attachment_id")?;
        let rows = statement.query_map([revision.as_slice()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (id, header, count) = row?;
            let id: [u8; 16] = id.try_into().map_err(|_| ReductionError::Integrity)?;
            let mut chunks = Vec::new();
            for index in 0..count {
                let bytes:Vec<u8>=c.query_row("SELECT ciphertext FROM attachment_stream_chunks WHERE attachment_id=?1 AND revision_id=?2 AND chunk_index=?3",params![id.as_slice(),revision.as_slice(),index],|r|r.get(0))?;
                chunks.push(write_stage(
                    directory,
                    &format!("stream-{}-{index}", hex_id(&id)),
                    &bytes,
                )?);
            }
            streams.push(ReceivedCiphertextStream { id, header, chunks });
        }
        let graph = ReceivedCiphertextGraph {
            item: parsed.subject,
            revision,
            kind,
            package: package_path,
            attachments,
            streams,
        };
        if graph_digest(&graph)? != expected {
            return Err(ReductionError::Integrity);
        }
        Ok(Some(graph))
    }

    /// Removes only remotely published event digests from the durable outbox.
    ///
    /// # Errors
    /// Returns an error without partial acknowledgement on storage failure.
    pub fn acknowledge_outbox(&self, digests: &[[u8; 32]]) -> Result<(), ReductionError> {
        let mut c = open_connection(&self.path)?;
        let tx = c.transaction()?;
        for id in digests {
            tx.execute("DELETE FROM outbox WHERE event_digest=?1", [id.as_slice()])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Recomputes the deterministic view from retained signed headers.
    ///
    /// # Errors
    /// Returns an error for corrupted persisted evidence.
    pub fn view(&self) -> Result<ReducedView, ReductionError> {
        let connection = open_connection(&self.path)?;
        view_connection(&connection, &self.trusted)
    }
}
fn view_connection(
    connection: &rusqlite::Connection,
    trusted: &TrustedRoot,
) -> Result<ReducedView, ReductionError> {
    let mut statement = connection.prepare(
        "SELECT event,human_signature,device_signature FROM authority_events ORDER BY event_digest",
    )?;
    let mut rows = statement.query([])?;
    let mut events = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let event: Vec<u8> = row.get(0)?;
        let human_signature = row
            .get::<_, Option<Vec<u8>>>(1)?
            .map(|v| fixed::<64>(&v))
            .transpose()?;
        let device_signature = fixed::<64>(&row.get::<_, Vec<u8>>(2)?)?;
        let signed = SignedCausalEvent {
            event,
            device_signature,
            human_signature,
        };
        let parsed = decode_event(&signed.event)?;
        verify_signed(connection, trusted, &signed, &parsed)?;
        events.insert(digest(&signed.event), parsed);
    }
    reduce(&events)
}

/// Stable failures at the signed reducer boundary.
#[derive(Debug)]
pub enum ReductionError {
    InvalidEvent,
    Integrity,
    ResourceLimit,
    Storage(rusqlite::Error),
    Vault(VaultError),
    Human(HumanCommitError),
}

fn staged_file(path: &Path, max: usize) -> Result<Vec<u8>, ReductionError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ReductionError::Integrity)?;
    let metadata = file.metadata().map_err(|_| ReductionError::Integrity)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max as u64 {
        return Err(ReductionError::ResourceLimit);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ReductionError::ResourceLimit)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| ReductionError::Integrity)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() > max {
        return Err(ReductionError::Integrity);
    }
    Ok(bytes)
}
fn write_stage(directory: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, ReductionError> {
    let path = directory.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| ReductionError::Integrity)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ReductionError::Integrity)?;
    Ok(path)
}
fn hex_id(id: &[u8; 16]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for b in id {
        out.push(char::from(D[usize::from(b >> 4)]));
        out.push(char::from(D[usize::from(b & 15)]));
    }
    out
}
fn insert_graph(
    tx: &rusqlite::Transaction<'_>,
    g: &ReceivedCiphertextGraph,
) -> Result<(), ReductionError> {
    if !g.attachments.is_empty() && !g.streams.is_empty() {
        return Err(ReductionError::Integrity);
    }
    let mut attachment_ids = BTreeSet::new();
    if !g
        .attachments
        .iter()
        .map(|attachment| attachment.id)
        .chain(g.streams.iter().map(|stream| stream.id))
        .all(|id| attachment_ids.insert(id))
    {
        return Err(ReductionError::Integrity);
    }
    let package = staged_file(&g.package, 16 * 1024 * 1024)?;
    tx.execute(
        "INSERT OR IGNORE INTO revision_parts(revision_id,item_id,package)VALUES(?1,?2,?3)",
        params![g.revision.as_slice(), g.item.as_slice(), &package],
    )?;
    let actual: (Vec<u8>, Vec<u8>) = tx.query_row(
        "SELECT item_id,package FROM revision_parts WHERE revision_id=?1",
        [g.revision.as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if actual.0 != g.item || actual.1 != package {
        return Err(ReductionError::Integrity);
    }
    for a in &g.attachments {
        let bytes = staged_file(&a.package, 17 * 1024 * 1024)?;
        tx.execute("INSERT OR IGNORE INTO attachment_parts(attachment_id,revision_id,package)VALUES(?1,?2,?3)",params![a.id.as_slice(),g.revision.as_slice(),&bytes])?;
        let actual: Vec<u8> = tx.query_row(
            "SELECT package FROM attachment_parts WHERE attachment_id=?1 AND revision_id=?2",
            params![a.id.as_slice(), g.revision.as_slice()],
            |r| r.get(0),
        )?;
        if actual != bytes {
            return Err(ReductionError::Integrity);
        }
    }
    for s in &g.streams {
        if s.header.is_empty() || s.header.len() > 16384 || s.chunks.is_empty() {
            return Err(ReductionError::ResourceLimit);
        }
        let count = i64::try_from(s.chunks.len()).map_err(|_| ReductionError::ResourceLimit)?;
        tx.execute("INSERT OR IGNORE INTO attachment_streams(attachment_id,revision_id,header,chunk_count)VALUES(?1,?2,?3,?4)",params![s.id.as_slice(),g.revision.as_slice(),&s.header,count])?;
        let actual:(Vec<u8>,i64)=tx.query_row("SELECT header,chunk_count FROM attachment_streams WHERE attachment_id=?1 AND revision_id=?2",params![s.id.as_slice(),g.revision.as_slice()],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if actual != (s.header.clone(), count) {
            return Err(ReductionError::Integrity);
        }
        for (index, path) in s.chunks.iter().enumerate() {
            let bytes = staged_file(path, 1_048_597)?;
            let index = i64::try_from(index).map_err(|_| ReductionError::ResourceLimit)?;
            tx.execute("INSERT OR IGNORE INTO attachment_stream_chunks(attachment_id,revision_id,chunk_index,ciphertext)VALUES(?1,?2,?3,?4)",params![s.id.as_slice(),g.revision.as_slice(),index,&bytes])?;
            let actual:Vec<u8>=tx.query_row("SELECT ciphertext FROM attachment_stream_chunks WHERE attachment_id=?1 AND revision_id=?2 AND chunk_index=?3",params![s.id.as_slice(),g.revision.as_slice(),index],|r|r.get(0))?;
            if actual != bytes {
                return Err(ReductionError::Integrity);
            }
        }
    }
    Ok(())
}
fn graph_digest(g: &ReceivedCiphertextGraph) -> Result<[u8; 32], ReductionError> {
    use pm_crypto::DigestState;
    let package = staged_file(&g.package, 16 * 1024 * 1024)?;
    if g.streams.is_empty() {
        let mut sorted: Vec<_> = g.attachments.iter().collect();
        sorted.sort_by_key(|a| a.id);
        let mut e = Encoder::new(Vec::new());
        e.array(u64::try_from(sorted.len()).map_err(|_| ReductionError::ResourceLimit)?)
            .unwrap();
        for a in sorted {
            let bytes = staged_file(&a.package, 17 * 1024 * 1024)?;
            e.map(2)
                .unwrap()
                .str("id")
                .unwrap()
                .bytes(&a.id)
                .unwrap()
                .str("package")
                .unwrap()
                .bytes(&bytes)
                .unwrap();
        }
        let values = e.into_writer();
        let mut e = Encoder::new(Vec::new());
        e.array(2).unwrap().bytes(&package).unwrap();
        e.bytes(&values).unwrap();
        return Ok(digest(&e.into_writer()));
    }
    let mut state = DigestState::new().map_err(|_| ReductionError::Integrity)?;
    state.update(b"pm/staged-stream/v1");
    state.update(&(package.len() as u64).to_be_bytes());
    state.update(&package);
    let mut streams: Vec<_> = g.streams.iter().collect();
    streams.sort_by_key(|s| s.id);
    for s in &streams {
        state.update(&s.id);
        state.update(&(s.header.len() as u64).to_be_bytes());
        state.update(&s.header);
        state.update(
            &i64::try_from(s.chunks.len())
                .map_err(|_| ReductionError::ResourceLimit)?
                .to_be_bytes(),
        );
    }
    for s in streams {
        for (index, path) in s.chunks.iter().enumerate() {
            let bytes = staged_file(path, 1_048_597)?;
            state.update(&s.id);
            state.update(
                &i64::try_from(index)
                    .map_err(|_| ReductionError::ResourceLimit)?
                    .to_be_bytes(),
            );
            state.update(&(bytes.len() as u64).to_be_bytes());
            state.update(&bytes);
        }
    }
    Ok(state.finish())
}

impl fmt::Display for ReductionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("causal event reduction failed")
    }
}
impl std::error::Error for ReductionError {}
impl From<rusqlite::Error> for ReductionError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}
impl From<VaultError> for ReductionError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}
impl From<HumanCommitError> for ReductionError {
    fn from(value: HumanCommitError) -> Self {
        Self::Human(value)
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn encode_body(body: &CausalEventBody) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    match body {
        CausalEventBody::Revision {
            revision_id,
            modified_at,
            manifest_digest,
            previous_revisions,
        } => {
            e.map(4)
                .unwrap()
                .str("revision_id")
                .unwrap()
                .bytes(revision_id)
                .unwrap();
            e.str("modified_at").unwrap().i64(*modified_at).unwrap();
            e.str("manifest_digest")
                .unwrap()
                .bytes(manifest_digest)
                .unwrap();
            e.str("previous_revisions").unwrap();
            encode_ids16(&mut e, previous_revisions);
        }
        CausalEventBody::Reason => {
            e.map(1)
                .unwrap()
                .str("reason_code")
                .unwrap()
                .str("owner_request")
                .unwrap();
        }
        CausalEventBody::Positive {
            prior_positive_events,
            withdrawals_seen,
        } => {
            e.map(2).unwrap().str("prior_positive_events").unwrap();
            encode_ids32(&mut e, prior_positive_events);
            e.str("withdrawals_seen").unwrap();
            encode_ids32(&mut e, withdrawals_seen);
        }
        CausalEventBody::Retire { accepted_prefixes } => {
            e.map(2)
                .unwrap()
                .str("reason_code")
                .unwrap()
                .str("owner_request")
                .unwrap();
            e.str("accepted_prefix")
                .unwrap()
                .array(u64::try_from(accepted_prefixes.len()).unwrap())
                .unwrap();
            for p in accepted_prefixes {
                e.map(3)
                    .unwrap()
                    .str("generation")
                    .unwrap()
                    .u64(p.generation)
                    .unwrap()
                    .str("seq")
                    .unwrap()
                    .u64(p.seq)
                    .unwrap()
                    .str("tip_digest")
                    .unwrap()
                    .bytes(&p.tip_digest)
                    .unwrap();
            }
        }
        CausalEventBody::Lifecycle { deletions_seen } => {
            e.map(1).unwrap().str("deletions_seen").unwrap();
            encode_ids32(&mut e, deletions_seen);
        }
        CausalEventBody::Purge { revision_ids } => {
            e.map(1).unwrap().str("revision_ids").unwrap();
            encode_ids16(&mut e, revision_ids);
        }
        CausalEventBody::PurgeScoped {
            item_id,
            revision_ids,
            scope,
        } => {
            e.map(3)
                .unwrap()
                .str("item_id")
                .unwrap()
                .bytes(item_id)
                .unwrap()
                .str("revision_ids")
                .unwrap();
            encode_ids16(&mut e, revision_ids);
            e.str("scope")
                .unwrap()
                .str(match scope {
                    PurgeScopeKind::Item => "item",
                    PurgeScopeKind::Revisions => "revisions",
                })
                .unwrap();
        }
        CausalEventBody::Join => {
            e.map(0).unwrap();
        }
        CausalEventBody::Checkpoint {
            covered_heads,
            state_digest,
            index_parts,
        } => {
            e.map(3).unwrap().str("covered_heads").unwrap();
            encode_ids32(&mut e, covered_heads);
            e.str("state_digest").unwrap().bytes(state_digest).unwrap();
            e.str("index_parts").unwrap();
            encode_ids32(&mut e, index_parts);
        }
    }
    e.into_writer()
}

fn encode_ids16(e: &mut Encoder<Vec<u8>>, values: &[[u8; 16]]) {
    e.array(u64::try_from(values.len()).unwrap()).unwrap();
    for value in values {
        e.bytes(value).unwrap();
    }
}
fn encode_ids32(e: &mut Encoder<Vec<u8>>, values: &[[u8; 32]]) {
    e.array(u64::try_from(values.len()).unwrap()).unwrap();
    for value in values {
        e.bytes(value).unwrap();
    }
}
fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone)]
struct ParsedEvent {
    vault: [u8; 16],
    event_id: [u8; 16],
    issuer_device: [u8; 16],
    issuer_generation: u64,
    seq: u64,
    previous: Option<[u8; 32]>,
    parents: Vec<[u8; 32]>,
    kind: CausalEventKind,
    subject: [u8; 16],
    subject_generation: u64,
    body: CausalEventBody,
    bound_graph: bool,
}

fn decode_event(bytes: &[u8]) -> Result<ParsedEvent, ReductionError> {
    let mut d = Decoder::new(bytes);
    expect_map(&mut d, 13)?;
    expect_key(&mut d, "v")?;
    if d.u64().map_err(|_| ReductionError::InvalidEvent)? != 1 {
        return Err(ReductionError::InvalidEvent);
    }
    expect_key(&mut d, "vault")?;
    let vault = decode_fixed(&mut d)?;
    expect_key(&mut d, "event_id")?;
    let event_id = decode_fixed(&mut d)?;
    expect_key(&mut d, "authority_epoch")?;
    if d.u64().map_err(|_| ReductionError::InvalidEvent)? != 1 {
        return Err(ReductionError::InvalidEvent);
    }
    expect_key(&mut d, "issuer_device")?;
    let issuer_device = decode_fixed(&mut d)?;
    expect_key(&mut d, "issuer_generation")?;
    let issuer_generation = d.u64().map_err(|_| ReductionError::InvalidEvent)?;
    expect_key(&mut d, "seq")?;
    let seq = d.u64().map_err(|_| ReductionError::InvalidEvent)?;
    expect_key(&mut d, "prev")?;
    let previous = decode_optional_fixed(&mut d)?;
    expect_key(&mut d, "parents")?;
    let parents = decode_array_fixed(&mut d, 4096)?;
    expect_key(&mut d, "kind")?;
    let kind = parse_kind(d.str().map_err(|_| ReductionError::InvalidEvent)?)?;
    expect_key(&mut d, "subject")?;
    let subject = decode_fixed(&mut d)?;
    expect_key(&mut d, "subject_generation")?;
    let subject_generation = d.u64().map_err(|_| ReductionError::InvalidEvent)?;
    expect_key(&mut d, "body")?;
    let body_start = d.position();
    d.skip().map_err(|_| ReductionError::InvalidEvent)?;
    let raw_body = &bytes[body_start..d.position()];
    let bound_graph =
        kind == CausalEventKind::ItemRevision && Decoder::new(raw_body).map().ok() == Some(Some(5));
    let mut body_decoder = Decoder::new(raw_body);
    let body = match decode_body(&mut body_decoder, kind) {
        Ok(value)
            if body_decoder.position() == raw_body.len() && encode_body(&value) == raw_body =>
        {
            value
        }
        _ => decode_legacy_body(raw_body, kind)?,
    };
    if matches!(
        &body,
        CausalEventBody::PurgeScoped { item_id, .. } if item_id != &subject
    ) {
        return Err(ReductionError::InvalidEvent);
    }
    if d.position() != bytes.len()
        || event_id == [0; 16]
        || issuer_generation == 0
        || seq == 0
        || subject_generation == 0
        || !strictly_sorted(&parents)
        || previous.is_some_and(|p| !parents.contains(&p))
        || ((seq == 1) != previous.is_none())
    {
        return Err(ReductionError::InvalidEvent);
    }
    let canonical_body = raw_body.to_vec();
    let canonical = encode_g5_event(&G5EventInput {
        vault: &vault,
        event_id,
        authority_epoch: 1,
        issuer_device,
        issuer_generation,
        seq,
        previous,
        parents: &parents,
        kind: kind.name(),
        subject,
        subject_generation,
        body: &canonical_body,
    });
    if canonical != bytes {
        return Err(ReductionError::InvalidEvent);
    }
    Ok(ParsedEvent {
        vault,
        event_id,
        issuer_device,
        issuer_generation,
        seq,
        previous,
        parents,
        kind,
        subject,
        subject_generation,
        body,
        bound_graph,
    })
}

#[allow(clippy::too_many_lines)]
fn decode_body(
    d: &mut Decoder<'_>,
    kind: CausalEventKind,
) -> Result<CausalEventBody, ReductionError> {
    match kind {
        CausalEventKind::ItemRevision => {
            expect_map(d, 4)?;
            expect_key(d, "revision_id")?;
            let revision_id = decode_fixed(d)?;
            expect_key(d, "modified_at")?;
            let modified_at = d.i64().map_err(|_| ReductionError::InvalidEvent)?;
            expect_key(d, "manifest_digest")?;
            let manifest_digest = decode_fixed(d)?;
            expect_key(d, "previous_revisions")?;
            let previous_revisions = decode_array_fixed(d, 4096)?;
            if !strictly_sorted(&previous_revisions) {
                return Err(ReductionError::InvalidEvent);
            }
            Ok(CausalEventBody::Revision {
                revision_id,
                modified_at,
                manifest_digest,
                previous_revisions,
            })
        }
        CausalEventKind::AgentGrant | CausalEventKind::Enable | CausalEventKind::Resume => {
            expect_map(d, 2)?;
            expect_key(d, "prior_positive_events")?;
            let prior_positive_events = decode_array_fixed(d, 4096)?;
            expect_key(d, "withdrawals_seen")?;
            let withdrawals_seen = decode_array_fixed(d, 4096)?;
            if !strictly_sorted(&prior_positive_events) || !strictly_sorted(&withdrawals_seen) {
                return Err(ReductionError::InvalidEvent);
            }
            Ok(CausalEventBody::Positive {
                prior_positive_events,
                withdrawals_seen,
            })
        }
        CausalEventKind::AgentRevoke | CausalEventKind::Disable | CausalEventKind::Suspend => {
            expect_map(d, 1)?;
            expect_key(d, "reason_code")?;
            if d.str().map_err(|_| ReductionError::InvalidEvent)? != "owner_request" {
                return Err(ReductionError::InvalidEvent);
            }
            Ok(CausalEventBody::Reason)
        }
        CausalEventKind::DeviceRetire => {
            expect_map(d, 2)?;
            expect_key(d, "reason_code")?;
            if d.str().map_err(|_| ReductionError::InvalidEvent)? != "owner_request" {
                return Err(ReductionError::InvalidEvent);
            }
            expect_key(d, "accepted_prefix")?;
            let count = definite_array(d, 4096)?;
            let mut accepted_prefixes = Vec::with_capacity(count);
            for _ in 0..count {
                expect_map(d, 3)?;
                expect_key(d, "generation")?;
                let generation = d.u64().map_err(|_| ReductionError::InvalidEvent)?;
                expect_key(d, "seq")?;
                let seq = d.u64().map_err(|_| ReductionError::InvalidEvent)?;
                expect_key(d, "tip_digest")?;
                let tip_digest = decode_fixed(d)?;
                if generation == 0 || seq == 0 {
                    return Err(ReductionError::InvalidEvent);
                }
                accepted_prefixes.push(AcceptedPrefix {
                    generation,
                    seq,
                    tip_digest,
                });
            }
            if !accepted_prefixes
                .windows(2)
                .all(|w| w[0].generation < w[1].generation)
            {
                return Err(ReductionError::InvalidEvent);
            }
            Ok(CausalEventBody::Retire { accepted_prefixes })
        }
        CausalEventKind::Trash | CausalEventKind::Restore => {
            expect_map(d, 1)?;
            expect_key(d, "deletions_seen")?;
            let deletions_seen = decode_array_fixed(d, 4096)?;
            if !strictly_sorted(&deletions_seen) {
                return Err(ReductionError::InvalidEvent);
            }
            Ok(CausalEventBody::Lifecycle { deletions_seen })
        }
        CausalEventKind::PurgeItem | CausalEventKind::PurgeRevisions => {
            match d.map().map_err(|_| ReductionError::InvalidEvent)? {
                Some(1) => {
                    expect_key(d, "revision_ids")?;
                    let revision_ids = decode_array_fixed(d, 4096)?;
                    if !strictly_sorted(&revision_ids) {
                        return Err(ReductionError::InvalidEvent);
                    }
                    Ok(CausalEventBody::Purge { revision_ids })
                }
                Some(3) => {
                    expect_key(d, "item_id")?;
                    let item_id = decode_fixed(d)?;
                    expect_key(d, "revision_ids")?;
                    let revision_ids = decode_array_fixed(d, 4096)?;
                    expect_key(d, "scope")?;
                    let scope = match d.str().map_err(|_| ReductionError::InvalidEvent)? {
                        "item" if kind == CausalEventKind::PurgeItem => PurgeScopeKind::Item,
                        "revisions" if kind == CausalEventKind::PurgeRevisions => {
                            PurgeScopeKind::Revisions
                        }
                        _ => return Err(ReductionError::InvalidEvent),
                    };
                    if revision_ids.is_empty() || !strictly_sorted(&revision_ids) {
                        return Err(ReductionError::InvalidEvent);
                    }
                    Ok(CausalEventBody::PurgeScoped {
                        item_id,
                        revision_ids,
                        scope,
                    })
                }
                _ => Err(ReductionError::InvalidEvent),
            }
        }
        CausalEventKind::Join => {
            expect_map(d, 0)?;
            Ok(CausalEventBody::Join)
        }
        CausalEventKind::CheckpointCache => {
            expect_map(d, 3)?;
            expect_key(d, "covered_heads")?;
            let covered_heads = decode_array_fixed(d, 4096)?;
            expect_key(d, "state_digest")?;
            let state_digest = decode_fixed(d)?;
            expect_key(d, "index_parts")?;
            let index_parts = decode_array_fixed(d, 4096)?;
            if !strictly_sorted(&covered_heads) || !strictly_sorted(&index_parts) {
                return Err(ReductionError::InvalidEvent);
            }
            Ok(CausalEventBody::Checkpoint {
                covered_heads,
                state_digest,
                index_parts,
            })
        }
        CausalEventKind::AuditPurge => Err(ReductionError::InvalidEvent),
    }
}

#[allow(clippy::too_many_lines)]
fn decode_legacy_body(
    bytes: &[u8],
    kind: CausalEventKind,
) -> Result<CausalEventBody, ReductionError> {
    if kind == CausalEventKind::AuditPurge {
        let mut d = Decoder::new(bytes);
        d.skip().map_err(|_| ReductionError::InvalidEvent)?;
        return (d.position() == bytes.len())
            .then_some(CausalEventBody::Reason)
            .ok_or(ReductionError::InvalidEvent);
    }
    if matches!(
        kind,
        CausalEventKind::AgentRevoke | CausalEventKind::Disable | CausalEventKind::Suspend
    ) {
        let mut d = Decoder::new(bytes);
        expect_map(&mut d, 1)?;
        expect_key(&mut d, "reason_code")?;
        if !matches!(
            d.str().map_err(|_| ReductionError::InvalidEvent)?,
            "owner_request" | "replacement" | "suspected_compromise"
        ) || d.position() != bytes.len()
        {
            return Err(ReductionError::InvalidEvent);
        }
        return Ok(CausalEventBody::Reason);
    }
    if kind == CausalEventKind::AgentGrant {
        let mut d = Decoder::new(bytes);
        expect_map(&mut d, 5)?;
        expect_key(&mut d, "request_id")?;
        let _: [u8; 16] = decode_fixed(&mut d)?;
        expect_key(&mut d, "public_identity")?;
        expect_map(&mut d, 2)?;
        expect_key(&mut d, "transport_rpk")?;
        if d.bytes().map_err(|_| ReductionError::InvalidEvent)?.len() != 44 {
            return Err(ReductionError::InvalidEvent);
        }
        expect_key(&mut d, "label")?;
        d.str().map_err(|_| ReductionError::InvalidEvent)?;
        expect_key(&mut d, "predecessor_grants")?;
        let predecessors = decode_array_fixed(&mut d, 4096)?;
        expect_key(&mut d, "expires_at")?;
        d.null().map_err(|_| ReductionError::InvalidEvent)?;
        expect_key(&mut d, "environment_binding")?;
        d.str().map_err(|_| ReductionError::InvalidEvent)?;
        if d.position() != bytes.len() || !strictly_sorted(&predecessors) {
            return Err(ReductionError::InvalidEvent);
        }
        return Ok(CausalEventBody::Positive {
            prior_positive_events: predecessors.clone(),
            withdrawals_seen: predecessors,
        });
    }
    if kind == CausalEventKind::Enable {
        let mut d = Decoder::new(bytes);
        expect_map(&mut d, 4)?;
        expect_key(&mut d, "revision_id")?;
        decode_fixed::<16>(&mut d)?;
        expect_key(&mut d, "grant_commitments")?;
        let commitments = decode_array_fixed::<32>(&mut d, 4096)?;
        expect_key(&mut d, "prior_positive_events")?;
        let prior_positive_events = decode_array_fixed(&mut d, 4096)?;
        expect_key(&mut d, "withdrawals_seen")?;
        let withdrawals_seen = decode_array_fixed(&mut d, 4096)?;
        if commitments.len() != 1
            || !strictly_sorted(&prior_positive_events)
            || !strictly_sorted(&withdrawals_seen)
            || d.position() != bytes.len()
        {
            return Err(ReductionError::InvalidEvent);
        }
        return Ok(CausalEventBody::Positive {
            prior_positive_events,
            withdrawals_seen,
        });
    }
    if !matches!(kind, CausalEventKind::ItemRevision | CausalEventKind::Trash) {
        return Err(ReductionError::InvalidEvent);
    }
    let mut d = Decoder::new(bytes);
    let fields = d.map().map_err(|_| ReductionError::InvalidEvent)?;
    if !matches!(fields, Some(4 | 5)) {
        return Err(ReductionError::InvalidEvent);
    }
    expect_key(&mut d, "revision_id")?;
    let revision_id = decode_optional_fixed(&mut d)?;
    expect_key(&mut d, "modified_at")?;
    let modified_at = d.i64().map_err(|_| ReductionError::InvalidEvent)?;
    expect_key(&mut d, "audit_generation")?;
    decode_optional_u64(&mut d)?;
    expect_key(&mut d, "audit_through_seq")?;
    decode_optional_u64(&mut d)?;
    let object_manifest_digest = if fields == Some(5) {
        expect_key(&mut d, "object_manifest_digest")?;
        decode_optional_fixed(&mut d)?
    } else {
        None
    };
    if d.position() != bytes.len() {
        return Err(ReductionError::InvalidEvent);
    }
    match (kind, revision_id) {
        (CausalEventKind::ItemRevision, Some(revision_id)) => Ok(CausalEventBody::Revision {
            revision_id,
            modified_at,
            manifest_digest: object_manifest_digest.unwrap_or_else(|| digest(bytes)),
            previous_revisions: Vec::new(),
        }),
        (CausalEventKind::Trash, _) => Ok(CausalEventBody::Lifecycle {
            deletions_seen: Vec::new(),
        }),
        _ => Err(ReductionError::InvalidEvent),
    }
}

fn verify_signed(
    connection: &rusqlite::Connection,
    trusted: &TrustedRoot,
    signed: &SignedCausalEvent,
    parsed: &ParsedEvent,
) -> Result<(), ReductionError> {
    if &parsed.vault != trusted.vault_id() {
        return Err(ReductionError::Integrity);
    }
    let package = load_key_package(
        connection,
        trusted,
        parsed.issuer_device,
        parsed.issuer_generation,
    )?;
    verify_audit_key_package(
        trusted,
        &package,
        parsed.issuer_device,
        parsed.issuer_generation,
    )
    .map_err(|_| ReductionError::Integrity)?;
    verify_device_event(
        package.signing_public_key(),
        &signed.event,
        &signed.device_signature,
    )
    .map_err(|_| ReductionError::Integrity)?;
    match (parsed.kind.technical(), signed.human_signature.as_ref()) {
        (true, None) => {}
        (false, Some(signature)) => verify_human_event(trusted, &signed.event, signature)
            .map_err(|_| ReductionError::Integrity)?,
        _ => return Err(ReductionError::Integrity),
    }
    Ok(())
}

fn load_key_package(
    connection: &rusqlite::Connection,
    trusted: &TrustedRoot,
    device: [u8; 16],
    generation: u64,
) -> Result<AuditKeyPackage, ReductionError> {
    crate::audit::load_package(connection, *trusted.vault_id(), device, generation)
        .map_err(ReductionError::from)
}

#[allow(clippy::too_many_lines)]
fn reduce(events: &BTreeMap<[u8; 32], ParsedEvent>) -> Result<ReducedView, ReductionError> {
    let mut structural = BTreeSet::new();
    loop {
        let before = structural.len();
        for (id, event) in events {
            if structural.contains(id) || !event.parents.iter().all(|p| structural.contains(p)) {
                continue;
            }
            let chain_ok = match event.previous {
                None => event.seq == 1,
                Some(prev) => events.get(&prev).is_some_and(|p| {
                    p.issuer_device == event.issuer_device
                        && p.issuer_generation == event.issuer_generation
                        && p.seq.checked_add(1) == Some(event.seq)
                }),
            };
            if chain_ok {
                structural.insert(*id);
            }
        }
        if structural.len() == before {
            break;
        }
    }
    let pending = events.len() - structural.len();
    let pending_bytes: usize = events
        .iter()
        .filter(|(id, _)| !structural.contains(*id))
        .map(|(_, e)| encode_body(&e.body).len() + 256)
        .sum();
    if pending > 4096 || pending_bytes > 256 * 1024 * 1024 {
        return Err(ReductionError::ResourceLimit);
    }

    let mut slots: HashMap<([u8; 16], u64, u64), Vec<[u8; 32]>> = HashMap::new();
    for id in &structural {
        let e = &events[id];
        slots
            .entry((e.issuer_device, e.issuer_generation, e.seq))
            .or_default()
            .push(*id);
    }
    let fork_slots: Vec<Vec<[u8; 32]>> = slots.values().filter(|v| v.len() > 1).cloned().collect();
    let ancestor_cache = Ancestors::new(events, &structural);
    let unresolved_forks = fork_slots
        .iter()
        .filter(|branches| {
            !structural.iter().any(|candidate| {
                !branches.contains(candidate)
                    && branches
                        .iter()
                        .all(|branch| ancestor_cache.is_ancestor(*branch, *candidate))
            })
        })
        .count();

    let negatives: BTreeSet<[u8; 32]> = structural
        .iter()
        .copied()
        .filter(|id| is_negative(events[id].kind))
        .collect();
    let retires: Vec<([u8; 32], &ParsedEvent)> = structural
        .iter()
        .filter_map(|id| {
            let e = &events[id];
            (e.kind == CausalEventKind::DeviceRetire).then_some((*id, e))
        })
        .collect();
    let mut active = BTreeSet::new();
    for id in &structural {
        let e = &events[id];
        if is_negative(e.kind) {
            active.insert(*id);
            continue;
        }
        if !within_retirement_cuts(*id, e, &retires, events, &ancestor_cache) {
            continue;
        }
        if !forks_acknowledged(*id, e, &fork_slots, &ancestor_cache) {
            continue;
        }
        if is_authority_positive(e.kind)
            && !positive_acknowledges(*id, e, &negatives, events, &ancestor_cache)
        {
            continue;
        }
        active.insert(*id);
    }

    let revision_purges: Vec<_> = active
        .iter()
        .copied()
        .filter(|id| events[id].kind == CausalEventKind::PurgeRevisions)
        .collect();
    for id in revision_purges {
        let event = &events[&id];
        let winner = active
            .iter()
            .filter_map(|candidate| {
                let revision = &events[candidate];
                if revision.subject != event.subject || !ancestor_cache.is_ancestor(*candidate, id)
                {
                    return None;
                }
                let CausalEventBody::Revision {
                    revision_id,
                    modified_at,
                    ..
                } = &revision.body
                else {
                    return None;
                };
                Some((
                    (*modified_at, revision.issuer_device, *revision_id),
                    *revision_id,
                ))
            })
            .max_by_key(|value| value.0)
            .map(|value| value.1);
        let Some(revision_ids) = purge_revision_ids(&event.body) else {
            continue;
        };
        if winner.is_some_and(|winner| revision_ids.contains(&winner)) {
            active.remove(&id);
        }
    }

    let checkpoints: Vec<_> = active
        .iter()
        .copied()
        .filter(|id| events[id].kind == CausalEventKind::CheckpointCache)
        .collect();
    for id in checkpoints {
        let CausalEventBody::Checkpoint {
            covered_heads,
            state_digest: claimed,
            ..
        } = &events[&id].body
        else {
            continue;
        };
        if !covered_heads
            .iter()
            .all(|head| ancestor_cache.is_ancestor(*head, id))
        {
            active.remove(&id);
            continue;
        }
        let covered: BTreeSet<_> = active
            .iter()
            .copied()
            .filter(|candidate| {
                covered_heads
                    .iter()
                    .any(|head| ancestor_cache.is_ancestor(*candidate, *head))
            })
            .collect();
        let projected = build_items(events, &covered, &ancestor_cache);
        if state_digest(&projected, &covered, events) != *claimed {
            active.remove(&id);
        }
    }
    let items = build_items(events, &active, &ancestor_cache);
    let retired_devices = active
        .iter()
        .filter_map(|id| {
            (events[id].kind == CausalEventKind::DeviceRetire).then_some(events[id].subject)
        })
        .collect();
    let delegated_resumed = active
        .iter()
        .any(|id| events[id].kind == CausalEventKind::Resume);
    let agents = active
        .iter()
        .filter_map(|id| {
            let e = &events[id];
            (e.kind == CausalEventKind::AgentGrant
                && !active.iter().any(|withdrawal| {
                    let w = &events[withdrawal];
                    w.kind == CausalEventKind::AgentRevoke
                        && w.subject == e.subject
                        && w.subject_generation == e.subject_generation
                }))
            .then_some((e.subject, e.subject_generation))
        })
        .collect();
    let enabled_items = active
        .iter()
        .filter_map(|id| {
            let e = &events[id];
            (e.kind == CausalEventKind::Enable
                && !active.iter().any(|withdrawal| {
                    let w = &events[withdrawal];
                    w.kind == CausalEventKind::Disable
                        && w.subject == e.subject
                        && w.subject_generation == e.subject_generation
                }))
            .then_some((e.subject, e.subject_generation))
        })
        .collect();
    let digest = state_digest(&items, &active, events);
    Ok(ReducedView {
        digest,
        items,
        pending,
        headers: events.len(),
        active,
        forks: unresolved_forks,
        agents,
        enabled_items,
        delegated_resumed,
        retired_devices,
    })
}

#[allow(clippy::too_many_lines)]
fn build_items(
    events: &BTreeMap<[u8; 32], ParsedEvent>,
    active: &BTreeSet<[u8; 32]>,
    ancestor_cache: &Ancestors,
) -> BTreeMap<[u8; 16], ReducedItem> {
    type RevisionTuple = ([u8; 16], i64, [u8; 16], [u8; 32]);
    let mut item_ids = BTreeSet::new();
    for id in active {
        let e = &events[id];
        if is_item_kind(e.kind) {
            item_ids.insert(e.subject);
        }
    }
    let mut items = BTreeMap::new();
    for item in item_ids {
        let purge_item = active
            .iter()
            .any(|id| events[id].subject == item && events[id].kind == CausalEventKind::PurgeItem);
        let trash: BTreeSet<[u8; 32]> = active
            .iter()
            .copied()
            .filter(|id| events[id].subject == item && events[id].kind == CausalEventKind::Trash)
            .collect();
        let restored = !trash.is_empty()
            && active.iter().any(|id| {
                let e = &events[id];
                if e.subject != item || e.kind != CausalEventKind::Restore {
                    return false;
                }
                let CausalEventBody::Lifecycle { deletions_seen } = &e.body else {
                    return false;
                };
                trash
                    .iter()
                    .all(|t| deletions_seen.contains(t) && ancestor_cache.is_ancestor(*t, *id))
            });
        let mut revisions: Vec<RevisionTuple> = active
            .iter()
            .filter_map(|id| {
                let e = &events[id];
                if e.subject != item {
                    return None;
                }
                let CausalEventBody::Revision {
                    revision_id,
                    modified_at,
                    ..
                } = &e.body
                else {
                    return None;
                };
                Some((*revision_id, *modified_at, e.issuer_device, *id))
            })
            .collect();
        revisions.sort_by_key(|(revision, time, device, _)| (*time, *device, *revision));
        let causal_winners: HashMap<[u8; 32], [u8; 16]> = active
            .iter()
            .filter_map(|id| {
                let e = &events[id];
                (e.kind == CausalEventKind::PurgeRevisions && e.subject == item).then(|| {
                    let winner = revisions
                        .iter()
                        .filter(|(_, _, _, rid)| ancestor_cache.is_ancestor(*rid, *id))
                        .max_by_key(|(r, t, d, _)| (*t, *d, *r))
                        .map(|v| v.0);
                    (*id, winner.unwrap_or([0; 16]))
                })
            })
            .collect();
        let mut purged = BTreeSet::new();
        for (id, winner) in causal_winners {
            let Some(revision_ids) = purge_revision_ids(&events[&id].body) else {
                continue;
            };
            if !revision_ids.contains(&winner) {
                purged.extend(revision_ids.iter().copied());
            }
        }
        revisions.retain(|(r, _, _, _)| !purged.contains(r));
        let visible_revision = if purge_item {
            None
        } else {
            revisions.last().map(|value| value.0)
        };
        let mut history: Vec<_> = if purge_item {
            Vec::new()
        } else {
            revisions.into_iter().map(|v| v.0).collect()
        };
        history.sort_unstable();
        history.dedup();
        let lifecycle = if purge_item {
            ItemLifecycle::Purged
        } else if !trash.is_empty() && !restored {
            ItemLifecycle::Trash
        } else {
            ItemLifecycle::Active
        };
        items.insert(
            item,
            ReducedItem {
                lifecycle,
                visible_revision,
                history,
            },
        );
    }
    items
}

fn purge_revision_ids(body: &CausalEventBody) -> Option<&[[u8; 16]]> {
    match body {
        CausalEventBody::Purge { revision_ids }
        | CausalEventBody::PurgeScoped { revision_ids, .. } => Some(revision_ids),
        _ => None,
    }
}

struct Ancestors {
    by_event: HashMap<[u8; 32], HashSet<[u8; 32]>>,
}
impl Ancestors {
    fn new(events: &BTreeMap<[u8; 32], ParsedEvent>, structural: &BTreeSet<[u8; 32]>) -> Self {
        let mut by_event: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
        loop {
            let before = by_event.len();
            for id in structural {
                if by_event.contains_key(id) {
                    continue;
                }
                let e = &events[id];
                if !e.parents.iter().all(|p| by_event.contains_key(p)) {
                    continue;
                }
                let mut set = HashSet::new();
                for p in &e.parents {
                    set.insert(*p);
                    set.extend(by_event[p].iter().copied());
                }
                by_event.insert(*id, set);
            }
            if by_event.len() == before {
                break;
            }
        }
        Self { by_event }
    }
    fn is_ancestor(&self, a: [u8; 32], b: [u8; 32]) -> bool {
        a == b || self.by_event.get(&b).is_some_and(|s| s.contains(&a))
    }
}

fn within_retirement_cuts(
    id: [u8; 32],
    event: &ParsedEvent,
    retires: &[([u8; 32], &ParsedEvent)],
    events: &BTreeMap<[u8; 32], ParsedEvent>,
    ancestors: &Ancestors,
) -> bool {
    for (_, retire) in retires
        .iter()
        .filter(|(_, r)| r.subject == event.issuer_device)
    {
        let CausalEventBody::Retire { accepted_prefixes } = &retire.body else {
            continue;
        };
        let Some(p) = accepted_prefixes
            .iter()
            .find(|p| p.generation == event.issuer_generation)
        else {
            return false;
        };
        if event.seq > p.seq {
            return false;
        }
        let Some(tip) = events.get(&p.tip_digest) else {
            return false;
        };
        if tip.issuer_device != event.issuer_device
            || tip.issuer_generation != event.issuer_generation
            || tip.seq != p.seq
            || !ancestors.is_ancestor(id, p.tip_digest)
        {
            return false;
        }
    }
    true
}
fn forks_acknowledged(
    id: [u8; 32],
    event: &ParsedEvent,
    forks: &[Vec<[u8; 32]>],
    ancestors: &Ancestors,
) -> bool {
    forks.iter().all(|branches| {
        if !branches.iter().any(|b| ancestors.is_ancestor(*b, id)) {
            true
        } else if branches.contains(&id) {
            false
        } else {
            branches.iter().all(|b| ancestors.is_ancestor(*b, id))
        }
    }) || event.kind == CausalEventKind::Join
}
fn positive_acknowledges(
    id: [u8; 32],
    event: &ParsedEvent,
    negatives: &BTreeSet<[u8; 32]>,
    events: &BTreeMap<[u8; 32], ParsedEvent>,
    ancestors: &Ancestors,
) -> bool {
    let CausalEventBody::Positive {
        withdrawals_seen, ..
    } = &event.body
    else {
        return false;
    };
    negatives
        .iter()
        .filter(|n| relevant_withdrawal(event, &events[*n]))
        .all(|n| withdrawals_seen.contains(n) && ancestors.is_ancestor(*n, id))
}
fn relevant_withdrawal(positive: &ParsedEvent, negative: &ParsedEvent) -> bool {
    negative.kind == CausalEventKind::Suspend || negative.subject == positive.subject
}
fn is_negative(kind: CausalEventKind) -> bool {
    matches!(
        kind,
        CausalEventKind::AgentRevoke
            | CausalEventKind::Disable
            | CausalEventKind::Suspend
            | CausalEventKind::DeviceRetire
            | CausalEventKind::Trash
            | CausalEventKind::PurgeItem
            | CausalEventKind::PurgeRevisions
    )
}
fn is_authority_positive(kind: CausalEventKind) -> bool {
    matches!(
        kind,
        CausalEventKind::AgentGrant | CausalEventKind::Enable | CausalEventKind::Resume
    )
}
fn is_item_kind(kind: CausalEventKind) -> bool {
    matches!(
        kind,
        CausalEventKind::ItemRevision
            | CausalEventKind::Trash
            | CausalEventKind::Restore
            | CausalEventKind::PurgeItem
            | CausalEventKind::PurgeRevisions
    )
}

fn state_digest(
    items: &BTreeMap<[u8; 16], ReducedItem>,
    active: &BTreeSet<[u8; 32]>,
    events: &BTreeMap<[u8; 32], ParsedEvent>,
) -> [u8; 32] {
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .array(u64::try_from(items.len()).unwrap())
        .unwrap();
    for (id, item) in items {
        e.bytes(id)
            .unwrap()
            .array(3)
            .unwrap()
            .u8(match item.lifecycle {
                ItemLifecycle::Active => 1,
                ItemLifecycle::Trash => 2,
                ItemLifecycle::Purged => 3,
            })
            .unwrap();
        match item.visible_revision {
            Some(v) => {
                e.bytes(&v).unwrap();
            }
            None => {
                e.null().unwrap();
            }
        }
        e.array(u64::try_from(item.history.len()).unwrap()).unwrap();
        for r in &item.history {
            e.bytes(r).unwrap();
        }
    }
    let material: Vec<_> = active
        .iter()
        .filter(|id| !events[*id].kind.technical())
        .collect();
    e.array(u64::try_from(material.len()).unwrap()).unwrap();
    for id in material {
        e.bytes(id).unwrap();
    }
    digest(&e.into_writer())
}

fn parse_kind(value: &str) -> Result<CausalEventKind, ReductionError> {
    match value {
        "item-revision" => Ok(CausalEventKind::ItemRevision),
        "agent-grant" => Ok(CausalEventKind::AgentGrant),
        "agent-revoke" => Ok(CausalEventKind::AgentRevoke),
        "enable" => Ok(CausalEventKind::Enable),
        "disable" => Ok(CausalEventKind::Disable),
        "suspend" => Ok(CausalEventKind::Suspend),
        "resume" => Ok(CausalEventKind::Resume),
        "device-retire" => Ok(CausalEventKind::DeviceRetire),
        "trash" => Ok(CausalEventKind::Trash),
        "restore" => Ok(CausalEventKind::Restore),
        "purge-item" => Ok(CausalEventKind::PurgeItem),
        "purge-revisions" => Ok(CausalEventKind::PurgeRevisions),
        "join" => Ok(CausalEventKind::Join),
        "checkpoint-cache" => Ok(CausalEventKind::CheckpointCache),
        "audit-purge" => Ok(CausalEventKind::AuditPurge),
        _ => Err(ReductionError::InvalidEvent),
    }
}
fn open_connection(path: &Path) -> Result<rusqlite::Connection, ReductionError> {
    let c = rusqlite::Connection::open(path)?;
    crate::configure_platform_durability(&c)?;
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")?;
    Ok(c)
}
fn sql_i64(v: u64) -> Result<i64, ReductionError> {
    i64::try_from(v).map_err(|_| ReductionError::InvalidEvent)
}
fn fixed<const N: usize>(v: &[u8]) -> Result<[u8; N], ReductionError> {
    v.try_into().map_err(|_| ReductionError::Integrity)
}
fn decode_fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], ReductionError> {
    d.bytes()
        .map_err(|_| ReductionError::InvalidEvent)?
        .try_into()
        .map_err(|_| ReductionError::InvalidEvent)
}
fn decode_optional_fixed<const N: usize>(
    d: &mut Decoder<'_>,
) -> Result<Option<[u8; N]>, ReductionError> {
    if d.datatype().map_err(|_| ReductionError::InvalidEvent)? == Type::Null {
        d.null().map_err(|_| ReductionError::InvalidEvent)?;
        Ok(None)
    } else {
        Ok(Some(decode_fixed(d)?))
    }
}
fn decode_optional_u64(d: &mut Decoder<'_>) -> Result<Option<u64>, ReductionError> {
    if d.datatype().map_err(|_| ReductionError::InvalidEvent)? == Type::Null {
        d.null().map_err(|_| ReductionError::InvalidEvent)?;
        Ok(None)
    } else {
        d.u64().map(Some).map_err(|_| ReductionError::InvalidEvent)
    }
}
fn definite_array(d: &mut Decoder<'_>, max: usize) -> Result<usize, ReductionError> {
    let n = d
        .array()
        .map_err(|_| ReductionError::InvalidEvent)?
        .ok_or(ReductionError::InvalidEvent)?;
    let n = usize::try_from(n).map_err(|_| ReductionError::ResourceLimit)?;
    if n > max {
        return Err(ReductionError::ResourceLimit);
    }
    Ok(n)
}
fn decode_array_fixed<const N: usize>(
    d: &mut Decoder<'_>,
    max: usize,
) -> Result<Vec<[u8; N]>, ReductionError> {
    let n = definite_array(d, max)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(decode_fixed(d)?);
    }
    Ok(out)
}
fn expect_map(d: &mut Decoder<'_>, n: u64) -> Result<(), ReductionError> {
    if d.map().map_err(|_| ReductionError::InvalidEvent)? == Some(n) {
        Ok(())
    } else {
        Err(ReductionError::InvalidEvent)
    }
}
fn expect_key(d: &mut Decoder<'_>, key: &str) -> Result<(), ReductionError> {
    if d.str().map_err(|_| ReductionError::InvalidEvent)? == key {
        Ok(())
    } else {
        Err(ReductionError::InvalidEvent)
    }
}
fn encode_ids32_value(values: &[[u8; 32]]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    encode_ids32(&mut e, values);
    e.into_writer()
}
