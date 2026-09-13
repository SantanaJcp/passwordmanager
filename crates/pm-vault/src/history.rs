// SPDX-License-Identifier: AGPL-3.0-only

//! Human-visible revision history and explicit purge scopes.

use crate::{ItemLifecycle, PreparedHumanCommand};

/// One authenticated immutable revision in an item's retained history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryEntry {
    pub(crate) revision_id: [u8; 16],
    pub(crate) modified_at_us: i64,
    pub(crate) issuer_device: [u8; 16],
    pub(crate) visible: bool,
    pub(crate) attachment_count: usize,
}

impl HistoryEntry {
    #[must_use]
    pub const fn revision_id(&self) -> &[u8; 16] {
        &self.revision_id
    }
    #[must_use]
    pub const fn modified_at_us(&self) -> i64 {
        self.modified_at_us
    }
    #[must_use]
    pub const fn issuer_device(&self) -> &[u8; 16] {
        &self.issuer_device
    }
    #[must_use]
    pub const fn visible(&self) -> bool {
        self.visible
    }
    #[must_use]
    pub const fn attachment_count(&self) -> usize {
        self.attachment_count
    }
}

/// Lifecycle and retained revisions visible to an unlocked human.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemHistory {
    pub(crate) lifecycle: ItemLifecycle,
    pub(crate) entries: Vec<HistoryEntry>,
}

impl ItemHistory {
    #[must_use]
    pub const fn lifecycle(&self) -> ItemLifecycle {
        self.lifecycle
    }
    #[must_use]
    pub fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }
}

/// Exact content scope shown before an irreversible human purge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemPurgeScope {
    pub(crate) item_id: [u8; 16],
    pub(crate) revision_ids: Vec<[u8; 16]>,
    pub(crate) attachment_count: usize,
    pub(crate) encrypted_bytes: u64,
    pub(crate) terminal: bool,
}

impl ItemPurgeScope {
    #[must_use]
    pub const fn item_id(&self) -> &[u8; 16] {
        &self.item_id
    }
    #[must_use]
    pub fn revision_ids(&self) -> &[[u8; 16]] {
        &self.revision_ids
    }
    #[must_use]
    pub const fn attachment_count(&self) -> usize {
        self.attachment_count
    }
    #[must_use]
    pub const fn encrypted_bytes(&self) -> u64 {
        self.encrypted_bytes
    }
    #[must_use]
    pub const fn terminal(&self) -> bool {
        self.terminal
    }
}

/// Signed command plus the immutable scope presented to the human.
pub struct PreparedItemPurge {
    pub(crate) prepared: PreparedHumanCommand,
    pub(crate) scope: ItemPurgeScope,
}

impl PreparedItemPurge {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedHumanCommand {
        &self.prepared
    }
    #[must_use]
    pub const fn scope(&self) -> &ItemPurgeScope {
        &self.scope
    }
}
