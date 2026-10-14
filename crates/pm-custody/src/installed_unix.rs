// SPDX-License-Identifier: AGPL-3.0-only

//! Installed local policy, separate from synced human authority. A running
//! daemon pins file identity as well as contents; changes require a restart.
use super::*;
use std::path::{Component, PathBuf};

pub(super) const REGISTRY_MAGIC: &[u8] = b"PMAR1";

#[derive(Clone)]
pub(super) struct Registry {
    pub(super) entries: Vec<(Vec<u8>, u32)>,
}

pub(super) fn sidecar(vault: &Path, suffix: &str) -> PathBuf {
    let mut value = vault.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

// No symlink components or attacker-writable ancestors. A root-owned sticky
// ancestor (e.g. /tmp in the documented UID-mapped lab) protects child names.
fn safe_parent(path: &Path) -> Result<(), Failure> {
    if !path.is_absolute() {
        return Err(Failure::Unavailable);
    }
    // The filesystem root is the trusted traversal anchor. In the documented
    // subordinate-UID namespace its owner is intentionally unmapped, while
    // administrative UID 0 owns the disposable installation root.
    let root_owner = fs::metadata("/").map_err(|_| Failure::Unavailable)?.uid();
    let mut prefix = PathBuf::new();
    for component in path.parent().ok_or(Failure::Unavailable)?.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(Failure::Unavailable);
        }
        prefix.push(component);
        let m = fs::symlink_metadata(&prefix).map_err(|_| Failure::Unavailable)?;
        if !m.is_dir()
            || ![0, current_uid(), root_owner].contains(&m.uid())
            || (m.mode() & 0o022 != 0 && !(m.uid() == root_owner && m.mode() & 0o1000 != 0))
        {
            return Err(Failure::Unavailable);
        }
    }
    Ok(())
}

fn stamp(m: &fs::Metadata) -> [u8; 48] {
    let mut value = [0; 48];
    for (part, number) in value.chunks_exact_mut(8).zip([
        m.dev(),
        m.ino(),
        m.len(),
        m.ctime() as u64,
        m.ctime_nsec() as u64,
        u64::from(m.mode()),
    ]) {
        part.copy_from_slice(&number.to_be_bytes());
    }
    value
}

pub(super) fn read_installed(path: &Path) -> Result<(Vec<u8>, [u8; 32]), Failure> {
    safe_parent(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Failure::Unavailable)?;
    let before = file.metadata().map_err(|_| Failure::Unavailable)?;
    if !before.is_file()
        || before.uid() != current_uid()
        || before.mode() & 0o7777 != 0o400
        || before.nlink() != 1
        || !(1..=MAX_PROTECTED_BYTES).contains(&before.len())
    {
        return Err(Failure::Unavailable);
    }
    let mut bytes = vec![0; usize::try_from(before.len()).map_err(|_| Failure::Unavailable)?];
    file.read_exact(&mut bytes)
        .map_err(|_| Failure::Unavailable)?;
    let mut extra = [0];
    let after = file.metadata().map_err(|_| Failure::Unavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| Failure::Unavailable)?;
    if file.read(&mut extra).map_err(|_| Failure::Unavailable)? != 0
        || stamp(&before) != stamp(&after)
        || stamp(&before) != stamp(&named)
        || named.uid() != current_uid()
        || named.nlink() != 1
    {
        return Err(Failure::Unavailable);
    }
    let hash = crate::custody_admission::fingerprint_parts(&[&stamp(&before), &bytes])?;
    Ok((bytes, hash))
}

pub(super) fn fingerprint(path: &Path) -> Result<[u8; 32], Failure> {
    Ok(read_installed(path)?.1)
}

pub(super) fn identity(vault: &Path) -> Result<[u8; 16], Failure> {
    Ok(*pm_vault::open_vault_identity(vault)
        .map_err(|_| Failure::Unavailable)?
        .trusted_root()
        .vault_id())
}

pub(super) fn header<'a>(
    bytes: &'a [u8],
    magic: &[u8],
    vault: &Path,
    device: [u8; 16],
    bootstrap: &Bootstrap,
) -> Result<(Cursor<'a>, usize), Failure> {
    let mut c = Cursor::new(bytes);
    c.expect(magic)?;
    if c.fixed(16)? != identity(vault)?
        || c.fixed(16)? != device
        || c.fixed(SPKI_BYTES)? != bootstrap.server.spki
    {
        return Err(Failure::Unavailable);
    }
    let count = u16::from_be_bytes(c.fixed(2)?.try_into().map_err(|_| Failure::Unavailable)?);
    if count == 0 {
        return Err(Failure::Unavailable);
    }
    Ok((c, usize::from(count)))
}

pub(super) fn encode_header(
    magic: &[u8],
    vault: &Path,
    device: [u8; 16],
    bootstrap: &Bootstrap,
    count: usize,
) -> Result<Vec<u8>, Failure> {
    let mut bytes = magic.to_vec();
    bytes.extend_from_slice(&identity(vault)?);
    bytes.extend_from_slice(&device);
    bytes.extend_from_slice(&bootstrap.server.spki);
    bytes.extend_from_slice(
        &u16::try_from(count)
            .map_err(|_| Failure::Unavailable)?
            .to_be_bytes(),
    );
    Ok(bytes)
}

impl Registry {
    pub(super) fn parse(
        bytes: &[u8],
        vault: &Path,
        device: [u8; 16],
        bootstrap: &Bootstrap,
    ) -> Result<Self, Failure> {
        let (mut c, count) = header(bytes, REGISTRY_MAGIC, vault, device, bootstrap)?;
        // Cardinality is constrained by actual serialized bytes (16 KiB), not
        // by an independent arbitrary agent-count limit.
        if count > bytes.len() / (SPKI_BYTES + 4) {
            return Err(Failure::Unavailable);
        }
        let mut entries: Vec<(Vec<u8>, u32)> = Vec::with_capacity(count);
        for _ in 0..count {
            let key = c.fixed(SPKI_BYTES)?.to_vec();
            let uid = c.u32()?;
            validate_spki(&key)?;
            if uid == 0
                || uid == current_uid()
                || uid == bootstrap.human_uid
                || key == bootstrap.human_spki
                || key == bootstrap.server.spki
                || entries.iter().any(|(k, _)| k == &key)
            {
                return Err(Failure::Unavailable);
            }
            entries.push((key, uid));
        }
        c.finish()?;
        if !entries
            .iter()
            .any(|(key, uid)| key == &bootstrap.agent_spki && *uid == bootstrap.agent_uid)
        {
            return Err(Failure::Unavailable);
        }
        Ok(Self { entries })
    }

    pub(super) fn keys_for(&self, uid: u32) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter(|(_, u)| *u == uid)
            .map(|(key, _)| key.clone())
            .collect()
    }
}

// Publish a fully synced file without replacing anything. Temp and destination
// share a protected parent. The link is atomic and create-only; cleanup failures
// propagate. Bootstrap and vault data are never rewritten.
pub(super) fn publish(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    safe_parent(path)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PROTECTED_BYTES {
        return Err(Failure::Unavailable);
    }
    let temporary = path.with_extension(format!(
        "install-{}",
        hex(&pm_crypto::random_id().map_err(|_| Failure::Unavailable)?)
    ));
    write_new(&temporary, bytes, 0o400)?;
    let result = fs::hard_link(&temporary, path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Failure::DestinationExists
        } else {
            Failure::Unavailable
        }
    });
    let cleanup = fs::remove_file(&temporary);
    if let Err(error) = result {
        return Err(error.after_owned_path_cleanup(cleanup));
    }
    cleanup.map_err(|_| Failure::Unavailable)?;
    File::open(path.parent().ok_or(Failure::Unavailable)?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| Failure::Unavailable)
}

pub(super) fn migrate(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), Failure> {
    let bootstrap_path = take_path(arguments, "--bootstrap")?;
    let vault = take_path(arguments, "--vault")?;
    let device = decode_hex_16(&take_path(arguments, "--device")?)?;
    let bootstrap = read_bootstrap(&bootstrap_path)?;
    let custody = Arc::new(
        AuditDeviceCustody::from_protected_bytes(&read_regular(
            &sidecar(&vault, ".audit-custody"),
            current_uid(),
            0o400,
        )?)
        .map_err(|_| Failure::Unavailable)?,
    );
    let delegated =
        DelegatedVault::open(&vault, device, custody).map_err(|_| Failure::Unavailable)?;
    let mut entries = vec![(bootstrap.agent_spki.clone(), bootstrap.agent_uid)];
    while let Some(flag) = arguments.next() {
        if flag != "--agent-public" {
            return Err(Failure::Usage);
        }
        let key = read_public(&std::path::PathBuf::from(
            arguments.next().ok_or(Failure::Usage)?,
        ))?;
        let uid = take_u32(arguments, "--agent-uid")?;
        entries.push((key, uid));
    }
    // Existing verified human grants are mandatory; a revoked or unknown key
    // cannot be silently reactivated by a local migration.
    for (key, _) in &entries {
        let peer =
            pm_vault::AgentPeer::from_transport_rpk(key).map_err(|_| Failure::Unavailable)?;
        delegated
            .agent_identity(&peer)
            .map_err(|_| Failure::Unavailable)?;
    }
    let mut bytes = encode_header(REGISTRY_MAGIC, &vault, device, &bootstrap, entries.len())?;
    for (key, uid) in entries {
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&uid.to_be_bytes());
    }
    Registry::parse(&bytes, &vault, device, &bootstrap)?;
    publish(&sidecar(&vault, ".agent-registry"), &bytes)
}
