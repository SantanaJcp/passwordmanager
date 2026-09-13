// SPDX-License-Identifier: AGPL-3.0-only

//! Strict, non-extracting 1PUX v3 reader and loss-visible logical mapping.

use pm_crypto::{DigestState, random_id};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;
use zip::{CompressionMethod, ZipArchive};

use crate::{
    Attachment, AuthRecord, CsvRowPreview, CsvRowStatus, CustomField, Destination,
    HumanCommitError, HumanMetadata, LogicalRecord, LogicalValue, RecordKind, SourceEncoding,
    SourceField, migration::parse_totp,
};

const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024 * 1024 + 256 * 1024 * 1024;
const MAX_LOGICAL_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_DATA_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ATTRIBUTES_BYTES: u64 = 64 * 1024;
const MAX_FILES: usize = 100_000;
const MAX_JSON_STRING: usize = 1024 * 1024;
const MAX_JSON_VALUES: usize = 1_000_000;
const MAX_FILE: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceIdentity {
    device: u64,
    inode: u64,
    length: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct AttachmentSource {
    pub(crate) id: [u8; 16],
    pub(crate) entry: String,
    pub(crate) size: u64,
    pub(crate) digest: [u8; 32],
}

pub struct OnePuxImportPreview {
    pub(crate) records: Vec<LogicalRecord>,
    pub(crate) rows: Vec<CsvRowPreview>,
    pub(crate) attachments: Vec<Vec<AttachmentSource>>,
    pub(crate) source: Source,
    pub(crate) identity: SourceIdentity,
}

pub(crate) enum Source {
    Path(PathBuf),
    Descriptor(File),
}

impl Source {
    fn open(&self) -> Result<File, HumanCommitError> {
        match self {
            Self::Path(path) => OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| HumanCommitError::InvalidInput),
            Self::Descriptor(file) => file.try_clone().map_err(HumanCommitError::Io),
        }
    }
}

pub struct OnePuxRecordPreview<'a> {
    record: &'a LogicalRecord,
    row: &'a CsvRowPreview,
}

impl OnePuxRecordPreview<'_> {
    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.record.kind()
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.record.human().title
    }
    #[must_use]
    pub const fn preserved_fields(&self) -> usize {
        self.row.unknown_fields
    }
    #[must_use]
    pub fn attachment_count(&self) -> usize {
        self.record.attachments().len()
    }
}

impl OnePuxImportPreview {
    #[must_use]
    pub fn total(&self) -> usize {
        self.rows.len()
    }
    /// Returns one bounded page using the common import row classification.
    ///
    /// # Errors
    /// Rejects a zero/oversized page or an offset outside the preview.
    pub fn page(&self, offset: usize, limit: usize) -> Result<&[CsvRowPreview], HumanCommitError> {
        if limit == 0 || limit > 100 || offset > self.rows.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(&self.rows[offset..self.rows.len().min(offset + limit)])
    }
    /// Returns bounded human-visible details without revealing imported secrets.
    ///
    /// # Errors
    /// Rejects an index outside the preview.
    pub fn record(&self, index: usize) -> Result<OnePuxRecordPreview<'_>, HumanCommitError> {
        Ok(OnePuxRecordPreview {
            record: self
                .records
                .get(index)
                .ok_or(HumanCommitError::InvalidInput)?,
            row: self.rows.get(index).ok_or(HumanCommitError::InvalidInput)?,
        })
    }
}

struct Entry {
    name: String,
    size: u64,
    digest: [u8; 32],
}

struct ArchiveInventory {
    attributes: Vec<u8>,
    data: Vec<u8>,
    entries: Vec<Entry>,
}

pub(crate) fn preview(path: &Path) -> Result<OnePuxImportPreview, HumanCommitError> {
    preview_source(Source::Path(path.to_owned()))
}

pub(crate) fn preview_file(file: File) -> Result<OnePuxImportPreview, HumanCommitError> {
    preview_source(Source::Descriptor(file))
}

fn preview_source(source: Source) -> Result<OnePuxImportPreview, HumanCommitError> {
    let (mut file, identity) = open_source(&source)?;
    let declared_entries = declared_entry_count(&mut file)?;
    if declared_entries > MAX_FILES + 2 {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut archive = ZipArchive::new(file).map_err(invalid)?;
    if archive.len() != declared_entries || archive.has_overlapping_files().map_err(invalid)? {
        return Err(HumanCommitError::InvalidInput);
    }
    let ArchiveInventory {
        attributes,
        data,
        entries,
    } = inspect_archive(&mut archive)?;
    validate_attributes(&attributes)?;
    let root = JsonParser::parse(&data)?;
    let mut used_files = BTreeSet::new();
    let mut external_ids = BTreeSet::new();
    let mut records = Vec::new();
    let mut attachment_sets = Vec::new();
    parse_accounts(
        &root,
        &entries,
        &mut used_files,
        &mut external_ids,
        &mut records,
        &mut attachment_sets,
    )?;
    for entry in entries
        .iter()
        .filter(|entry| entry.name.starts_with("files/"))
    {
        if used_files.insert(entry.name.clone()) {
            let id = random_id().map_err(|_| HumanCommitError::RandomUnavailable)?;
            let name = entry
                .name
                .strip_prefix("files/")
                .and_then(|name| name.split_once("___").map(|(_, suffix)| suffix))
                .unwrap_or_else(|| entry.name.strip_prefix("files/").unwrap_or("unreferenced"));
            let attachment = Attachment::descriptor(
                id,
                name,
                "application/octet-stream",
                entry.size,
                entry.digest,
            )?;
            let record = LogicalRecord::new_streaming(
                RecordKind::File,
                HumanMetadata {
                    title: format!("Unreferenced 1PUX file: {name}"),
                    destinations: Vec::new(),
                    tags: vec!["source:unreferenced".into()],
                    favorite: false,
                    notes: String::new(),
                    fields: Vec::new(),
                    source_fields: vec![SourceField {
                        path: "1pux.unreferenced_file".into(),
                        encoding: SourceEncoding::Utf8,
                        value: entry.name.as_bytes().to_vec(),
                    }],
                },
                Vec::new(),
                vec![attachment],
            )?;
            records.push(record);
            attachment_sets.push(vec![AttachmentSource {
                id,
                entry: entry.name.clone(),
                size: entry.size,
                digest: entry.digest,
            }]);
        }
    }
    if records.is_empty() || records.len() > MAX_JSON_VALUES {
        return Err(HumanCommitError::InvalidInput);
    }
    let rows = records
        .iter()
        .enumerate()
        .map(|(index, record)| CsvRowPreview {
            ordinal: index + 1,
            status: CsvRowStatus::New,
            unknown_fields: record.human().source_fields.len(),
            duplicate_item: None,
        })
        .collect();
    verify_source(&source, &identity)?;
    Ok(OnePuxImportPreview {
        records,
        rows,
        attachments: attachment_sets,
        source,
        identity,
    })
}

pub(crate) fn stream_entry(
    source_handle: &Source,
    identity: &SourceIdentity,
    source: &AttachmentSource,
    consume: impl FnOnce(&mut dyn Read) -> Result<(), HumanCommitError>,
) -> Result<(), HumanCommitError> {
    let (file, actual) = open_source(source_handle)?;
    if &actual != identity {
        return Err(HumanCommitError::StateChanged);
    }
    let mut archive = ZipArchive::new(file).map_err(invalid)?;
    let mut entry = archive.by_name(&source.entry).map_err(invalid)?;
    if entry.size() != source.size || !entry.is_file() {
        return Err(HumanCommitError::StateChanged);
    }
    consume(&mut entry)?;
    drop(entry);
    verify_source(source_handle, identity)
}

pub(crate) fn verify_source(
    source: &Source,
    expected: &SourceIdentity,
) -> Result<(), HumanCommitError> {
    let (_, actual) = open_source(source)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(HumanCommitError::StateChanged)
    }
}

pub(crate) fn ensure_staging_capacity(
    vault_path: &Path,
    logical_bytes: u64,
    file_count: usize,
) -> Result<(), HumanCommitError> {
    let required = required_capacity(logical_bytes, file_count)?;
    let path = CString::new(vault_path.as_os_str().as_bytes())
        .map_err(|_| HumanCommitError::InvalidInput)?;
    // SAFETY: `path` is NUL-terminated and `status` is valid writable storage.
    let available = unsafe {
        let mut status: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(path.as_ptr(), &raw mut status) != 0 {
            return Err(HumanCommitError::Io(std::io::Error::last_os_error()));
        }
        filesystem_available_bytes(status.f_bavail, status.f_frsize)?
    };
    if available < required {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(())
}

fn filesystem_available_bytes<B, F>(
    available_blocks: B,
    fragment_size: F,
) -> Result<u64, HumanCommitError>
where
    B: TryInto<u64>,
    F: TryInto<u64>,
{
    let available_blocks = available_blocks
        .try_into()
        .map_err(|_| HumanCommitError::InvalidInput)?;
    let fragment_size = fragment_size
        .try_into()
        .map_err(|_| HumanCommitError::InvalidInput)?;
    available_blocks
        .checked_mul(fragment_size)
        .ok_or(HumanCommitError::InvalidInput)
}

fn required_capacity(logical_bytes: u64, file_count: usize) -> Result<u64, HumanCommitError> {
    let files = u64::try_from(file_count).map_err(|_| HumanCommitError::InvalidInput)?;
    let chunks = logical_bytes.div_ceil(1024 * 1024).saturating_add(files);
    logical_bytes
        .checked_mul(3)
        .and_then(|value| value.checked_add(chunks.saturating_mul(128)))
        .and_then(|value| value.checked_add(64 * 1024 * 1024))
        .ok_or(HumanCommitError::InvalidInput)
}

pub(crate) fn same_import_content(left: &LogicalRecord, right: &LogicalRecord) -> bool {
    let left_human = left.human();
    let right_human = right.human();
    left.kind() == right.kind()
        && left.auth() == right.auth()
        && left_human.title == right_human.title
        && left_human.destinations == right_human.destinations
        && left_human.tags == right_human.tags
        && left_human.favorite == right_human.favorite
        && left_human.notes == right_human.notes
        && left_human.source_fields == right_human.source_fields
        && left_human.fields.len() == right_human.fields.len()
        && left_human
            .fields
            .iter()
            .zip(&right_human.fields)
            .all(|(left, right)| {
                left.label == right.label
                    && left.value == right.value
                    && left.concealed == right.concealed
            })
        && left.attachments().len() == right.attachments().len()
        && left
            .attachments()
            .iter()
            .zip(right.attachments())
            .all(|(left, right)| {
                left.name() == right.name()
                    && left.mime() == right.mime()
                    && left.size() == right.size()
                    && left.sha256() == right.sha256()
            })
}

pub(crate) fn same_external_identity(left: &LogicalRecord, right: &LogicalRecord) -> bool {
    provenance(left).is_some() && provenance(left) == provenance(right)
}

fn provenance(record: &LogicalRecord) -> Option<&[u8]> {
    record
        .human()
        .source_fields
        .iter()
        .find(|field| field.path == "1pux.provenance")
        .map(|field| field.value.as_slice())
}

fn open_source(source: &Source) -> Result<(File, SourceIdentity), HumanCommitError> {
    let mut file = source.open()?;
    file.seek(SeekFrom::Start(0))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_ARCHIVE_BYTES
    {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut state = DigestState::new()?;
    let mut buffer = Zeroizing::new(vec![0_u8; 1024 * 1024]);
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        state.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((
        file,
        SourceIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            digest: state.finish(),
        },
    ))
}

fn inspect_archive(archive: &mut ZipArchive<File>) -> Result<ArchiveInventory, HumanCommitError> {
    if archive.len() > MAX_FILES + 2 {
        return Err(HumanCommitError::InvalidInput);
    }
    let mut names = BTreeSet::new();
    let mut total = 0_u64;
    let mut attributes = None;
    let mut data = None;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(invalid)?;
        let name = validate_entry(&entry)?;
        if !names.insert(name.clone()) {
            return Err(HumanCommitError::InvalidInput);
        }
        if entry.is_dir() {
            if name != "files/" {
                return Err(HumanCommitError::InvalidInput);
            }
            continue;
        }
        let size = entry.size();
        total = add_logical_size(total, size).ok_or(HumanCommitError::InvalidInput)?;
        if !decompression_ratio_allowed(size, entry.compressed_size()) {
            return Err(HumanCommitError::InvalidInput);
        }
        let limit = match name.as_str() {
            "export.attributes" => MAX_ATTRIBUTES_BYTES,
            "export.data" => MAX_DATA_BYTES,
            name if name.starts_with("files/") => MAX_FILE,
            _ => return Err(HumanCommitError::InvalidInput),
        };
        if size > limit {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut state = DigestState::new()?;
        let capacity = usize::try_from(size.min(limit).min(MAX_DATA_BYTES))
            .map_err(|_| HumanCommitError::InvalidInput)?;
        let mut captured = if matches!(name.as_str(), "export.attributes" | "export.data") {
            Vec::with_capacity(capacity)
        } else {
            Vec::new()
        };
        let mut prefix = [0_u8; 4];
        let mut read = 0_u64;
        let mut buffer = Zeroizing::new(vec![0_u8; 1024 * 1024]);
        loop {
            let count = entry.read(&mut buffer).map_err(invalid)?;
            if count == 0 {
                break;
            }
            if read < 4 {
                let offset = usize::try_from(read).map_err(|_| HumanCommitError::InvalidInput)?;
                let copy = count.min(4 - offset);
                prefix[offset..offset + copy].copy_from_slice(&buffer[..copy]);
            }
            read = read
                .checked_add(u64::try_from(count).map_err(|_| HumanCommitError::InvalidInput)?)
                .filter(|read| *read <= limit)
                .ok_or(HumanCommitError::InvalidInput)?;
            state.update(&buffer[..count]);
            captured.extend_from_slice(
                if matches!(name.as_str(), "export.attributes" | "export.data") {
                    &buffer[..count]
                } else {
                    &[]
                },
            );
        }
        if read != size {
            return Err(HumanCommitError::InvalidInput);
        }
        if name.starts_with("files/") && &prefix[..2] == b"PK" {
            return Err(HumanCommitError::InvalidInput);
        }
        let value = Entry {
            name: name.clone(),
            size,
            digest: state.finish(),
        };
        match name.as_str() {
            "export.attributes" => attributes = Some(captured),
            "export.data" => data = Some(captured),
            _ => entries.push(value),
        }
    }
    Ok(ArchiveInventory {
        attributes: attributes.ok_or(HumanCommitError::InvalidInput)?,
        data: data.ok_or(HumanCommitError::InvalidInput)?,
        entries,
    })
}

fn add_logical_size(total: u64, size: u64) -> Option<u64> {
    total
        .checked_add(size)
        .filter(|total| *total <= MAX_LOGICAL_BYTES)
}

const fn decompression_ratio_allowed(size: u64, compressed: u64) -> bool {
    size == 0 || (compressed > 0 && size <= compressed.saturating_mul(100))
}

fn declared_entry_count(file: &mut File) -> Result<usize, HumanCommitError> {
    let length = file.metadata()?.len();
    let tail_length =
        usize::try_from(length.min(65_557)).map_err(|_| HumanCommitError::InvalidInput)?;
    file.seek(SeekFrom::End(
        -i64::try_from(tail_length).map_err(|_| HumanCommitError::InvalidInput)?,
    ))?;
    let mut tail = vec![0_u8; tail_length];
    file.read_exact(&mut tail)?;
    let eocd = (0..=tail.len().saturating_sub(22))
        .rev()
        .find(|offset| {
            tail[*offset..].starts_with(b"PK\x05\x06")
                && usize::from(u16::from_le_bytes([tail[*offset + 20], tail[*offset + 21]]))
                    == tail.len() - *offset - 22
        })
        .ok_or(HumanCommitError::InvalidInput)?;
    let count = u16::from_le_bytes([tail[eocd + 10], tail[eocd + 11]]);
    if count != u16::MAX {
        file.seek(SeekFrom::Start(0))?;
        return Ok(usize::from(count));
    }
    if eocd < 20 || !tail[eocd - 20..].starts_with(b"PK\x06\x07") {
        return Err(HumanCommitError::InvalidInput);
    }
    let offset = u64::from_le_bytes(
        tail[eocd - 12..eocd - 4]
            .try_into()
            .map_err(|_| HumanCommitError::InvalidInput)?,
    );
    file.seek(SeekFrom::Start(offset))?;
    let mut zip64 = [0_u8; 40];
    file.read_exact(&mut zip64)?;
    if !zip64.starts_with(b"PK\x06\x06") {
        return Err(HumanCommitError::InvalidInput);
    }
    let count = u64::from_le_bytes(
        zip64[32..40]
            .try_into()
            .map_err(|_| HumanCommitError::InvalidInput)?,
    );
    file.seek(SeekFrom::Start(0))?;
    usize::try_from(count).map_err(|_| HumanCommitError::InvalidInput)
}

fn validate_entry(entry: &zip::read::ZipFile<'_, File>) -> Result<String, HumanCommitError> {
    if entry.encrypted()
        || !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        )
        || entry.name_raw().contains(&0)
    {
        return Err(HumanCommitError::InvalidInput);
    }
    let name = std::str::from_utf8(entry.name_raw()).map_err(|_| HumanCommitError::InvalidInput)?;
    if name.contains('\\') || name.starts_with('/') || name.contains("//") {
        return Err(HumanCommitError::InvalidInput);
    }
    let path = Path::new(name);
    if path.components().any(|component| {
        !(matches!(component, Component::Normal(_))
            || component == Component::CurDir && name == "files/")
    }) || entry.enclosed_name().as_deref() != Some(path)
    {
        return Err(HumanCommitError::InvalidInput);
    }
    if let Some(mode) = entry.unix_mode()
        && !zip_mode_is_supported(mode, libc::S_IFMT, libc::S_IFREG, libc::S_IFDIR)?
    {
        return Err(HumanCommitError::InvalidInput);
    }
    if entry.is_symlink() || (!entry.is_file() && !entry.is_dir()) {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(name.to_owned())
}

fn zip_mode_is_supported<M, R, D>(
    mode: u32,
    file_type_mask: M,
    regular_file: R,
    directory: D,
) -> Result<bool, HumanCommitError>
where
    M: TryInto<u32>,
    R: TryInto<u32>,
    D: TryInto<u32>,
{
    let file_type_mask = file_type_mask
        .try_into()
        .map_err(|_| HumanCommitError::InvalidInput)?;
    let regular_file = regular_file
        .try_into()
        .map_err(|_| HumanCommitError::InvalidInput)?;
    let directory = directory
        .try_into()
        .map_err(|_| HumanCommitError::InvalidInput)?;
    let kind = mode & file_type_mask;
    Ok(kind == 0 || kind == regular_file || kind == directory)
}

fn validate_attributes(bytes: &[u8]) -> Result<(), HumanCommitError> {
    let value = JsonParser::parse(bytes)?;
    let object = value.object()?;
    if object.get("version").and_then(Json::integer) != Some(3) {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_accounts(
    root: &Json,
    entries: &[Entry],
    used_files: &mut BTreeSet<String>,
    external_ids: &mut BTreeSet<String>,
    records: &mut Vec<LogicalRecord>,
    attachment_sets: &mut Vec<Vec<AttachmentSource>>,
) -> Result<(), HumanCommitError> {
    let accounts = root
        .object()?
        .get("accounts")
        .ok_or(HumanCommitError::InvalidInput)?
        .array()?;
    for account in accounts {
        let account = account.object()?;
        let account_id = required_string(required_object(account, "attrs")?, "uuid")?;
        let vaults = account
            .get("vaults")
            .ok_or(HumanCommitError::InvalidInput)?
            .array()?;
        for vault in vaults {
            let vault = vault.object()?;
            let vault_id = required_string(required_object(vault, "attrs")?, "uuid")?;
            let items = vault
                .get("items")
                .ok_or(HumanCommitError::InvalidInput)?
                .array()?;
            for item in items {
                let item_id = required_string(item.object()?, "uuid")?;
                let identity = format!("{account_id}/{vault_id}/{item_id}");
                if !external_ids.insert(identity) {
                    return Err(HumanCommitError::InvalidInput);
                }
                let (record, sources) = map_item(account_id, vault_id, item, entries, used_files)?;
                records.push(record);
                attachment_sets.push(sources);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn map_item(
    account: &str,
    vault: &str,
    item: &Json,
    entries: &[Entry],
    used_files: &mut BTreeSet<String>,
) -> Result<(LogicalRecord, Vec<AttachmentSource>), HumanCommitError> {
    let object = item.object()?;
    let item_id = required_string(object, "uuid")?;
    let overview = required_object(object, "overview")?;
    let details = required_object(object, "details")?;
    let title = overview
        .get("title")
        .and_then(Json::string)
        .unwrap_or("")
        .to_owned();
    let mut destinations = Vec::new();
    if let Some(url) = overview.get("url").and_then(Json::string) {
        push_destination(&mut destinations, "primary", url);
    }
    if let Some(urls) = overview.get("urls") {
        for value in urls.array()? {
            let value = value.object()?;
            push_destination(
                &mut destinations,
                value.get("label").and_then(Json::string).unwrap_or(""),
                required_string(value, "url")?,
            );
        }
    }
    let mut tags = overview
        .get("tags")
        .map(|tags| {
            tags.array()?
                .iter()
                .map(|tag| {
                    tag.string()
                        .map(ToOwned::to_owned)
                        .ok_or(HumanCommitError::InvalidInput)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    if object.get("state").and_then(Json::string) == Some("archived") {
        tags.push("source:archived".into());
    }
    let mut seen_tags = BTreeSet::new();
    tags.retain(|tag| seen_tags.insert(tag.clone()));
    let favorite = object.get("favIndex").and_then(Json::integer).unwrap_or(0) > 0;
    let notes = details
        .get("notesPlain")
        .and_then(Json::string)
        .unwrap_or("")
        .to_owned();
    let mut source_fields = vec![SourceField {
        path: "1pux.raw_item".into(),
        encoding: SourceEncoding::Json,
        value: item.canonical(),
    }];
    let mut provenance = BTreeMap::new();
    provenance.insert("account".to_owned(), Json::String(account.to_owned()));
    provenance.insert("vault".to_owned(), Json::String(vault.to_owned()));
    provenance.insert("item".to_owned(), Json::String(item_id.to_owned()));
    for key in ["createdAt", "updatedAt", "categoryUuid", "state"] {
        if let Some(value) = object.get(key) {
            provenance.insert(key.to_owned(), value.clone());
        }
    }
    source_fields.push(SourceField {
        path: "1pux.provenance".into(),
        encoding: SourceEncoding::Json,
        value: Json::Object(provenance).canonical(),
    });
    if let Some(history) = details.get("passwordHistory") {
        source_fields.push(SourceField {
            path: "1pux.passwordHistory".into(),
            encoding: SourceEncoding::Json,
            value: history.canonical(),
        });
    }
    if object.get("state").and_then(Json::string) == Some("archived") {
        source_fields.push(SourceField {
            path: "1pux.state".into(),
            encoding: SourceEncoding::Utf8,
            value: b"archived".to_vec(),
        });
    }
    let refs = (0..destinations.len())
        .map(|index| u16::try_from(index).map_err(|_| HumanCommitError::InvalidInput))
        .collect::<Result<Vec<_>, _>>()?;
    let (password, ambiguous) = login_auth(details, &refs)?;
    if let Some(raw) = ambiguous {
        source_fields.push(SourceField {
            path: "1pux.ambiguous_loginFields".into(),
            encoding: SourceEncoding::Json,
            value: raw,
        });
    }
    let (fields, totp) = section_fields(details, &refs, &mut source_fields)?;
    let mut attachment_sources = Vec::new();
    let mut attachments = Vec::new();
    if let Some(document) = details.get("documentAttributes") {
        let document = document.object()?;
        let document_id = required_string(document, "documentId")?;
        let size = u64::try_from(
            document
                .get("decryptedSize")
                .and_then(Json::integer)
                .ok_or(HumanCommitError::InvalidInput)?,
        )
        .map_err(|_| HumanCommitError::InvalidInput)?;
        let prefix = format!("files/{document_id}___");
        let matching = entries
            .iter()
            .filter(|entry| entry.name.starts_with(&prefix))
            .collect::<Vec<_>>();
        if matching.len() != 1
            || matching[0].size != size
            || !used_files.insert(matching[0].name.clone())
        {
            return Err(HumanCommitError::InvalidInput);
        }
        let id = random_id().map_err(|_| HumanCommitError::RandomUnavailable)?;
        let name = required_string(document, "fileName")?;
        attachments.push(Attachment::descriptor(
            id,
            name,
            "application/octet-stream",
            size,
            matching[0].digest,
        )?);
        attachment_sources.push(AttachmentSource {
            id,
            entry: matching[0].name.clone(),
            size,
            digest: matching[0].digest,
        });
    }
    let mut auth = Vec::new();
    let kind = if !attachments.is_empty() {
        RecordKind::File
    } else if let Some(password) = password {
        auth.push(password);
        if let Some(totp) = totp {
            auth.push(totp);
        }
        RecordKind::Password
    } else if let Some(totp) = totp {
        auth.push(totp);
        RecordKind::Totp
    } else {
        RecordKind::Note
    };
    if kind == RecordKind::File {
        auth.clear();
    }
    let human = HumanMetadata {
        title,
        destinations,
        tags,
        favorite,
        notes,
        fields,
        source_fields,
    };
    let record = if attachments.is_empty() {
        LogicalRecord::new(kind, human, auth, attachments)?
    } else {
        LogicalRecord::new_streaming(kind, human, auth, attachments)?
    };
    Ok((record, attachment_sources))
}

fn login_auth(
    details: &BTreeMap<String, Json>,
    refs: &[u16],
) -> Result<(Option<AuthRecord>, Option<Vec<u8>>), HumanCommitError> {
    let Some(fields) = details.get("loginFields") else {
        return Ok((None, None));
    };
    let values = fields.array()?;
    let mut usernames = Vec::new();
    let mut passwords = Vec::new();
    for field in values {
        let field = field.object()?;
        match field.get("designation").and_then(Json::string) {
            Some("username") => usernames.push(required_string(field, "value")?.to_owned()),
            Some("password") => {
                passwords.push(required_string(field, "value")?.as_bytes().to_vec());
            }
            _ => {}
        }
    }
    if usernames.len() > 1 || passwords.len() > 1 {
        return Ok((None, Some(fields.canonical())));
    }
    let Some(password) = passwords.pop() else {
        return Ok((None, None));
    };
    Ok((
        Some(AuthRecord::Password {
            username: usernames.pop().unwrap_or_default(),
            password,
            destination_refs: refs.to_vec(),
        }),
        None,
    ))
}

fn section_fields(
    details: &BTreeMap<String, Json>,
    refs: &[u16],
    sources: &mut Vec<SourceField>,
) -> Result<(Vec<CustomField>, Option<AuthRecord>), HumanCommitError> {
    let mut fields = Vec::new();
    let mut totp = None;
    let Some(sections) = details.get("sections") else {
        return Ok((fields, totp));
    };
    for section in sections.array()? {
        let section = section.object()?;
        let section_name = section
            .get("name")
            .and_then(Json::string)
            .unwrap_or("section");
        for value in section
            .get("fields")
            .ok_or(HumanCommitError::InvalidInput)?
            .array()?
        {
            let field = value.object()?;
            let label = field
                .get("title")
                .and_then(Json::string)
                .unwrap_or("")
                .to_owned();
            let value = field.get("value").ok_or(HumanCommitError::InvalidInput)?;
            if let Some(uri) = find_totp(value) {
                if totp.is_some() {
                    sources.push(SourceField {
                        path: format!("1pux.sections.{section_name}.ambiguous_totp"),
                        encoding: SourceEncoding::Json,
                        value: value.canonical(),
                    });
                } else if let Ok(parsed) = parse_totp(uri, refs) {
                    totp = Some(parsed);
                } else {
                    sources.push(SourceField {
                        path: format!("1pux.sections.{section_name}.invalid_totp"),
                        encoding: SourceEncoding::Json,
                        value: value.canonical(),
                    });
                }
                continue;
            }
            let (logical, concealed) = match value {
                Json::String(text) => (LogicalValue::Text(text.clone()), false),
                Json::Object(object) if object.len() == 1 => {
                    if let Some(text) = object.get("concealed").and_then(Json::string) {
                        (LogicalValue::Text(text.to_owned()), true)
                    } else {
                        sources.push(SourceField {
                            path: format!("1pux.sections.{section_name}.{label}"),
                            encoding: SourceEncoding::Json,
                            value: value.canonical(),
                        });
                        continue;
                    }
                }
                _ => {
                    sources.push(SourceField {
                        path: format!("1pux.sections.{section_name}.{label}"),
                        encoding: SourceEncoding::Json,
                        value: value.canonical(),
                    });
                    continue;
                }
            };
            fields.push(CustomField {
                id: random_id().map_err(|_| HumanCommitError::RandomUnavailable)?,
                label,
                value: logical,
                concealed,
            });
        }
    }
    Ok((fields, totp))
}

fn find_totp(value: &Json) -> Option<&str> {
    match value {
        Json::String(value) if value.starts_with("otpauth://totp/") => Some(value),
        Json::Object(object) => object
            .values()
            .filter_map(Json::string)
            .find(|value| value.starts_with("otpauth://totp/")),
        _ => None,
    }
}

fn push_destination(values: &mut Vec<Destination>, label: &str, value: &str) {
    if !values.iter().any(|entry| entry.value == value) {
        values.push(Destination {
            label: label.to_owned(),
            value: value.to_owned(),
        });
    }
}

fn required_object<'a>(
    object: &'a BTreeMap<String, Json>,
    key: &str,
) -> Result<&'a BTreeMap<String, Json>, HumanCommitError> {
    object
        .get(key)
        .ok_or(HumanCommitError::InvalidInput)?
        .object()
}
fn required_string<'a>(
    object: &'a BTreeMap<String, Json>,
    key: &str,
) -> Result<&'a str, HumanCommitError> {
    object
        .get(key)
        .and_then(Json::string)
        .ok_or(HumanCommitError::InvalidInput)
}
fn invalid<T>(_: T) -> HumanCommitError {
    HumanCommitError::InvalidInput
}

#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}
impl Json {
    fn object(&self) -> Result<&BTreeMap<String, Self>, HumanCommitError> {
        if let Self::Object(value) = self {
            Ok(value)
        } else {
            Err(HumanCommitError::InvalidInput)
        }
    }
    fn array(&self) -> Result<&[Self], HumanCommitError> {
        if let Self::Array(value) = self {
            Ok(value)
        } else {
            Err(HumanCommitError::InvalidInput)
        }
    }
    const fn string(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value.as_str())
        } else {
            None
        }
    }
    fn integer(&self) -> Option<i64> {
        if let Self::Number(value) = self {
            value.parse().ok()
        } else {
            None
        }
    }
    fn canonical(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.write(&mut output);
        output
    }
    fn write(&self, output: &mut Vec<u8>) {
        match self {
            Self::Null => output.extend_from_slice(b"null"),
            Self::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            Self::Number(value) => output.extend_from_slice(value.as_bytes()),
            Self::String(value) => write_json_string(output, value),
            Self::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    value.write(output);
                }
                output.push(b']');
            }
            Self::Object(values) => {
                output.push(b'{');
                for (index, (key, value)) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write_json_string(output, key);
                    output.push(b':');
                    value.write(output);
                }
                output.push(b'}');
            }
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
    values: usize,
}
impl<'a> JsonParser<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Json, HumanCommitError> {
        if bytes.len() > usize::try_from(MAX_DATA_BYTES).unwrap() {
            return Err(HumanCommitError::InvalidInput);
        }
        let mut parser = Self {
            bytes,
            position: 0,
            values: 0,
        };
        let value = parser.value(0)?;
        parser.whitespace();
        if parser.position != bytes.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(value)
    }
    fn value(&mut self, depth: usize) -> Result<Json, HumanCommitError> {
        if depth > 32 || self.values >= MAX_JSON_VALUES {
            return Err(HumanCommitError::InvalidInput);
        }
        self.values += 1;
        self.whitespace();
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Json::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Json::Bool(false))
            }
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b'[') => self.array_value(depth + 1),
            Some(b'{') => self.object_value(depth + 1),
            Some(b'-' | b'0'..=b'9') => Ok(Json::Number(self.number()?)),
            _ => Err(HumanCommitError::InvalidInput),
        }
    }
    fn array_value(&mut self, depth: usize) -> Result<Json, HumanCommitError> {
        self.expect(b'[')?;
        self.whitespace();
        let mut values = Vec::new();
        if self.take(b']') {
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value(depth)?);
            self.whitespace();
            if self.take(b']') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(Json::Array(values))
    }
    fn object_value(&mut self, depth: usize) -> Result<Json, HumanCommitError> {
        self.expect(b'{')?;
        self.whitespace();
        let mut values = BTreeMap::new();
        if self.take(b'}') {
            return Ok(Json::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            let value = self.value(depth)?;
            if values.insert(key, value).is_some() {
                return Err(HumanCommitError::InvalidInput);
            }
            self.whitespace();
            if self.take(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(Json::Object(values))
    }
    fn string(&mut self) -> Result<String, HumanCommitError> {
        self.expect(b'"')?;
        let mut output = Vec::new();
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(HumanCommitError::InvalidInput)?;
            self.position += 1;
            match byte {
                b'"' => break,
                0..=0x1f => return Err(HumanCommitError::InvalidInput),
                b'\\' => {
                    let escaped = *self
                        .bytes
                        .get(self.position)
                        .ok_or(HumanCommitError::InvalidInput)?;
                    self.position += 1;
                    match escaped {
                        b'"' | b'\\' | b'/' => output.push(escaped),
                        b'b' => output.push(8),
                        b'f' => output.push(12),
                        b'n' => output.push(b'\n'),
                        b'r' => output.push(b'\r'),
                        b't' => output.push(b'\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let second = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(HumanCommitError::InvalidInput);
                                }
                                0x10000
                                    + ((u32::from(first) - 0xd800) << 10)
                                    + (u32::from(second) - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err(HumanCommitError::InvalidInput);
                            } else {
                                u32::from(first)
                            };
                            let character =
                                char::from_u32(scalar).ok_or(HumanCommitError::InvalidInput)?;
                            let mut bytes = [0; 4];
                            output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
                        }
                        _ => return Err(HumanCommitError::InvalidInput),
                    }
                }
                _ => output.push(byte),
            }
            if output.len() > MAX_JSON_STRING {
                return Err(HumanCommitError::InvalidInput);
            }
        }
        String::from_utf8(output).map_err(|_| HumanCommitError::InvalidInput)
    }
    fn hex4(&mut self) -> Result<u16, HumanCommitError> {
        let bytes = self
            .bytes
            .get(self.position..self.position + 4)
            .ok_or(HumanCommitError::InvalidInput)?;
        self.position += 4;
        let mut value = 0_u16;
        for byte in bytes {
            value = value
                .checked_mul(16)
                .ok_or(HumanCommitError::InvalidInput)?;
            value += u16::from(match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(HumanCommitError::InvalidInput),
            });
        }
        Ok(value)
    }
    fn number(&mut self) -> Result<String, HumanCommitError> {
        let start = self.position;
        self.take(b'-');
        match self.peek() {
            Some(b'0') => {
                self.position += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(HumanCommitError::InvalidInput);
                }
            }
            Some(b'1'..=b'9') => {
                self.position += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(HumanCommitError::InvalidInput),
        }
        if self.take(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(HumanCommitError::InvalidInput);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(HumanCommitError::InvalidInput);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position += 1;
            }
        }
        if self.position - start > 64 {
            return Err(HumanCommitError::InvalidInput);
        }
        let number = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| HumanCommitError::InvalidInput)?;
        let in_range = if number
            .bytes()
            .all(|byte| byte == b'-' || byte.is_ascii_digit())
        {
            number.parse::<i64>().is_ok()
        } else {
            number.parse::<f64>().is_ok_and(f64::is_finite)
        };
        if !in_range {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(number.to_owned())
    }
    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }
    fn literal(&mut self, value: &[u8]) -> Result<(), HumanCommitError> {
        if self.bytes.get(self.position..self.position + value.len()) == Some(value) {
            self.position += value.len();
            Ok(())
        } else {
            Err(HumanCommitError::InvalidInput)
        }
    }
    fn expect(&mut self, value: u8) -> Result<(), HumanCommitError> {
        if self.take(value) {
            Ok(())
        } else {
            Err(HumanCommitError::InvalidInput)
        }
    }
    fn take(&mut self, value: u8) -> bool {
        if self.peek() == Some(value) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
}

fn write_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'"' => output.extend_from_slice(br#"\""#),
            b'\\' => output.extend_from_slice(br"\\"),
            b'\n' => output.extend_from_slice(br"\n"),
            b'\r' => output.extend_from_slice(br"\r"),
            b'\t' => output.extend_from_slice(br"\t"),
            0..=0x1f => output.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            _ => output.push(byte),
        }
    }
    output.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_security_boundaries_do_not_gain_an_implicit_byte() {
        assert!(decompression_ratio_allowed(100, 1));
        assert!(!decompression_ratio_allowed(101, 1));
        assert_eq!(
            add_logical_size(MAX_LOGICAL_BYTES - 1, 1),
            Some(MAX_LOGICAL_BYTES)
        );
        assert_eq!(add_logical_size(MAX_LOGICAL_BYTES, 1), None);
        assert!(Attachment::descriptor([1; 16], "x", "x", MAX_FILE, [2; 32]).is_ok());
        assert!(Attachment::descriptor([1; 16], "x", "x", MAX_FILE + 1, [2; 32]).is_err());
        assert_eq!(required_capacity(0, 0).unwrap(), 64 * 1024 * 1024);
        assert!(required_capacity(u64::MAX, 1).is_err());
    }

    #[test]
    fn native_integer_widths_are_normalized_without_truncation() {
        assert_eq!(filesystem_available_bytes(7_u32, 4096_u64).unwrap(), 28_672);
        assert!(filesystem_available_bytes(u64::MAX, 2_u64).is_err());

        let mask = 0o170_000_u16;
        let regular = 0o100_000_u16;
        let directory = 0o040_000_u16;
        assert!(zip_mode_is_supported(0, mask, regular, directory).unwrap());
        assert!(zip_mode_is_supported(0o100_644, mask, regular, directory).unwrap());
        assert!(zip_mode_is_supported(0o040_755, mask, regular, directory).unwrap());
        assert!(!zip_mode_is_supported(0o120_777, mask, regular, directory).unwrap());
        assert!(
            zip_mode_is_supported(
                0,
                u64::from(u32::MAX) + 1,
                u64::from(regular),
                u64::from(directory),
            )
            .is_err()
        );
    }

    #[test]
    fn json_depth_and_number_range_are_closed() {
        let at_limit = format!("{}0{}", "[".repeat(32), "]".repeat(32));
        let beyond = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert!(JsonParser::parse(at_limit.as_bytes()).is_ok());
        assert!(JsonParser::parse(beyond.as_bytes()).is_err());
        assert!(JsonParser::parse(b"9223372036854775807").is_ok());
        assert!(JsonParser::parse(b"9223372036854775808").is_err());
    }
}
