// SPDX-License-Identifier: AGPL-3.0-only

//! Closed CSV import profiles and loss-visible preview data.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AuthRecord, Destination, HumanCommitError, HumanMetadata, LogicalRecord, RecordKind,
    SourceEncoding, SourceField, TotpAlgorithm,
};

const MAX_COLUMNS: usize = 256;
const MAX_ROW_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 1_000_000;
pub(crate) const IMPORT_PAGE_ITEMS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsvDelimiter {
    Comma,
    Semicolon,
    Tab,
}
impl CsvDelimiter {
    const fn byte(self) -> u8 {
        match self {
            Self::Comma => b',',
            Self::Semicolon => b';',
            Self::Tab => b'\t',
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsvEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CsvField {
    Title,
    Destination,
    Username,
    Password,
    Notes,
    OtpAuth,
    TokenSecret,
    Provider,
    ProfileId,
    SshPrivateKey,
    SshPublicKey,
    SshPassphrase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsvMapping {
    pub(crate) delimiter: CsvDelimiter,
    pub(crate) encoding: CsvEncoding,
    pub(crate) has_header: bool,
    pub(crate) kind: RecordKind,
    pub(crate) columns: Vec<(usize, CsvField)>,
}
impl CsvMapping {
    /// Builds an explicit, one-column-per-scalar mapping.
    ///
    /// # Errors
    /// Rejects duplicate columns/targets, excessive indices, or incomplete types.
    pub fn new(
        delimiter: CsvDelimiter,
        encoding: CsvEncoding,
        has_header: bool,
        kind: RecordKind,
        mut columns: Vec<(usize, CsvField)>,
    ) -> Result<Self, HumanCommitError> {
        columns.sort_by_key(|v| v.0);
        let unique_columns = columns.iter().map(|v| v.0).collect::<BTreeSet<_>>();
        let unique_fields = columns.iter().map(|v| v.1).collect::<BTreeSet<_>>();
        if columns.is_empty()
            || columns.len() != unique_columns.len()
            || columns.len() != unique_fields.len()
            || columns.iter().any(|v| v.0 >= MAX_COLUMNS)
        {
            return Err(HumanCommitError::InvalidInput);
        }
        let has = |f| columns.iter().any(|v| v.1 == f);
        let valid = match kind {
            RecordKind::Password => {
                has(CsvField::Destination) && has(CsvField::Username) && has(CsvField::Password)
            }
            RecordKind::Note => true,
            RecordKind::Totp => has(CsvField::OtpAuth),
            RecordKind::Token => {
                has(CsvField::TokenSecret) && has(CsvField::Provider) && has(CsvField::ProfileId)
            }
            RecordKind::Ssh => {
                has(CsvField::SshPrivateKey)
                    && has(CsvField::SshPublicKey)
                    && has(CsvField::Username)
            }
            _ => false,
        };
        if !valid {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(Self {
            delimiter,
            encoding,
            has_header,
            kind,
            columns,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CsvImportProfile {
    Chrome,
    Apple(CsvMapping),
    Mappable(CsvMapping),
}
impl CsvImportProfile {
    #[must_use]
    pub const fn chrome() -> Self {
        Self::Chrome
    }
    #[must_use]
    pub const fn apple(mapping: CsvMapping) -> Self {
        Self::Apple(mapping)
    }
    #[must_use]
    pub const fn mappable(mapping: CsvMapping) -> Self {
        Self::Mappable(mapping)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsvRowStatus {
    New,
    ExactDuplicate,
    CandidateDuplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsvRowPreview {
    pub(crate) ordinal: usize,
    pub(crate) status: CsvRowStatus,
    pub(crate) unknown_fields: usize,
    pub(crate) duplicate_item: Option<[u8; 16]>,
}
impl CsvRowPreview {
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }
    #[must_use]
    pub const fn status(&self) -> CsvRowStatus {
        self.status
    }
    #[must_use]
    pub const fn unknown_fields(&self) -> usize {
        self.unknown_fields
    }
    #[must_use]
    pub const fn duplicate_item(&self) -> Option<&[u8; 16]> {
        self.duplicate_item.as_ref()
    }
}

pub struct CsvImportPreview {
    pub(crate) records: Vec<LogicalRecord>,
    pub(crate) rows: Vec<CsvRowPreview>,
    pub(crate) source: &'static str,
}

/// Borrowed human-visible fields for one preview row; secret material is not exposed.
pub struct CsvRecordPreview<'a> {
    row: &'a CsvRowPreview,
    record: &'a LogicalRecord,
}

impl CsvRecordPreview<'_> {
    #[must_use]
    pub const fn row(&self) -> &CsvRowPreview {
        self.row
    }

    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.record.kind()
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.record.human().title
    }

    #[must_use]
    pub fn destination(&self) -> Option<&str> {
        self.record
            .human()
            .destinations
            .first()
            .map(|value| value.value.as_str())
    }

    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.record.auth().first().map(|auth| match auth {
            AuthRecord::Password { username, .. } | AuthRecord::Ssh { username, .. } => {
                username.as_str()
            }
            AuthRecord::Totp { account, .. } => account.as_str(),
            AuthRecord::Token { profile_id, .. } => profile_id.as_str(),
            AuthRecord::Passkey { user_name, .. } => user_name.as_str(),
        })
    }

    pub fn unknown_field_paths(&self) -> impl Iterator<Item = &str> {
        self.record
            .human()
            .source_fields
            .iter()
            .map(|field| field.path.as_str())
    }
}

impl CsvImportPreview {
    #[must_use]
    pub fn total(&self) -> usize {
        self.rows.len()
    }
    /// Returns one bounded page of row classifications.
    ///
    /// # Errors
    /// Rejects a zero/oversized page or an offset beyond the preview.
    pub fn page(&self, offset: usize, limit: usize) -> Result<&[CsvRowPreview], HumanCommitError> {
        if limit == 0 || limit > 100 || offset > self.rows.len() {
            return Err(HumanCommitError::InvalidInput);
        }
        Ok(&self.rows[offset..self.rows.len().min(offset + limit)])
    }

    /// Returns human-visible, non-secret details for one zero-based preview row.
    ///
    /// # Errors
    /// Rejects an index outside this preview.
    pub fn record(&self, index: usize) -> Result<CsvRecordPreview<'_>, HumanCommitError> {
        Ok(CsvRecordPreview {
            row: self.rows.get(index).ok_or(HumanCommitError::InvalidInput)?,
            record: self
                .records
                .get(index)
                .ok_or(HumanCommitError::InvalidInput)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsvImportDecision {
    ImportNew,
    SkipExact,
    KeepBoth,
    Replace([u8; 16]),
    Exclude,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsvImportReport {
    pub(crate) total: usize,
    pub(crate) new_items: usize,
    pub(crate) replaced: usize,
    pub(crate) skipped_exact: usize,
    pub(crate) excluded: usize,
    pub(crate) preserved_fields: usize,
    pub(crate) event_pages: usize,
}
impl CsvImportReport {
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }
    #[must_use]
    pub const fn new_items(&self) -> usize {
        self.new_items
    }
    #[must_use]
    pub const fn replaced(&self) -> usize {
        self.replaced
    }
    #[must_use]
    pub const fn skipped_exact(&self) -> usize {
        self.skipped_exact
    }
    #[must_use]
    pub const fn excluded(&self) -> usize {
        self.excluded
    }
    #[must_use]
    pub const fn preserved_fields(&self) -> usize {
        self.preserved_fields
    }
    #[must_use]
    pub const fn event_pages(&self) -> usize {
        self.event_pages
    }
}

pub struct PreparedCsvImport {
    pub(crate) prepared: crate::PreparedHumanCommand,
    pub(crate) report: CsvImportReport,
    pub(crate) item_ids: Vec<[u8; 16]>,
}
impl PreparedCsvImport {
    #[must_use]
    pub const fn prepared(&self) -> &crate::PreparedHumanCommand {
        &self.prepared
    }
    #[must_use]
    pub const fn report(&self) -> &CsvImportReport {
        &self.report
    }
    #[must_use]
    pub fn item_ids(&self) -> &[[u8; 16]] {
        &self.item_ids
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse(
    bytes: &[u8],
    profile: &CsvImportProfile,
) -> Result<CsvImportPreview, HumanCommitError> {
    let (mapping, source) = match profile {
        CsvImportProfile::Chrome => (None, "chrome"),
        CsvImportProfile::Apple(v) => (Some(v.clone()), "apple"),
        CsvImportProfile::Mappable(v) => (Some(v.clone()), "mappable"),
    };
    let encoding = mapping.as_ref().map_or(CsvEncoding::Utf8, |v| v.encoding);
    let delimiter = mapping
        .as_ref()
        .map_or(CsvDelimiter::Comma, |v| v.delimiter);
    let text = decode_text(bytes, encoding)?;
    let table = parse_csv(text.as_bytes(), delimiter.byte())?;
    if table.is_empty() {
        return Err(HumanCommitError::InvalidInput);
    }
    let has_header = mapping.as_ref().is_none_or(|v| v.has_header);
    let width = table[0].len();
    if width == 0 || width > MAX_COLUMNS {
        return Err(HumanCommitError::InvalidInput);
    }
    let headers = if has_header {
        table[0].clone()
    } else {
        (0..width).map(|i| format!("column:{i}")).collect()
    };
    let data = if has_header { &table[1..] } else { &table[..] };
    if data.is_empty() {
        return Err(HumanCommitError::InvalidInput);
    }
    let mapping = if let Some(v) = mapping {
        v
    } else {
        chrome_mapping(&headers)?
    };
    if data.len() > MAX_RECORDS {
        return Err(HumanCommitError::InvalidInput);
    }
    let mapped = mapping.columns.iter().map(|v| v.0).collect::<BTreeSet<_>>();
    let mut records = Vec::with_capacity(data.len());
    let mut previews = Vec::with_capacity(data.len());
    for (ordinal, row) in data.iter().enumerate() {
        if row.len() != width || mapping.columns.iter().any(|v| v.0 >= row.len()) {
            return Err(HumanCommitError::InvalidInput);
        }
        let values = mapping
            .columns
            .iter()
            .map(|(i, f)| (*f, row[*i].clone()))
            .collect::<BTreeMap<_, _>>();
        let mut source_fields = Vec::new();
        for (i, value) in row.iter().enumerate() {
            if !mapped.contains(&i) {
                source_fields.push(SourceField {
                    path: headers[i].clone(),
                    encoding: SourceEncoding::Utf8,
                    value: value.as_bytes().to_vec(),
                });
            }
        }
        if let Some(value) = values.get(&CsvField::OtpAuth).filter(|v| !v.is_empty()) {
            source_fields.push(SourceField {
                path: "OTPAuth".into(),
                encoding: SourceEncoding::Utf8,
                value: value.as_bytes().to_vec(),
            });
        }
        let title = values.get(&CsvField::Title).cloned().unwrap_or_default();
        let destination = values
            .get(&CsvField::Destination)
            .cloned()
            .unwrap_or_default();
        let destinations = if destination.is_empty() {
            Vec::new()
        } else {
            vec![Destination {
                label: String::new(),
                value: destination,
            }]
        };
        let refs = if destinations.is_empty() {
            Vec::new()
        } else {
            vec![0]
        };
        let mut auth = Vec::new();
        match mapping.kind {
            RecordKind::Password => auth.push(AuthRecord::Password {
                username: values.get(&CsvField::Username).cloned().unwrap_or_default(),
                password: values
                    .get(&CsvField::Password)
                    .map_or_else(Vec::new, |v| v.as_bytes().to_vec()),
                destination_refs: refs.clone(),
            }),
            RecordKind::Totp | RecordKind::Note => {}
            RecordKind::Token => auth.push(AuthRecord::Token {
                secret: values
                    .get(&CsvField::TokenSecret)
                    .map_or_else(Vec::new, |v| v.as_bytes().to_vec()),
                provider: values.get(&CsvField::Provider).cloned().unwrap_or_default(),
                profile_id: values
                    .get(&CsvField::ProfileId)
                    .cloned()
                    .unwrap_or_default(),
                destination_refs: refs.clone(),
                expires_at: None,
            }),
            RecordKind::Ssh => auth.push(AuthRecord::Ssh {
                private_format: crate::PrivateKeyFormat::OpenSsh,
                private_key: values
                    .get(&CsvField::SshPrivateKey)
                    .map_or_else(Vec::new, |v| v.as_bytes().to_vec()),
                public_key: values
                    .get(&CsvField::SshPublicKey)
                    .map_or_else(Vec::new, |v| v.as_bytes().to_vec()),
                username: values.get(&CsvField::Username).cloned().unwrap_or_default(),
                destination_refs: refs.clone(),
                passphrase: values
                    .get(&CsvField::SshPassphrase)
                    .filter(|v| !v.is_empty())
                    .map(|v| v.as_bytes().to_vec()),
            }),
            _ => return Err(HumanCommitError::InvalidInput),
        }
        if let Some(uri) = values.get(&CsvField::OtpAuth).filter(|v| !v.is_empty()) {
            auth.push(parse_totp(uri, &refs)?);
        }
        let record = LogicalRecord::new(
            mapping.kind,
            HumanMetadata {
                title,
                destinations,
                tags: Vec::new(),
                favorite: false,
                notes: values.get(&CsvField::Notes).cloned().unwrap_or_default(),
                fields: Vec::new(),
                source_fields,
            },
            auth,
            Vec::new(),
        )?;
        let unknown = record.human().source_fields.len();
        records.push(record);
        previews.push(CsvRowPreview {
            ordinal: ordinal + 1,
            status: CsvRowStatus::New,
            unknown_fields: unknown,
            duplicate_item: None,
        });
    }
    Ok(CsvImportPreview {
        records,
        rows: previews,
        source,
    })
}

fn chrome_mapping(headers: &[String]) -> Result<CsvMapping, HumanCommitError> {
    let find = |name: &str| headers.iter().position(|v| v == name);
    let mut columns = Vec::new();
    if let Some(v) = find("name") {
        columns.push((v, CsvField::Title));
    }
    columns.push((
        find("url").ok_or(HumanCommitError::InvalidInput)?,
        CsvField::Destination,
    ));
    columns.push((
        find("username").ok_or(HumanCommitError::InvalidInput)?,
        CsvField::Username,
    ));
    columns.push((
        find("password").ok_or(HumanCommitError::InvalidInput)?,
        CsvField::Password,
    ));
    if let Some(v) = find("note") {
        columns.push((v, CsvField::Notes));
    }
    CsvMapping::new(
        CsvDelimiter::Comma,
        CsvEncoding::Utf8,
        true,
        RecordKind::Password,
        columns,
    )
}

fn decode_text(bytes: &[u8], encoding: CsvEncoding) -> Result<String, HumanCommitError> {
    match encoding {
        CsvEncoding::Utf8 => {
            let b = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
            String::from_utf8(b.to_vec()).map_err(|_| HumanCommitError::InvalidInput)
        }
        CsvEncoding::Utf16Le | CsvEncoding::Utf16Be => {
            let bom = match encoding {
                CsvEncoding::Utf16Le => [0xff, 0xfe],
                CsvEncoding::Utf16Be => [0xfe, 0xff],
                CsvEncoding::Utf8 => unreachable!(),
            };
            let b = bytes
                .strip_prefix(&bom)
                .ok_or(HumanCommitError::InvalidInput)?;
            if b.len() % 2 != 0 {
                return Err(HumanCommitError::InvalidInput);
            }
            let units = b.as_chunks::<2>().0.iter().map(|v| {
                if encoding == CsvEncoding::Utf16Le {
                    u16::from_le_bytes([v[0], v[1]])
                } else {
                    u16::from_be_bytes([v[0], v[1]])
                }
            });
            char::decode_utf16(units)
                .collect::<Result<String, _>>()
                .map_err(|_| HumanCommitError::InvalidInput)
        }
    }
}

fn parse_csv(bytes: &[u8], delimiter: u8) -> Result<Vec<Vec<String>>, HumanCommitError> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = Vec::new();
    let mut quoted = false;
    let mut after_quote = false;
    let mut i = 0;
    let mut row_bytes = 0;
    while i < bytes.len() {
        let b = bytes[i];
        row_bytes += 1;
        if row_bytes > MAX_ROW_BYTES {
            return Err(HumanCommitError::InvalidInput);
        }
        if quoted {
            if b == b'"' {
                if bytes.get(i + 1) == Some(&b'"') {
                    field.push(b'"');
                    i += 1;
                } else {
                    quoted = false;
                    after_quote = true;
                }
            } else {
                field.push(b);
            }
        } else if after_quote {
            if b == delimiter {
                push_field(&mut row, &mut field)?;
                after_quote = false;
            } else if b == b'\n' {
                push_field(&mut row, &mut field)?;
                rows.push(std::mem::take(&mut row));
                check_row_count(&rows)?;
                after_quote = false;
                row_bytes = 0;
            } else if b == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                push_field(&mut row, &mut field)?;
                rows.push(std::mem::take(&mut row));
                check_row_count(&rows)?;
                after_quote = false;
                row_bytes = 0;
                i += 1;
            } else {
                return Err(HumanCommitError::InvalidInput);
            }
        } else if b == b'"' && field.is_empty() {
            quoted = true;
        } else if b == delimiter {
            push_field(&mut row, &mut field)?;
        } else if b == b'\n' {
            push_field(&mut row, &mut field)?;
            rows.push(std::mem::take(&mut row));
            check_row_count(&rows)?;
            row_bytes = 0;
        } else if b == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            push_field(&mut row, &mut field)?;
            rows.push(std::mem::take(&mut row));
            check_row_count(&rows)?;
            row_bytes = 0;
            i += 1;
        } else if b == b'\r' {
            return Err(HumanCommitError::InvalidInput);
        } else {
            field.push(b);
        }
        i += 1;
    }
    if quoted {
        return Err(HumanCommitError::InvalidInput);
    }
    if after_quote || !field.is_empty() || !row.is_empty() {
        push_field(&mut row, &mut field)?;
        rows.push(row);
        check_row_count(&rows)?;
    }
    Ok(rows)
}
fn check_row_count(rows: &[Vec<String>]) -> Result<(), HumanCommitError> {
    if rows.len() > MAX_RECORDS + 1 {
        Err(HumanCommitError::InvalidInput)
    } else {
        Ok(())
    }
}
fn push_field(row: &mut Vec<String>, field: &mut Vec<u8>) -> Result<(), HumanCommitError> {
    if row.len() >= MAX_COLUMNS {
        return Err(HumanCommitError::InvalidInput);
    }
    row.push(String::from_utf8(std::mem::take(field)).map_err(|_| HumanCommitError::InvalidInput)?);
    Ok(())
}

pub(crate) fn parse_totp(uri: &str, refs: &[u16]) -> Result<AuthRecord, HumanCommitError> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or(HumanCommitError::InvalidInput)?;
    let (label, query) = rest.split_once('?').ok_or(HumanCommitError::InvalidInput)?;
    let label = percent(label)?;
    let mut values = BTreeMap::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').ok_or(HumanCommitError::InvalidInput)?;
        if values.insert(k, percent(v)?).is_some() {
            return Err(HumanCommitError::InvalidInput);
        }
    }
    let secret = base32(values.get("secret").ok_or(HumanCommitError::InvalidInput)?)?;
    let algorithm = match values.get("algorithm").map_or("SHA1", String::as_str) {
        "SHA1" => TotpAlgorithm::Sha1,
        "SHA256" => TotpAlgorithm::Sha256,
        "SHA512" => TotpAlgorithm::Sha512,
        _ => return Err(HumanCommitError::InvalidInput),
    };
    let digits = values.get("digits").map_or(Ok(6), |v| {
        v.parse().map_err(|_| HumanCommitError::InvalidInput)
    })?;
    let period = values.get("period").map_or(Ok(30), |v| {
        v.parse().map_err(|_| HumanCommitError::InvalidInput)
    })?;
    let (issuer, account) = label.split_once(':').map_or(
        (
            values.get("issuer").cloned().unwrap_or_default(),
            label.clone(),
        ),
        |(i, a)| (i.to_owned(), a.to_owned()),
    );
    Ok(AuthRecord::Totp {
        secret,
        algorithm,
        digits,
        period,
        t0: 0,
        issuer,
        account,
        destination_refs: refs.to_vec(),
    })
}
fn percent(v: &str) -> Result<String, HumanCommitError> {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(HumanCommitError::InvalidInput);
            }
            let h = |x: u8| match x {
                b'0'..=b'9' => Some(x - b'0'),
                b'a'..=b'f' => Some(x - b'a' + 10),
                b'A'..=b'F' => Some(x - b'A' + 10),
                _ => None,
            };
            out.push(
                h(b[i + 1])
                    .zip(h(b[i + 2]))
                    .map(|(a, c)| (a << 4) | c)
                    .ok_or(HumanCommitError::InvalidInput)?,
            );
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| HumanCommitError::InvalidInput)
}
fn base32(v: &str) -> Result<Vec<u8>, HumanCommitError> {
    let mut out = Vec::new();
    let mut acc = 0_u32;
    let mut bits = 0;
    for b in v.bytes().filter(|v| *v != b'=') {
        let n = match b.to_ascii_uppercase() {
            b'A'..=b'Z' => b.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return Err(HumanCommitError::InvalidInput),
        };
        acc = (acc << 5) | u32::from(n);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).map_err(|_| HumanCommitError::InvalidInput)?);
            acc &= (1 << bits) - 1;
        }
    }
    if out.len() < 10 || out.len() > 128 {
        return Err(HumanCommitError::InvalidInput);
    }
    Ok(out)
}
