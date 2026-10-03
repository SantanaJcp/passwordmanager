// SPDX-License-Identifier: AGPL-3.0-only

//! Product-owned provider plaintext. Containers own only pointers/structure;
//! every text/byte payload is locked before its first write. No Vec adapters,
//! cloning or diagnostic traits are provided for plaintext values.

use pm_crypto::{CryptoError, ProtectedBytes, ProtectedText, ProtectedWriter};
use std::{fmt, io::Read};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Empty,
    InvalidUtf8,
    InvalidJson,
    DuplicateKey,
    TooDeep,
    TrailingBytes,
    ResourceUnavailable,
    Io,
}
impl From<()> for Error {
    fn from((): ()) -> Self {
        Self::InvalidJson
    }
}
impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::ResourceUnavailable => Self::ResourceUnavailable,
            _ => Self::InvalidJson,
        }
    }
}

pub(crate) trait Sink {
    fn put(&mut self, value: &[u8]) -> Result<(), Error>;
}
struct Size(usize);
impl Sink for Size {
    fn put(&mut self, value: &[u8]) -> Result<(), Error> {
        self.0 = self.0.checked_add(value.len()).ok_or(Error::InvalidJson)?;
        Ok(())
    }
}
impl Sink for ProtectedWriter {
    fn put(&mut self, value: &[u8]) -> Result<(), Error> {
        ProtectedWriter::put(self, value).map_err(Error::from)
    }
}
pub(crate) fn encode(
    emit: impl Fn(&mut dyn Sink) -> Result<(), Error>,
) -> Result<ProtectedBytes, Error> {
    let mut size = Size(0);
    emit(&mut size)?;
    let mut writer = ProtectedWriter::new(size.0)?;
    emit(&mut writer)?;
    writer.finish_exact().map_err(Error::from)
}
struct Format<'a>(&'a mut dyn Sink);
impl fmt::Write for Format<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.put(value.as_bytes()).map_err(|_| fmt::Error)
    }
}
pub(crate) fn format(arguments: fmt::Arguments<'_>) -> Result<ProtectedText, Error> {
    let bytes =
        encode(|sink| fmt::write(&mut Format(sink), arguments).map_err(|_| Error::InvalidJson))?;
    ProtectedText::from_bytes(bytes).map_err(Error::from)
}
pub(crate) fn text(value: &str) -> Result<ProtectedText, Error> {
    ProtectedText::copy_from_str(value).map_err(Error::from)
}

pub(crate) fn decode_base64(value: &str) -> Result<ProtectedBytes, Error> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let maximum = value.len().checked_add(3).ok_or(Error::InvalidJson)? / 4 * 3;
    let mut bytes = ProtectedBytes::zeroed(maximum)?;
    let size = URL_SAFE_NO_PAD
        .decode_slice(value, &mut bytes)
        .map_err(|_| Error::InvalidJson)?;
    bytes.truncate(size);
    Ok(bytes)
}
pub(crate) fn encode_base64(value: &[u8]) -> Result<ProtectedText, Error> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let maximum = value.len().checked_add(2).ok_or(Error::InvalidJson)? / 3 * 4;
    let mut bytes = ProtectedBytes::zeroed(maximum)?;
    let size = URL_SAFE_NO_PAD
        .encode_slice(value, &mut bytes)
        .map_err(|_| Error::InvalidJson)?;
    bytes.truncate(size);
    ProtectedText::from_bytes(bytes).map_err(Error::from)
}

impl From<crate::OidcError> for Error {
    fn from(error: crate::OidcError) -> Self {
        match error {
            crate::OidcError::ResourceUnavailable => Self::ResourceUnavailable,
            crate::OidcError::Network => Self::Io,
            crate::OidcError::InvalidResponse | crate::OidcError::InvalidToken => Self::InvalidJson,
        }
    }
}

/// Borrows output values; encoding never copies them into an ordinary tree.
pub(crate) enum Value<'a> {
    Null,
    Bool(bool),
    Number(&'a str),
    String(&'a str),
    Array(Vec<Value<'a>>),
    Object(Vec<(&'a str, Value<'a>)>),
}
impl Value<'_> {
    pub(crate) fn encode(&self) -> Result<ProtectedBytes, Error> {
        encode(|output| self.write(output))
    }
    fn write(&self, output: &mut dyn Sink) -> Result<(), Error> {
        match self {
            Self::Null => output.put(b"null")?,
            Self::Bool(value) => output.put(if *value { b"true" } else { b"false" })?,
            Self::Number(value) => output.put(value.as_bytes())?,
            Self::String(value) => write_json_string(output, value)?,
            Self::Array(values) => {
                output.put(b"[")?;
                for (i, value) in values.iter().enumerate() {
                    if i != 0 {
                        output.put(b",")?;
                    }
                    value.write(output)?;
                }
                output.put(b"]")?;
            }
            Self::Object(fields) => {
                output.put(b"{")?;
                for (i, (key, value)) in fields.iter().enumerate() {
                    if i != 0 {
                        output.put(b",")?;
                    }
                    write_json_string(output, key)?;
                    output.put(b":")?;
                    value.write(output)?;
                }
                output.put(b"}")?;
            }
        }
        Ok(())
    }
}
pub(crate) fn write_json_string(output: &mut dyn Sink, value: &str) -> Result<(), Error> {
    output.put(b"\"")?;
    for character in value.chars() {
        match character {
            '"' => output.put(b"\\\"")?,
            '\\' => output.put(b"\\\\")?,
            '\n' => output.put(b"\\n")?,
            '\r' => output.put(b"\\r")?,
            '\t' => output.put(b"\\t")?,
            c if c.is_control() => {
                use fmt::Write as _;
                write!(&mut Format(output), "\\u{:04x}", u32::from(c))
                    .map_err(|_| Error::InvalidJson)?;
            }
            c => {
                let mut bytes = [0; 4];
                output.put(c.encode_utf8(&mut bytes).as_bytes())?;
            }
        }
    }
    output.put(b"\"")
}
pub(crate) fn form_component(value: &str) -> Result<ProtectedText, Error> {
    let bytes = encode(|output| write_form_component(output, value))?;
    ProtectedText::from_bytes(bytes).map_err(Error::from)
}
fn write_form_component(output: &mut dyn Sink, value: &str) -> Result<(), Error> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.put(&[byte])?;
        } else {
            output.put(&[
                b'%',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 15)],
            ])?;
        }
    }
    Ok(())
}
pub(crate) fn form(fields: &[(&str, &str)]) -> Result<ProtectedBytes, Error> {
    encode(|output| {
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                output.put(b"&")?;
            }
            write_form_component(output, key)?;
            output.put(b"=")?;
            write_form_component(output, value)?;
        }
        Ok(())
    })
}
pub(crate) fn read_all(input: &mut impl Read, maximum: usize) -> Result<ProtectedBytes, Error> {
    let mut bytes = ProtectedBytes::zeroed(maximum.checked_add(1).ok_or(Error::InvalidJson)?)?;
    let mut at = 0;
    loop {
        let count = input.read(&mut bytes[at..]).map_err(|_| Error::Io)?;
        if count == 0 {
            bytes.truncate(at);
            return Ok(bytes);
        }
        at += count;
        if at > maximum {
            return Err(Error::InvalidJson);
        }
    }
}
pub(crate) fn read_until(
    input: &mut impl Read,
    maximum: usize,
    delimiter: &[u8],
) -> Result<ProtectedBytes, Error> {
    let capacity = maximum
        .checked_add(delimiter.len())
        .ok_or(Error::InvalidJson)?;
    let mut bytes = ProtectedBytes::zeroed(capacity)?;
    for at in 0..capacity {
        input
            .read_exact(&mut bytes[at..=at])
            .map_err(|_| Error::Io)?;
        if bytes[..=at].ends_with(delimiter) {
            bytes.truncate(at + 1 - delimiter.len());
            return Ok(bytes);
        }
    }
    Err(Error::InvalidJson)
}

pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(ProtectedText),
    String(ProtectedText),
    Array(Vec<Json>),
    Object(Vec<(ProtectedText, Json)>),
}
impl Json {
    pub(crate) fn field(&self, name: &str) -> Option<&Self> {
        if let Self::Object(fields) = self {
            fields
                .iter()
                .find(|(key, _)| &**key == name)
                .map(|(_, value)| value)
        } else {
            None
        }
    }
    pub(crate) fn string(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn number(&self) -> Option<&str> {
        if let Self::Number(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) const fn bool(&self) -> Option<bool> {
        if let Self::Bool(value) = self {
            Some(*value)
        } else {
            None
        }
    }
}
pub(crate) fn parse_json(bytes: &[u8]) -> Result<Json, Error> {
    if bytes.is_empty() {
        return Err(Error::Empty);
    }
    std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    let mut parser = Parser { bytes, at: 0 };
    let value = parser.value(0)?;
    parser.space();
    if parser.at != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}
const MAX_DEPTH: usize = pm_interface::MAX_DEPTH;
struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<Json, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        self.space();
        let byte = *self.bytes.get(self.at).ok_or(Error::InvalidJson)?;
        match byte {
            b'n' => self.literal(b"null", Json::Null),
            b't' => self.literal(b"true", Json::Bool(true)),
            b'f' => self.literal(b"false", Json::Bool(false)),
            b'"' => Ok(Json::String(self.string()?)),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            b'-' | b'0'..=b'9' => Ok(Json::Number(self.number()?)),
            _ => Err(Error::InvalidJson),
        }
    }
    fn literal(&mut self, literal: &[u8], value: Json) -> Result<Json, Error> {
        if self.bytes.get(self.at..self.at + literal.len()) != Some(literal) {
            return Err(Error::InvalidJson);
        }
        self.at += literal.len();
        Ok(value)
    }
    fn string(&mut self) -> Result<ProtectedText, Error> {
        let start = self.at;
        let end = std::cell::Cell::new(start);
        let bytes = encode(|output| {
            let mut parser = Parser {
                bytes: self.bytes,
                at: start,
            };
            parser.write_string(output)?;
            end.set(parser.at);
            Ok(())
        })?;
        self.at = end.get();
        ProtectedText::from_bytes(bytes).map_err(Error::from)
    }
    fn write_string(&mut self, output: &mut dyn Sink) -> Result<(), Error> {
        self.at += 1;
        loop {
            let byte = *self.bytes.get(self.at).ok_or(Error::InvalidJson)?;
            self.at += 1;
            match byte {
                b'"' => return Ok(()),
                b'\\' => {
                    let escaped = *self.bytes.get(self.at).ok_or(Error::InvalidJson)?;
                    self.at += 1;
                    match escaped {
                        b'"' | b'\\' | b'/' => output.put(&[escaped])?,
                        b'b' => output.put(&[8])?,
                        b'f' => output.put(&[12])?,
                        b'n' => output.put(b"\n")?,
                        b'r' => output.put(b"\r")?,
                        b't' => output.put(b"\t")?,
                        b'u' => {
                            let digits = self
                                .bytes
                                .get(self.at..self.at + 4)
                                .ok_or(Error::InvalidJson)?;
                            let text =
                                std::str::from_utf8(digits).map_err(|_| Error::InvalidJson)?;
                            let code =
                                u16::from_str_radix(text, 16).map_err(|_| Error::InvalidJson)?;
                            self.at += 4;
                            let character =
                                char::from_u32(u32::from(code)).ok_or(Error::InvalidJson)?;
                            if (0xd800..=0xdfff).contains(&code) {
                                return Err(Error::InvalidJson);
                            }
                            let mut bytes = [0; 4];
                            output.put(character.encode_utf8(&mut bytes).as_bytes())?;
                        }
                        _ => return Err(Error::InvalidJson),
                    }
                }
                b if b < 0x20 => return Err(Error::InvalidJson),
                _ => {
                    let start = self.at - 1;
                    while self.at < self.bytes.len()
                        && self.bytes[self.at] >= 0x20
                        && self.bytes[self.at] != b'"'
                        && self.bytes[self.at] != b'\\'
                    {
                        self.at += 1;
                    }
                    let text = std::str::from_utf8(&self.bytes[start..self.at])
                        .map_err(|_| Error::InvalidUtf8)?;
                    output.put(text.as_bytes())?;
                }
            }
        }
    }
    fn number(&mut self) -> Result<ProtectedText, Error> {
        let start = self.at;
        if self.bytes[self.at] == b'-' {
            self.at += 1;
        }
        match self.bytes.get(self.at) {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.at += 1;
                while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(Error::InvalidJson),
        }
        if self.bytes.get(self.at) == Some(&b'.') {
            self.at += 1;
            let begin = self.at;
            while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                self.at += 1;
            }
            if self.at == begin {
                return Err(Error::InvalidJson);
            }
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            let begin = self.at;
            while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                self.at += 1;
            }
            if self.at == begin {
                return Err(Error::InvalidJson);
            }
        }
        let number =
            std::str::from_utf8(&self.bytes[start..self.at]).map_err(|_| Error::InvalidJson)?;
        ProtectedText::copy_from_str(number).map_err(Error::from)
    }
    fn array(&mut self, depth: usize) -> Result<Json, Error> {
        self.at += 1;
        let mut values = Vec::new();
        self.space();
        if self.bytes.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value(depth + 1)?);
            self.space();
            match self.bytes.get(self.at) {
                Some(b',') => {
                    self.at += 1;
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(values));
                }
                _ => return Err(Error::InvalidJson),
            }
        }
    }
    fn object(&mut self, depth: usize) -> Result<Json, Error> {
        self.at += 1;
        let mut fields = Vec::new();
        self.space();
        if self.bytes.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.space();
            if self.bytes.get(self.at) != Some(&b'"') {
                return Err(Error::InvalidJson);
            }
            let key = self.string()?;
            if fields.iter().any(|(known, _)| known == &key) {
                return Err(Error::DuplicateKey);
            }
            self.space();
            if self.bytes.get(self.at) != Some(&b':') {
                return Err(Error::InvalidJson);
            }
            self.at += 1;
            fields.push((key, self.value(depth + 1)?));
            self.space();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(fields));
                }
                _ => return Err(Error::InvalidJson),
            }
        }
    }
    fn space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.at += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(actual: &Json, prior: &pm_interface::Json) -> bool {
        use pm_interface::Json as Prior;
        match (actual, prior) {
            (Json::Null, Prior::Null) => true,
            (Json::Bool(a), Prior::Bool(b)) => a == b,
            (Json::String(a), Prior::String(b)) | (Json::Number(a), Prior::Number(b)) => &**a == b,
            (Json::Array(a), Prior::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
            }
            (Json::Object(a), Prior::Object(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .zip(b)
                        .all(|((ak, av), (bk, bv))| &**ak == bk && same(av, bv))
            }
            _ => false,
        }
    }

    #[test]
    fn protected_json_preserves_existing_grammar_and_exact_scalar_text() {
        for source in [
            b"null".as_slice(),
            b"[true,false,-0,9007199254740993,0.001,1e+3]",
            br#"{"PM28_SYNTHETIC":"a\"\\\/\b\f\n\r\t\u0085\u754c","empty":""}"#,
            "{\"界\":\"e\u{301}\",\"nested\":[{},[],42]}".as_bytes(),
        ] {
            let actual = parse_json(source).unwrap();
            let prior = pm_interface::parse_json(source).unwrap();
            assert!(same(&actual, &prior), "JSON compatibility changed");
        }
        let too_deep = format!(
            "{}0{}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        for source in [
            b"".as_slice(),
            b"01",
            b"1.",
            b"1e",
            b"[1,]",
            br#"{"x":1,"x":2}"#,
            br#""\ud800""#,
            br#""\ud83d\ude00""#,
            b"{} trailing",
            too_deep.as_bytes(),
        ] {
            assert!(pm_interface::parse_json(source).is_err());
            assert!(parse_json(source).is_err(), "JSON rejection changed");
        }
    }

    #[test]
    fn bounded_readers_reject_excess_and_incomplete_messages() {
        assert!(
            read_all(&mut b"PM28".as_slice(), 4)
                .unwrap()
                .as_ref()
                .eq(b"PM28")
        );
        assert!(read_all(&mut b"PM28x".as_slice(), 4).is_err());
        assert!(
            read_until(&mut b"PM28\0".as_slice(), 4, &[0])
                .unwrap()
                .as_ref()
                .eq(b"PM28")
        );
        assert!(read_until(&mut b"PM28x\0".as_slice(), 4, &[0]).is_err());
        assert!(read_until(&mut b"PM28".as_slice(), 4, &[0]).is_err());
        assert!(
            read_until(&mut b"PM28\r\n\r\n".as_slice(), 4, b"\r\n\r\n")
                .unwrap()
                .as_ref()
                .eq(b"PM28")
        );
        assert!(read_until(&mut b"PM28\r\n\r".as_slice(), 4, b"\r\n\r\n").is_err());
    }

    #[test]
    fn borrowed_json_egress_escapes_without_ordinary_secret_tree() {
        let encoded = Value::Object(vec![
            ("PM28", Value::String("界\"\\\n\u{0085}")),
            ("n", Value::Number("9007199254740993")),
        ])
        .encode()
        .unwrap();
        assert!(
            encoded
                .as_ref()
                .eq("{\"PM28\":\"界\\\"\\\\\\n\\u0085\",\"n\":9007199254740993}".as_bytes())
        );
    }
}
