// SPDX-License-Identifier: AGPL-3.0-only
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

//! Chromium Native Messaging bridge for the custodial WebAuthn provider. It
//! owns no passkey secret and accepts only a closed request derived by the
//! packaged MV3 extension from a top-level, exact-origin document.

use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};

use pm_interface::{Json, encode_json, parse_json};
use pm_vault::{PasskeyOperation, PasskeyRequest, PasskeyStatus, UserVerificationRequirement};

const MAX_NATIVE_MESSAGE: usize = 256 * 1024;
const CONFIG_MAGIC: &str = "PMN1";

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        if run().is_ok() {
            ExitCode::SUCCESS
        } else {
            let _ = write_native(&Json::Object(vec![
                ("ok".into(), Json::Bool(false)),
                ("error".into(), Json::String("NOT_ALLOWED".into())),
            ]));
            ExitCode::from(4)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        ExitCode::from(4)
    }
}

#[derive(Debug)]
struct Config {
    profile: PathBuf,
    private: PathBuf,
    socket: PathBuf,
    extension_origin: String,
    origin: String,
    rp_id: String,
}

fn run() -> Result<(), ()> {
    let executable = std::env::current_exe().map_err(|_| ())?;
    let config = read_config(PathBuf::from(format!("{}.conf", executable.display())).as_path())?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() != [config.extension_origin.as_str()] {
        return Err(());
    }
    loop {
        let Some(message) = read_native()? else {
            return Ok(());
        };
        let response = process_message(&config, &message).unwrap_or_else(|()| {
            Json::Object(vec![
                ("ok".into(), Json::Bool(false)),
                ("error".into(), Json::String("NOT_ALLOWED".into())),
            ])
        });
        write_native(&response)?;
    }
}

fn read_config(path: &Path) -> Result<Config, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o400
        || metadata.len() > 16 * 1024
    {
        return Err(());
    }
    let text = fs::read_to_string(path).map_err(|_| ())?;
    let mut lines = text.lines();
    if lines.next() != Some(CONFIG_MAGIC) {
        return Err(());
    }
    let profile = config_path(lines.next(), "profile=")?;
    let private = config_path(lines.next(), "private=")?;
    let socket = config_path(lines.next(), "socket=")?;
    let extension_origin = config_value(lines.next(), "extension_origin=")?;
    let origin = config_value(lines.next(), "origin=")?;
    let rp_id = config_value(lines.next(), "rp_id=")?;
    if lines.next().is_some()
        || !extension_origin.starts_with("chrome-extension://")
        || !extension_origin.ends_with('/')
        || extension_origin.len() != "chrome-extension:///".len() + 32
        || !extension_origin
            .trim_start_matches("chrome-extension://")
            .trim_end_matches('/')
            .bytes()
            .all(|value| matches!(value, b'a'..=b'p'))
        || origin != format!("https://{rp_id}")
    {
        return Err(());
    }
    Ok(Config {
        profile,
        private,
        socket,
        extension_origin,
        origin,
        rp_id,
    })
}

fn config_path(line: Option<&str>, prefix: &str) -> Result<PathBuf, ()> {
    let value = PathBuf::from(config_value(line, prefix)?);
    if !value.is_absolute() {
        return Err(());
    }
    Ok(value)
}

fn config_value(line: Option<&str>, prefix: &str) -> Result<String, ()> {
    let value = line.and_then(|line| line.strip_prefix(prefix)).ok_or(())?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(());
    }
    Ok(value.to_owned())
}

fn process_message(config: &Config, bytes: &[u8]) -> Result<Json, ()> {
    let value = parse_json(bytes).map_err(|_| ())?;
    let Json::Object(fields) = &value else {
        return Err(());
    };
    let op = field(fields, "op")?.string().ok_or(())?;
    let request_id = fixed_hex::<16>(field(fields, "requestId")?.string().ok_or(())?)?;
    validate_sender(config, fields)?;
    let request = match op {
        "create" => {
            exact_fields(
                fields,
                &[
                    "op",
                    "requestId",
                    "documentId",
                    "origin",
                    "rpId",
                    "challenge",
                    "userHandle",
                    "userName",
                    "displayName",
                    "credentialIds",
                    "uv",
                    "topLevel",
                    "frameId",
                    "senderOrigin",
                ],
            )?;
            if !matches!(field(fields, "credentialIds")?, Json::Array(values) if values.is_empty())
            {
                return Err(());
            }
            PasskeyRequest::registration(
                request_id,
                field(fields, "documentId")?.string().ok_or(())?,
                &config.origin,
                &config.rp_id,
                &hex_bytes(field(fields, "challenge")?.string().ok_or(())?, 64)?,
                &hex_bytes(field(fields, "userHandle")?.string().ok_or(())?, 64)?,
                field(fields, "userName")?.string().ok_or(())?,
                field(fields, "displayName")?.string().ok_or(())?,
                uv(fields)?,
            )
            .map_err(|_| ())?
        }
        "get" => {
            exact_fields(
                fields,
                &[
                    "op",
                    "requestId",
                    "attemptId",
                    "documentId",
                    "origin",
                    "rpId",
                    "challenge",
                    "userHandle",
                    "userName",
                    "displayName",
                    "credentialIds",
                    "uv",
                    "topLevel",
                    "frameId",
                    "senderOrigin",
                ],
            )?;
            if field(fields, "userHandle")?.string() != Some("")
                || field(fields, "userName")?.string() != Some("")
                || field(fields, "displayName")?.string() != Some("")
            {
                return Err(());
            }
            let Json::Array(ids) = field(fields, "credentialIds")? else {
                return Err(());
            };
            let credential_ids = ids
                .iter()
                .map(|value| hex_bytes(value.string().ok_or(())?, 1024))
                .collect::<Result<Vec<_>, _>>()?;
            PasskeyRequest::assertion(
                request_id,
                fixed_hex(field(fields, "attemptId")?.string().ok_or(())?)?,
                field(fields, "documentId")?.string().ok_or(())?,
                &config.origin,
                &config.rp_id,
                &hex_bytes(field(fields, "challenge")?.string().ok_or(())?, 64)?,
                credential_ids,
                uv(fields)?,
            )
            .map_err(|_| ())?
        }
        "response" => {
            exact_fields(
                fields,
                &[
                    "op",
                    "requestId",
                    "documentId",
                    "origin",
                    "rpId",
                    "topLevel",
                    "frameId",
                    "senderOrigin",
                ],
            )?;
            let mut rpc = vec![42];
            rpc.extend_from_slice(&request_id);
            return call(config, &rpc);
        }
        _ => return Err(()),
    };
    if request.origin() != config.origin || request.rp_id() != config.rp_id {
        return Err(());
    }
    let mut rpc = vec![41];
    rpc.extend_from_slice(&request.to_bytes());
    call(config, &rpc)
}

fn validate_sender(config: &Config, fields: &[(String, Json)]) -> Result<(), ()> {
    if field(fields, "topLevel")?.bool() != Some(true)
        || field(fields, "frameId")?.number() != Some("0")
        || field(fields, "origin")?.string() != Some(config.origin.as_str())
        || field(fields, "senderOrigin")?.string() != Some(config.origin.as_str())
        || field(fields, "rpId")?.string() != Some(config.rp_id.as_str())
    {
        return Err(());
    }
    let document = field(fields, "documentId")?.string().ok_or(())?;
    if document.is_empty()
        || document.len() > 256
        || !document
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
    {
        return Err(());
    }
    Ok(())
}

fn uv(fields: &[(String, Json)]) -> Result<UserVerificationRequirement, ()> {
    match field(fields, "uv")?.string() {
        Some("required") => Ok(UserVerificationRequirement::Required),
        Some("preferred") => Ok(UserVerificationRequirement::Preferred),
        Some("discouraged") => Ok(UserVerificationRequirement::Discouraged),
        _ => Err(()),
    }
}

fn call(config: &Config, rpc: &[u8]) -> Result<Json, ()> {
    let response =
        pm_custody::agent_rpc(&config.profile, &config.private, &config.socket, Some(rpc))
            .map_err(|_| ())?;
    if response.first() != Some(&0) {
        return Err(());
    }
    let payload = wire_bytes(response.get(1..).ok_or(())?)?;
    if payload.is_empty() {
        return Ok(Json::Object(vec![
            ("ok".into(), Json::Bool(true)),
            ("state".into(), Json::String("waiting".into())),
        ]));
    }
    let status = PasskeyStatus::from_bytes(payload).map_err(|_| ())?;
    status_json(&status)
}

fn status_json(status: &PasskeyStatus) -> Result<Json, ()> {
    let mut fields = vec![("ok".into(), Json::Bool(true))];
    match status {
        PasskeyStatus::Waiting(prompt) => {
            fields.push(("state".into(), Json::String("waiting".into())));
            fields.push((
                "operation".into(),
                Json::String(
                    match prompt.operation() {
                        PasskeyOperation::Create => "create",
                        PasskeyOperation::Get => "get",
                    }
                    .into(),
                ),
            ));
            fields.push(("rpId".into(), Json::String(prompt.rp_id().into())));
            fields.push(("account".into(), Json::String(prompt.account().into())));
            fields.push((
                "documentId".into(),
                Json::String(prompt.document_id().into()),
            ));
        }
        PasskeyStatus::Registration(value) => {
            fields.push(("state".into(), Json::String("registration".into())));
            fields.push((
                "credentialId".into(),
                Json::String(hex(value.credential_id())),
            ));
            fields.push(("publicKey".into(), Json::String(hex(value.public_key()))));
            fields.push(("userHandle".into(), Json::String(hex(value.user_handle()))));
            fields.push(("algorithm".into(), Json::Number("-8".into())));
            fields.push(("attestation".into(), Json::String("none".into())));
            fields.push(("signCount".into(), Json::Number("0".into())));
            fields.push(("backupEligible".into(), Json::Bool(value.backup_eligible())));
            fields.push(("backupState".into(), Json::Bool(value.backup_state())));
        }
        PasskeyStatus::Assertion(value) => {
            fields.push(("state".into(), Json::String("assertion".into())));
            fields.push((
                "credentialId".into(),
                Json::String(hex(value.credential_id())),
            ));
            fields.push((
                "authenticatorData".into(),
                Json::String(hex(value.authenticator_data())),
            ));
            fields.push((
                "clientDataJSON".into(),
                Json::String(hex(value.client_data_json())),
            ));
            fields.push(("signature".into(), Json::String(hex(value.signature()))));
            fields.push(("userHandle".into(), Json::String(hex(value.user_handle()))));
        }
    }
    Ok(Json::Object(fields))
}

fn exact_fields(fields: &[(String, Json)], expected: &[&str]) -> Result<(), ()> {
    if fields.len() != expected.len()
        || fields
            .iter()
            .any(|(key, _)| !expected.contains(&key.as_str()))
    {
        Err(())
    } else {
        Ok(())
    }
}

fn field<'a>(fields: &'a [(String, Json)], name: &str) -> Result<&'a Json, ()> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or(())
}

fn read_native() -> Result<Option<Vec<u8>>, ()> {
    let mut length = [0_u8; 4];
    let mut input = std::io::stdin().lock();
    match input.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err(()),
    }
    let length = usize::try_from(u32::from_ne_bytes(length)).map_err(|_| ())?;
    if length == 0 || length > MAX_NATIVE_MESSAGE {
        return Err(());
    }
    let mut message = vec![0_u8; length];
    input.read_exact(&mut message).map_err(|_| ())?;
    Ok(Some(message))
}

fn write_native(value: &Json) -> Result<(), ()> {
    let bytes = encode_json(value);
    if bytes.len() > MAX_NATIVE_MESSAGE {
        return Err(());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ())?;
    let mut output = std::io::stdout().lock();
    output.write_all(&length.to_ne_bytes()).map_err(|_| ())?;
    output.write_all(&bytes).map_err(|_| ())?;
    output.flush().map_err(|_| ())
}

fn wire_bytes(bytes: &[u8]) -> Result<&[u8], ()> {
    let length: [u8; 4] = bytes.get(..4).ok_or(())?.try_into().map_err(|_| ())?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| ())?;
    let value = bytes.get(4..).ok_or(())?;
    if value.len() != length {
        return Err(());
    }
    Ok(value)
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    hex_bytes(value, N)?.try_into().map_err(|_| ())
}

fn hex_bytes(value: &str, maximum: usize) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 || value.len() / 2 > maximum {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = digit(pair[0])?;
            let low = digit(pair[1])?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn digit(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn current_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    unsafe { libc::geteuid() }
}
