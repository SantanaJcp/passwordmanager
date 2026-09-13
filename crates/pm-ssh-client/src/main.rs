// SPDX-License-Identifier: AGPL-3.0-only
use std::{path::PathBuf, process::ExitCode, sync::Arc};
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(4)
        }
    }
}
fn run() -> Result<(), pm_ssh_client::Error> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next().ok_or(pm_ssh_client::Error::Protocol)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| pm_ssh_client::Error::Io)?;
    match command.to_str() {
        Some("serve") => {
            let profile_path = take_path(&mut args, "--profile")?;
            let owner = take_u32(&mut args, "--profile-owner")?;
            let provider_socket = take_path(&mut args, "--provider-socket")?;
            let provider_uid = take_u32(&mut args, "--provider-uid")?;
            let consumer_socket = take_path(&mut args, "--consumer-socket")?;
            if args.next().is_some() || provider_uid == 0 {
                return Err(pm_ssh_client::Error::Protocol);
            }
            let profile = Arc::new(pm_ssh_client::Profile::read_installed(
                &profile_path,
                owner,
            )?);
            runtime.block_on(pm_ssh_client::serve(
                profile,
                &provider_socket,
                provider_uid,
                &consumer_socket,
            ))
        }
        Some("consume") => {
            let socket = take_path(&mut args, "--socket")?;
            let reference = args.next().ok_or(pm_ssh_client::Error::Protocol)?;
            if args.next().is_some() {
                return Err(pm_ssh_client::Error::Protocol);
            }
            runtime.block_on(pm_ssh_client::consume(
                &socket,
                &reference.to_string_lossy(),
            ))?;
            println!("PASS ssh-consumer authenticated-channel-opened-and-closed");
            Ok(())
        }
        _ => Err(pm_ssh_client::Error::Protocol),
    }
}
fn take_path(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<PathBuf, pm_ssh_client::Error> {
    match (args.next(), args.next()) {
        (Some(actual), Some(value)) if actual == flag => Ok(value.into()),
        _ => Err(pm_ssh_client::Error::Protocol),
    }
}
fn take_u32(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<u32, pm_ssh_client::Error> {
    take_path(args, flag)?
        .to_string_lossy()
        .parse()
        .map_err(|_| pm_ssh_client::Error::Protocol)
}
