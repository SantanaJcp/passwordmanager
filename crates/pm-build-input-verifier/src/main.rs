// SPDX-License-Identifier: AGPL-3.0-only

use std::{env, error::Error, fs, path::Path};

use minisign_verify::{PublicKey, Signature};

const LIBSODIUM_RELEASE_KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let archive = arguments.next().ok_or("archive path is required")?;
    let signature = arguments.next().ok_or("signature path is required")?;
    if arguments.next().is_some() {
        return Err("unexpected verifier argument".into());
    }

    let archive = fs::read(Path::new(&archive))?;
    let signature = Signature::from_file(Path::new(&signature))?;
    let public_key = PublicKey::from_base64(LIBSODIUM_RELEASE_KEY)?;
    public_key.verify(&archive, &signature, false)?;
    println!("PASS libsodium-source minisign=verified key=upstream-fixed");
    Ok(())
}
