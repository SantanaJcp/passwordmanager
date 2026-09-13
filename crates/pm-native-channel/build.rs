// SPDX-License-Identifier: AGPL-3.0-only

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/macos_clipboard.m");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let object = out.join("macos_clipboard.o");
    let archive = out.join("libpm_macos_clipboard.a");
    let cc = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(cc)
        .args(["-fobjc-arc", "-c", "src/macos_clipboard.m", "-o"])
        .arg(&object)
        .status()
        .expect("macOS Objective-C compiler must be installed");
    assert!(
        status.success(),
        "macOS clipboard bridge compilation failed"
    );
    let status = Command::new("ar")
        .arg("crus")
        .arg(&archive)
        .arg(&object)
        .status()
        .expect("macOS archiver must be installed");
    assert!(status.success(), "macOS clipboard bridge archive failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=pm_macos_clipboard");
    println!("cargo:rustc-link-lib=framework=AppKit");
}
