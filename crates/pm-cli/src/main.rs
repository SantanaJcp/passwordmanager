// SPDX-License-Identifier: AGPL-3.0-only

fn main() {
    if std::env::args_os().skip(1).eq(["--version"]) {
        println!(
            "passwordmanager {} (libsodium {})",
            env!("CARGO_PKG_VERSION"),
            pm_crypto::linked_libsodium_version().to_string_lossy()
        );
    } else {
        eprintln!("usage: pm --version");
        std::process::exit(2);
    }
}
