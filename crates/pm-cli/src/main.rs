// SPDX-License-Identifier: AGPL-3.0-only

fn main() {
    if let Err(error) = pm_cli::run(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code().into());
    }
}
