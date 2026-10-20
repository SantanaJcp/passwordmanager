#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Release binaries for scripts/install-linux-local.sh, built offline with the pinned toolchain.
set -eu
workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUSTUP_AUTO_INSTALL=0 exec flock -x /tmp/pm-cargo-window.lock "$workspace_root/scripts/cargo-local.sh" \
    build --release --locked --offline -p pm-cli -p pm-custody -p pm-web-auth -p pm-ssh-client --bins
