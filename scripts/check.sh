#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo="$workspace_root/scripts/cargo-local.sh"

"$workspace_root/scripts/verify-native-ci-config.sh"
"$workspace_root/scripts/verify-macos-custody-ci-config.sh"
"$workspace_root/scripts/verify-build-inputs.sh"
"$cargo" fmt --all --check
"$cargo" check --workspace --all-targets --locked --offline
"$cargo" test --workspace --all-targets --locked --offline
"$cargo" clippy --workspace --all-targets --locked --offline
