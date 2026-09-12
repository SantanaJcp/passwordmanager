#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo="$workspace_root/scripts/cargo-local.sh"

"$workspace_root/scripts/verify-build-inputs.sh"
"$cargo" clean
"$cargo" build --workspace --all-targets --locked --offline
