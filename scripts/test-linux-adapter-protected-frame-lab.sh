#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
./scripts/cargo-local.sh build -p pm-web-auth -p pm-ssh-client --locked --offline
python3 "$root/crates/pm-custody/tests/adapter_protected_frame_lab.py" \
  "$root/target/debug/pm-web-auth" "$root/target/debug/pm-ssh-client"
