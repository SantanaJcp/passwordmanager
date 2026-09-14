#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
./scripts/cargo-local.sh build -p pm-custody --locked --offline
user=$(id -un); host_uid=$(id -u); host_gid=$(id -g)
subuid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subuid)
subgid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subgid)
test -n "$subuid"; test -n "$subgid"
unshare --user --map-users "0:$host_uid:1" --map-users "1:$subuid:65535" \
  --map-groups "0:$host_gid:1" --map-groups "1:$subgid:65535" \
  --pid --fork --mount-proc \
  python3 "$root/crates/pm-custody/tests/cleanup_fault_lab.py" \
  "$root/target/debug/pm-custody" \
  "$root/crates/pm-custody/tests/cleanup_fault_interposer.c"
