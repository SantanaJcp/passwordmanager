#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
[[ $# -ge 1 && $# -le 3 && ( "$1" == bootstrap || "$1" == vault || "$1" == audit || "$1" == sqlite-sync || "$1" == matrix || "$1" == inflight || "$1" == inflight-live || "$1" == canaries ) ]]
if [[ "$1" == matrix ]]; then
  [[ $# == 1 || ( $# == 2 && "$2" == trace ) ]]
elif [[ "$1" == inflight ]]; then
  [[ $# == 2 && ( "$2" == bootstrap || "$2" == audit || "$2" == vault || "$2" == crash || "$2" == result-sync ) ]]
elif [[ "$1" == inflight-live ]]; then
  [[ $# == 2 && ( "$2" == bootstrap || "$2" == audit || "$2" == vault ) ]]
elif [[ $# == 2 ]]; then
  [[ ( "$1" == bootstrap || "$1" == vault ) && "$2" == completed ]]
else
  [[ $# == 1 ]]
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
./scripts/cargo-local.sh build -p pm-custody -p pm-cli --locked --offline
user=$(id -un); host_uid=$(id -u); host_gid=$(id -g)
subuid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subuid)
subgid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subgid)
test -n "$subuid"; test -n "$subgid"
if [[ "$1" == audit ]]; then
  fixture=("$root/crates/pm-custody/tests/audit_custody_loss_lab.py" "$root/target/debug/pm-custody" "$root/target/debug/pm")
elif [[ "$1" == sqlite-sync || "$1" == matrix || "$1" == inflight || "$1" == inflight-live || "$1" == canaries ]]; then
  fixture=("$root/crates/pm-custody/tests/sqlite_sync_fault_lab.py" "$root/target/debug/pm-custody" "$root/target/debug/pm" "$root/crates/pm-custody/tests/sqlite_sync_interposer.c")
  if [[ "$1" != sqlite-sync ]]; then fixture+=("$@"); fi
else
  fixture=("$root/crates/pm-custody/tests/custody_loss_lab.py" "$root/target/debug/pm-custody" "$root/target/debug/pm" "$@")
fi
unshare --user --pid --fork --mount-proc \
  --map-users "0:$host_uid:1" --map-users "1:$subuid:65535" \
  --map-groups "0:$host_gid:1" --map-groups "1:$subgid:65535" \
  python3 "${fixture[@]}"
