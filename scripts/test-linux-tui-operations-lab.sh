#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then echo "ticket 25 laboratory requires Linux x86_64" >&2; exit 1; fi
for tool in /usr/bin/tmux /usr/bin/wl-copy /usr/bin/wl-paste; do test -x "$tool"; done
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$root"
./scripts/cargo-local.sh build -p pm-custody -p pm-cli -p pm-sync --locked --offline
user=$(id -un); host_uid=$(id -u); host_gid=$(id -g)
subuid=$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subuid)
subgid=$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subgid)
test -n "$subuid"; test -n "$subgid"
unshare --user --mount --map-users "0:$host_uid:1" --map-users "1:$subuid:65535" \
  --map-groups "0:$host_gid:1" --map-groups "1:$subgid:65535" \
  env PYTHONDONTWRITEBYTECODE=1 PM_TMUX_SERVER=pm-ticket25 python3 "$root/crates/pm-custody/tests/tui_operations_lab.py" \
  "$root/target/debug/pm-custody" "$root/target/debug/pm" "$root/target/debug/pm-sync"
