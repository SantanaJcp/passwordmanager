#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$workspace_root/scripts/cargo-local.sh" build -p pm-custody --locked --offline

user=$(id -un)
host_uid=$(id -u)
host_gid=$(id -g)
subuid=$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subuid)
subgid=$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subgid)
test -n "$subuid"
test -n "$subgid"

exec unshare --user \
  --map-users "0:$host_uid:1" --map-users "1:$subuid:65535" \
  --map-groups "0:$host_gid:1" --map-groups "1:$subgid:65535" \
  python3 "$workspace_root/crates/pm-custody/tests/linux_lab.py" \
  "$workspace_root/target/debug/pm-custody"
