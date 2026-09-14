#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
kc="${PM_KEYCLOAK_DIST:-$root/.scratch/lab-artifacts/keycloak/keycloak-26.7.3}"
java_home="${PM_JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
test -x "$kc/bin/kc.sh"
test "$("$kc/bin/kc.sh" --version | head -1)" = "Keycloak 26.7.3"
./scripts/cargo-local.sh build -p pm-custody -p pm-cli -p pm-web-auth --locked --offline
user=$(id -un); host_uid=$(id -u); host_gid=$(id -g)
subuid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subuid)
subgid=$(awk -F: -v user="$user" '$1 == user {print $2; exit}' /etc/subgid)
test -n "$subuid"; test -n "$subgid"
unshare --user --map-users "0:$host_uid:1" --map-users "1:$subuid:65535" \
  --map-groups "0:$host_gid:1" --map-groups "1:$subgid:65535" \
  python3 "$root/crates/pm-web-auth/tests/token_exchange_lab.py" \
    "$root/target/debug/pm-custody" "$root/target/debug/pm" \
    "$root/target/debug/pm-web-auth" "$kc" "$java_home"
