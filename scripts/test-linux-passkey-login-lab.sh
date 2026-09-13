#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)";cd "$root"
kc="${PM_KEYCLOAK_DIST:-$root/.scratch/lab-artifacts/keycloak/keycloak-26.7.3}"
cft="${PM_CFT_DIR:-$root/.scratch/lab-artifacts/cft/chrome-linux64}"
java="${PM_JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}";test -x "$kc/bin/kc.sh";test -x "$cft/chrome"
test "$("$kc/bin/kc.sh" --version | head -1)" = "Keycloak 26.7.3"
test "$("$cft/chrome" --version)" = "Google Chrome for Testing 153.0.8010.36 "
test "$(sha256sum "$cft/chrome"|cut -d' ' -f1)" = 79a4ebf6da53e4ceab11844257aabc5166f17b595dc694d6382cbee8ff50565f
./scripts/cargo-local.sh build -p pm-custody -p pm-cli -p pm-web-auth --locked --offline
user=$(id -un);host_uid=$(id -u);host_gid=$(id -g);subuid=$(awk -F: -v user="$user" '$1==user{print $2;exit}' /etc/subuid);subgid=$(awk -F: -v user="$user" '$1==user{print $2;exit}' /etc/subgid)
test -n "$subuid";test -n "$subgid"
unshare --user --mount --map-users "0:$host_uid:1" --map-users "1:$subuid:65535" --map-groups "0:$host_gid:1" --map-groups "1:$subgid:65535" \
 python3 "$root/crates/pm-web-auth/tests/passkey_login_lab.py" "$root/target/debug/pm-custody" "$root/target/debug/pm" "$root/target/debug/pm-web-auth" "$root/target/debug/pm-passkey-bridge" "$kc" "$cft" "$root/integrations/chromium/passkey-extension" "$java"
