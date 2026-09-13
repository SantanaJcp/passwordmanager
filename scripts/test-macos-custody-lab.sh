#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "ticket 26 laboratory requires a native macOS runner" >&2
  exit 1
fi
if [[ "${PM_MACOS_EPHEMERAL_CI:-}" != 1 ]]; then
  echo "ticket 26 laboratory is restricted to the authorized ephemeral CI environment" >&2
  exit 1
fi
if [[ "$(id -u)" == 0 ]] || ! sudo -n true; then
  echo "ticket 26 laboratory requires a non-root user with passwordless sudo" >&2
  exit 1
fi
for command in ar cargo cc dscl launchctl plutil python3 script security sudo; do
  command -v "$command" >/dev/null || {
    echo "ticket 26 laboratory requires $command" >&2
    exit 1
  }
done

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
./scripts/cargo-local.sh build -p pm-custody -p pm-cli --locked --offline
./scripts/cargo-local.sh test -p pm-native-channel -p pm-vault --locked --offline
plutil -lint packaging/macos/com.santanajcp.passwordmanager.plist >/dev/null

python3 crates/pm-custody/tests/macos_lab.py \
  "$root/target/debug/pm-custody" \
  "$root/target/debug/pm" \
  "$root/packaging/macos/com.santanajcp.passwordmanager.plist"
