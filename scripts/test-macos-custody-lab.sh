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
for command in ar cargo cc cmp dscl file lipo launchctl plutil python3 script security stat sudo; do
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

machine=$(uname -m)
case "$machine" in
  x86_64|arm64) ;;
  *)
    echo "ticket 26 laboratory does not accept machine architecture: $machine" >&2
    exit 1
    ;;
esac
for binary in target/debug/pm-custody target/debug/pm; do
  test -x "$binary" || {
    echo "ticket 26 native artifact is absent: $binary" >&2
    exit 1
  }
  architectures=$(lipo -archs "$binary")
  if [[ "$architectures" != "$machine" ]]; then
    echo "ticket 26 artifact architecture mismatch: expected $machine, got $architectures ($binary)" >&2
    exit 1
  fi
  file "$binary"
done

python3 crates/pm-custody/tests/macos_lab.py \
  "$root/target/debug/pm-custody" \
  "$root/target/debug/pm" \
  "$root/packaging/macos/com.santanajcp.passwordmanager.plist"
