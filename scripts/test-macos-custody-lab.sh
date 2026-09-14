#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

configure_ticket26_build_commands() {
  local mode="$1"
  local root="$2"
  build_command=(
    "$root/scripts/cargo-local.sh" build -p pm-custody -p pm-cli
    --locked --offline --message-format=json-render-diagnostics
  )
  test_command=(
    "$root/scripts/cargo-local.sh" test
    -p pm-native-channel -p pm-vault -p pm-crypto -p pm-custody --locked --offline
  )
  if [[ "$mode" == diagnostic ]]; then
    build_command+=(--features macos-ticket26-diagnostics)
    test_command+=(--features macos-ticket26-diagnostics)
  fi
}

configure_ticket26_harness_command() {
  local mode="$1"
  local root="$2"
  local sodium_config="$3"
  harness_command=(python3 "$root/crates/pm-custody/tests/macos_lab.py")
  if [[ "$mode" == diagnostic ]]; then
    harness_command+=(--diagnostic)
  elif [[ "$mode" == pasteboard ]]; then
    harness_command+=(--pasteboard-diagnostic)
  fi
  harness_command+=(
    "$root/target/debug/pm-custody"
    "$root/target/debug/pm"
    "$root/packaging/macos/com.santanajcp.passwordmanager.plist"
    "$sodium_config"
  )
}

main() {
  local mode=normal
  case "$#" in
    0) ;;
    1)
      if [[ "$1" == --diagnostic ]]; then
        mode=diagnostic
      elif [[ "$1" == --pasteboard-diagnostic ]]; then
        mode=pasteboard
      else
        echo "ticket 26 laboratory accepts only --diagnostic or --pasteboard-diagnostic" >&2
        exit 1
      fi
      ;;
    *)
      echo "ticket 26 laboratory accepts at most one diagnostic-mode argument" >&2
      exit 1
      ;;
  esac

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
  for command in ar cargo cc cmp dscl file id lipo launchctl osascript plutil python3 script security stat sudo; do
    command -v "$command" >/dev/null || {
      echo "ticket 26 laboratory requires $command" >&2
      exit 1
    }
  done

  local root
  root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
  cd "$root"
  configure_ticket26_build_commands "$mode" "$root"
  local libsodium_out_dir
  libsodium_out_dir=$("${build_command[@]}" |
    python3 scripts/extract-libsodium-build-metadata.py)
  "${test_command[@]}"
  plutil -lint packaging/macos/com.santanajcp.passwordmanager.plist >/dev/null

  local machine
  machine=$(uname -m)
  case "$machine" in
    x86_64|arm64) ;;
    *)
      echo "ticket 26 laboratory does not accept machine architecture: $machine" >&2
      exit 1
      ;;
  esac
  local binary architectures
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

  configure_ticket26_harness_command \
    "$mode" "$root" "$libsodium_out_dir/source/libsodium-stable/config.log"
  "${harness_command[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
