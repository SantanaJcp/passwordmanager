#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

configure_ticket26_build_commands() {
  local mode="$1"
  local root="$2"
  build_command=(
    "$root/scripts/cargo-local.sh" build -p pm-custody -p pm-cli -p pm-sync
    --locked --offline --message-format=json-render-diagnostics
  )
  test_command=(
    "$root/scripts/cargo-local.sh" test
    -p pm-native-channel -p pm-vault -p pm-crypto -p pm-custody -p pm-sync --locked --offline
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
  local final_phase_only="$4"
  harness_command=(python3 "$root/crates/pm-custody/tests/macos_lab.py")
  if [[ "$mode" == diagnostic ]]; then
    harness_command+=(--diagnostic)
  elif [[ "$mode" == pasteboard ]]; then
    harness_command+=(--pasteboard-diagnostic)
  fi
  if [[ "$final_phase_only" == true ]]; then
    harness_command+=(--final-phase-only)
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
  local final_phase_only=false argument
  for argument in "$@"; do
    case "$argument" in
      --diagnostic|--pasteboard-diagnostic)
        [[ "$mode" == normal ]] || { echo "duplicate/conflicting diagnostic mode" >&2; exit 1; }
        if [[ "$argument" == --diagnostic ]]; then mode=diagnostic; else mode=pasteboard; fi
        ;;
      --final-phase-only)
        [[ "$final_phase_only" == false ]] || { echo "duplicate final-phase mode" >&2; exit 1; }
        final_phase_only=true
        ;;
      *) echo "unknown ticket 26 laboratory argument" >&2; exit 1 ;;
    esac
  done

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
  # W6 phase 2 diagnostic: measure duplicate revision decoding without changing gates.
  export PMW6_TIMING=1
  configure_ticket26_build_commands "$mode" "$root"
  local libsodium_out_dir
  libsodium_out_dir=$("${build_command[@]}" |
    python3 scripts/extract-libsodium-build-metadata.py)
  "${test_command[@]}"
  cc -Wno-deprecated-declarations -framework AppKit \
    crates/pm-custody/tests/macos_pasteboard_probe.m -o target/debug/macos-pasteboard-probe
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
  for binary in target/debug/pm-custody target/debug/pm target/debug/pm-sync target/debug/macos-pasteboard-probe; do
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
    "$mode" "$root" "$libsodium_out_dir/source/libsodium-stable/config.log" \
    "$final_phase_only"
  "${harness_command[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
