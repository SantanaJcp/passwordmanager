#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

if test "$#" -ne 4; then
    echo 'usage: native-preflight-unix.sh <linux|macos> <machine> <runner-arch> <rust-host>' >&2
    exit 2
fi

platform=$1
expected_machine=$2
expected_runner_arch=$3
expected_rust_host=$4

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required native CI command is absent: $1" >&2
        exit 1
    }
}

test "${CI:-}" = true || {
    echo 'CI=true is required' >&2
    exit 1
}
test "${RUSTUP_AUTO_INSTALL:-}" = 0 || {
    echo 'RUSTUP_AUTO_INSTALL=0 is required before invoking rustup' >&2
    exit 1
}
test "${RUNNER_ARCH:-}" = "$expected_runner_arch" || {
    echo "runner architecture mismatch: expected $expected_runner_arch, got ${RUNNER_ARCH:-unset}" >&2
    exit 1
}
test -n "${ImageOS:-}" || {
    echo 'ImageOS is absent' >&2
    exit 1
}
test -n "${ImageVersion:-}" || {
    echo 'ImageVersion is absent' >&2
    exit 1
}

machine=$(uname -m)
test "$machine" = "$expected_machine" || {
    echo "kernel architecture mismatch: expected $expected_machine, got $machine" >&2
    exit 1
}

for command_name in awk cargo file id ps rustc rustup stat sudo uname; do
    require_command "$command_name"
done

test "$(id -u)" -ne 0 || {
    echo 'workflow process unexpectedly runs as root' >&2
    exit 1
}
sudo -n true
test "$(sudo -n id -u)" -eq 0 || {
    echo 'passwordless sudo did not produce uid 0' >&2
    exit 1
}

case "$platform" in
    linux)
        test "${RUNNER_OS:-}" = Linux || {
            echo "runner OS mismatch: expected Linux, got ${RUNNER_OS:-unset}" >&2
            exit 1
        }
        for command_name in dpkg getconf getent openssl ps runuser setpriv stat systemctl useradd; do
            require_command "$command_name"
        done
        # shellcheck disable=SC1091
        . /etc/os-release
        test "${ID:-}" = ubuntu || {
            echo "Linux distribution mismatch: expected ubuntu, got ${ID:-unset}" >&2
            exit 1
        }
        dpkg --compare-versions "${VERSION_ID:?VERSION_ID is absent}" ge 24.04 || {
            echo "Ubuntu version is below 24.04: $VERSION_ID" >&2
            exit 1
        }
        kernel_version=$(uname -r)
        dpkg --compare-versions "${kernel_version%%-*}" ge 6.1 || {
            echo "Linux kernel is below 6.1: $kernel_version" >&2
            exit 1
        }
        glibc_version=$(getconf GNU_LIBC_VERSION | awk '{print $2}')
        dpkg --compare-versions "$glibc_version" ge 2.36 || {
            echo "glibc is below 2.36: $glibc_version" >&2
            exit 1
        }
        systemd_version=$(systemd --version | awk 'NR == 1 {print $2}')
        dpkg --compare-versions "$systemd_version" ge 252 || {
            echo "systemd is below 252: $systemd_version" >&2
            exit 1
        }
        pid_one=$(ps -p 1 -o comm= | tr -d '[:space:]')
        test "$pid_one" = systemd || {
            echo "PID 1 mismatch: expected systemd, got $pid_one" >&2
            exit 1
        }
        printf 'os=%s version=%s kernel=%s glibc=%s systemd=%s\n' \
            "$ID" "$VERSION_ID" "$kernel_version" "$glibc_version" "$systemd_version"
        ;;
    macos)
        test "${RUNNER_OS:-}" = macOS || {
            echo "runner OS mismatch: expected macOS, got ${RUNNER_OS:-unset}" >&2
            exit 1
        }
        for command_name in codesign dscl launchctl lipo pkgbuild plutil productbuild security spctl sw_vers; do
            require_command "$command_name"
        done
        product_version=$(sw_vers -productVersion)
        major_version=${product_version%%.*}
        test "$major_version" -ge 13 || {
            echo "macOS version is below 13: $product_version" >&2
            exit 1
        }
        printf 'os=macOS version=%s kernel=%s\n' "$product_version" "$(uname -r)"
        ;;
    *)
        echo "unsupported preflight platform: $platform" >&2
        exit 2
        ;;
esac

toolchain="1.98.1-$expected_rust_host"
if ! rustup toolchain list | awk -v expected="$toolchain" '$1 == expected { found = 1 } END { exit !found }'; then
    echo "required explicitly installed native Rust toolchain is absent: $toolchain" >&2
    exit 1
fi
export RUSTUP_TOOLCHAIN=$toolchain
rust_version=$(rustc --version)
printf '%s\n' "$rust_version" | grep -Eq '^rustc 1\.98\.1 ' || {
    echo "Rust version mismatch: $rust_version" >&2
    exit 1
}
cargo_version=$(cargo --version)
printf '%s\n' "$cargo_version" | grep -Eq '^cargo 1\.98\.1 ' || {
    echo "Cargo version mismatch: $cargo_version" >&2
    exit 1
}
actual_rust_host=$(rustc -vV | awk '/^host:/ {print $2}')
test "$actual_rust_host" = "$expected_rust_host" || {
    echo "native Rust host mismatch: expected $expected_rust_host, got $actual_rust_host" >&2
    exit 1
}

probe_dir=$(mktemp -d)
trap 'rm -rf "$probe_dir"' EXIT HUP INT TERM
cat >"$probe_dir/probe.rs" <<'EOF'
fn main() {
    println!("PM_NATIVE_CI_PROBE");
}
EOF
rustc "$probe_dir/probe.rs" -o "$probe_dir/probe"

case "$expected_machine" in
    x86_64)
        probe_file=$(file "$probe_dir/probe")
        printf '%s\n' "$probe_file" | grep -Eq 'x86[-_]64|x86_64' || {
            echo "compiled probe is not x86-64: $probe_file" >&2
            exit 1
        }
        ;;
    aarch64|arm64)
        probe_file=$(file "$probe_dir/probe")
        printf '%s\n' "$probe_file" | grep -Eq 'aarch64|arm64' || {
            echo "compiled probe is not ARM64: $probe_file" >&2
            exit 1
        }
        ;;
    *)
        echo "unsupported executable architecture assertion: $expected_machine" >&2
        exit 2
        ;;
esac
probe_output=$("$probe_dir/probe")
test "$probe_output" = PM_NATIVE_CI_PROBE || {
    echo "unexpected native Rust probe output: $probe_output" >&2
    exit 1
}

printf 'runner_os=%s runner_arch=%s image_os=%s image_version=%s user=%s uid=%s rust_host=%s\n' \
    "$RUNNER_OS" "$RUNNER_ARCH" "$ImageOS" "$ImageVersion" "$(id -un)" "$(id -u)" "$actual_rust_host"
printf 'PASS native-environment-preflight target=%s/%s scope=environment-only product-validation=NOT_RUN\n' \
    "$platform" "$expected_machine"
