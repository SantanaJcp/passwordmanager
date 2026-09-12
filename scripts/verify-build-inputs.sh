#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sodium_dir="$workspace_root/third_party/libsodium"

(
    cd "$sodium_dir"
    sha256sum --check SHA256SUMS
)

tar -xOf "$sodium_dir/LATEST.tar.gz" libsodium-stable/configure.ac \
    | grep -Fqx 'AC_INIT([libsodium],[1.0.22],[https://github.com/jedisct1/libsodium/issues],[libsodium],[https://libsodium.org])'

"$workspace_root/scripts/cargo-local.sh" metadata --format-version 1 --locked --offline > /dev/null
feature_graph=$("$workspace_root/scripts/cargo-local.sh" tree -p pm-crypto -e features --locked --offline)
printf '%s\n' "$feature_graph" | grep -Fq 'libsodium-sys-stable v1.24.0'
if printf '%s\n' "$feature_graph" | grep -Fq 'libsodium-sys-stable feature "fetch-latest"'; then
    echo 'forbidden libsodium fetch-latest feature is enabled' >&2
    exit 1
fi
