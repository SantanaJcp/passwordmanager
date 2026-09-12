#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

workspace_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
git_common_dir=$(git -C "$workspace_root" rev-parse --path-format=absolute --git-common-dir)
repository_root=$(dirname -- "$git_common_dir")

export RUSTUP_HOME="$repository_root/.toolchain/rustup"
export CARGO_HOME="$repository_root/.toolchain/cargo"
export PATH="$CARGO_HOME/bin:$PATH"

exec cargo "$@"
