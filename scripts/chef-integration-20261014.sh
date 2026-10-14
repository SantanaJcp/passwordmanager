#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Exact local composition. No cached PASS, external publication or installation.
set -euo pipefail
method=$(cd -- "$(dirname -- "$0")" && pwd)/chef-integration-20261014
exec python3 "$method/integrate.py" "$@"
