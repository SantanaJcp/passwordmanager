#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "ticket 04 laboratory requires Linux x86_64" >&2
  exit 1
fi

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
./scripts/cargo-local.sh test -p pm-vault --test human_transactions --locked --offline
printf '%s\n' \
  'PASS channel=SO_PEERCRED role=request-field-absent crypto=libsodium storage=sqlite-wal-full' \
  'PASS prepare=challenge60s commit=atomic receipt=idempotent audit=encrypted-atomic' \
  'LIMIT tls-rpk-alpn=ticket-03-lab host-reboot=NOT_RUN non-linux=NOT_RUN'
