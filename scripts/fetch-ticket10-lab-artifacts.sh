#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

# Fetches only the disposable, pinned Ticket 10 laboratory instruments. Chrome
# for Testing is not the Chromium-from-source product artifact required by 29/33.
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
out="${PM_TICKET10_ARTIFACT_DIR:-$root/.scratch/lab-artifacts}"
downloads="$out/downloads"
mkdir -p "$downloads" "$out/keycloak" "$out/cft"

fetch() {
  local url=$1 file=$2 sha=$3 bytes=$4
  if [[ ! -f "$file" ]]; then
    curl --fail --location --proto '=https' --tlsv1.2 --output "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  test "$(stat -c %s "$file")" = "$bytes"
  printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status
}

kc_archive="$downloads/keycloak-26.7.3.tar.gz"
cft_archive="$downloads/chrome-linux64-153.0.8010.36.zip"
fetch "https://github.com/keycloak/keycloak/releases/download/26.7.3/keycloak-26.7.3.tar.gz" \
  "$kc_archive" "77657f30b7e90d70f727712ce1c967f430fd6a5e9f458d32d8c6df0635345f47" 176448763
fetch "https://storage.googleapis.com/chrome-for-testing-public/153.0.8010.36/linux64/chrome-linux64.zip" \
  "$cft_archive" "167a098c4fdec156b58a9f678c90a84f9072d789f9c6e7b35496a6987b8b7ef8" 195711476

rm -rf "$out/keycloak/keycloak-26.7.3" "$out/cft/chrome-linux64"
tar -xzf "$kc_archive" -C "$out/keycloak"
unzip -q "$cft_archive" -d "$out/cft"
test "$(sha256sum "$out/cft/chrome-linux64/chrome" | cut -d' ' -f1)" = \
  "79a4ebf6da53e4ceab11844257aabc5166f17b595dc694d6382cbee8ff50565f"
test "$("$out/keycloak/keycloak-26.7.3/bin/kc.sh" --version | head -1)" = "Keycloak 26.7.3"
test "$("$out/cft/chrome-linux64/chrome" --version)" = "Google Chrome for Testing 153.0.8010.36 "
printf 'READY ticket10-lab keycloak=26.7.3 cft=153.0.8010.36 artifact-dir=%s\n' "$out"
