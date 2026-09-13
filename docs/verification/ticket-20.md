# Ticket 20 verification evidence

Date: 2026-09-13. Requirements: R04, R07, R19. Observed host: Linux x86_64; Rust 1.98.1; SQLite is the repository-pinned bundled build. Every archive, field, credential, attachment and identity used below is synthetic and disposable.

## TDD red/green

The first public behavioral fixture was written before the 1PUX API. The focused command was:

```text
./scripts/cargo-local.sh test -p pm-vault --test onepux_import --offline
```

It failed to compile with the intended API red:

```text
error[E0599]: no method named `preview_1pux` found for struct `HumanVault`
error[E0599]: no method named `prepare_1pux_import` found for struct `HumanVault`
```

After the strict reader and preview seam were introduced, the same test remained red only on the still-missing `prepare_1pux_import`; it was not skipped or replaced by an internal unit test. After encrypted attachment streaming and common import commit integration, the final focused run is:

```text
running 4 tests
test changed_source_and_failed_commit_never_publish_partial_attachment_state ... ok
test hostile_archives_and_json_fail_closed_without_extracting_any_entry ... ok
test onepux_v3_maps_login_totp_notes_and_streamed_files_through_common_import_commit ... ok
test totp_note_ambiguous_and_unreferenced_types_remain_loss_visible ... ok

test result: ok. 4 passed; 0 failed; 0 ignored
```

## Reader, mapping and common staging

`HumanVault::preview_1pux` opens the selected regular source with `O_NOFOLLOW`, rejects hard-linked/changing sources, hashes its complete bytes, and never extracts an entry. The public multi-UID route uses `preview_1pux_file`: the authenticated human process opens its private mode-0400 source itself and transfers that already-open descriptor with one `SCM_RIGHTS` message only after the TLS/RPK session has authenticated and explicitly synchronized the transfer. The path is not sent to the custodian and the archive is not copied into an 18 MiB RPC frame or a plaintext temporary.

The ZIP reader permits only store/deflate and rejects encryption, duplicate central-directory names (including the zip crate's otherwise collapsed duplicate case), overlapping entries, absolute/traversal/backslash/NUL names, symlinks/devices, nested ZIP magic, truncated archives, missing references, inconsistent sizes, ratios above 100:1, excessive entry counts and exact physical/logical/file bounds. The JSON reader rejects duplicate keys, trailing data, malformed Unicode, more than 32 levels, over-range numbers and bounded-string/value violations. Before staging selected files it performs a conservative destination-space preflight for encrypted staging, atomic publication/WAL and framing overhead; it never silently reduces the selection. It streams every file with a 1 MiB plaintext buffer while hashing actual decompressed bytes, then independently encrypts each PMF1 chunk into SQLite staging.

The mapping covers password plus TOTP, TOTP-only, note/unrepresentable categories, referenced documents and unreferenced files/icons. It preserves Unicode, all distinct URLs, tags/favorite, notes, section fields and concealed markers, raw typed/unknown values, ambiguous repeated login designations, partial password history, state, external links and composite account/vault/item provenance in encrypted `source_fields`. `state=archived` becomes an active, non-delegated record tagged `source:archived`. It neither invents passkeys nor guesses SSH/API-token credentials from titles or generic concealed fields.

Selections reuse ticket 19's paged `CsvRowStatus`, `CsvImportDecision`, `CsvImportReport`, `PreparedCsvImport`, signed `import_commit`, audit record and replayable receipt. Exact comparison ignores locally generated custom-field/attachment IDs while comparing attachment name/MIME/size/digest; a changed record with the same composite external identity is only a candidate requiring keep/replace choice. No import creates `credential_authorizations` or enables an agent. Publication remains the one `HumanVault::commit` transaction; there is no second reducer, authority ledger, import commit engine or extracted staging tree.

The focused tests additionally prove a changed source aborts before preparation, an injected audit failure leaves zero item/revision/attachment/authority/report publication, and retrying the identical prepared command publishes all content and its receipt together. Database and sidecars are scanned for password/history canaries. Exact boundary unit checks accept a 100:1 ratio, 32 JSON levels, signed 64-bit maximum integer, 1 TiB logical total and 16 GiB attachment descriptor, and reject one unit beyond each applicable boundary without materializing a 16 GiB payload. A sparse archive just above the selected physical cap is rejected before parsing.

## Real process/TLS/RPK laboratory

```text
./scripts/test-linux-1pux-import-lab.sh
```

Observed result:

```text
PASS 1pux-import-e2e tls-rpk=1 multi-uid=1 archive-over-frame=1 attachment-streamed=21chunks source-fd=scm-rights private-source=0400 source-unchanged=1 process-crash=staging-rollback traversal=no-effect symlink=rejected audit-failure=atomic response-loss=recovered restart=durable exact-duplicate=explicit-skip plaintext-canaries=absent auto-enable=0
```

The disposable user-namespace lab runs custodian, human and agent as three distinct UIDs. Its synthetic 1PUX source is human-owned mode 0400 and contains a deterministic 20 MiB + 17 byte incompressible attachment, making the archive larger than the 18 MiB human frame. The real `pm-custody human-1pux-import --confirm` path authenticates mutual TLS 1.3 RPK with ALPN `pm-human/1`, transfers the source descriptor rather than archive bytes, paginates preview decisions, streams 21 encrypted attachment chunks, signs and commits through the normal human transaction, and recovers a deliberately lost commit response by durable receipt. SQLite observations show one `attachment_streams` row, 21 chunk rows, zero legacy `attachment_parts`, zero credential authorizations, and source `1pux` in the common import report.

The lab also kills the custodian only after observing both the transferred source descriptor and more than 1 MiB of uncommitted encrypted SQLite WAL staging; restart recovery leaves every committed-table count unchanged before a clean retry. The same public path rejects traversal and symlink fixtures with unchanged committed-table counts and no outside file. An injected audit trigger proves item/revision/stream/authority/outbox/receipt/report/audit atomicity; removing the trigger allows a clean retry. After custodian restart, reimport of the identical archive reports `new=0` and explicit exact skips. The source digest remains unchanged and vault/sidecars contain none of the plaintext password, history or attachment canaries.

## Repository gates and regression labs

Final candidate commands:

```text
./scripts/check.sh
./scripts/clean-offline-build.sh
./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-attempts-lab.sh
./scripts/test-linux-csv-import-lab.sh
./scripts/test-linux-1pux-import-lab.sh
git diff --check
grep -RIn 'TODO\|FIXME\|todo!\|unimplemented!' <ticket-20 changed source/test files>
```

The 1PUX process laboratory is this ticket's positive integrated evidence; older laboratories are regression evidence rather than substitutes. No private provider database, real credential, plugin, network account, TUI, backup/import-history feature or ticket 21+ behavior is accessed or implemented. A reboot and production service/FDE environment remain outside this disposable lab and are not claimed.
