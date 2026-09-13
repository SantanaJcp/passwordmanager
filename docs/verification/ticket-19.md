# Ticket 19 verification evidence

Date: 2026-09-12. Requirements: R04, R07, R19. Observed host: Linux x86_64; Rust 1.98.1; libsodium 1.0.22; SQLite is the repository-pinned bundled build. All CSV values, keys, vaults, identities, and paths are synthetic and disposable.

## TDD red/green

The public behavioral test was written before the import API. The first focused run was:

```text
./scripts/cargo-local.sh test -p pm-vault --test csv_import --locked --offline
```

It failed to compile with unresolved public imports (`CsvDelimiter`, `CsvEncoding`, `CsvField`, `CsvImportDecision`, `CsvImportProfile`, `CsvMapping`, `CsvRowStatus`) and missing `HumanVault::{preview_csv,prepare_csv_import}` methods. This was the intended API red, not a skipped test or dependency failure.

After implementing the parser, encrypted staging and the existing human commit integration, the same command reports:

```text
running 3 tests
test chrome_apple_and_mappable_csv_preserve_unicode_unknowns_and_require_signed_confirmation ... ok
test duplicate_decisions_pagination_and_audit_failure_are_atomic ... ok
test explicit_replace_disables_prior_delegation_and_input_limits_fail_closed ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

## Stable import and transaction seams

`pm-vault` exposes closed `CsvImportProfile`/`CsvMapping`/`CsvField` types, paged `CsvImportPreview`, explicit per-row `CsvImportDecision`, `CsvImportReport`, and `PreparedCsvImport`. The only publication path remains `HumanVault::commit`: `prepare_csv_import` durably stages independently encrypted native revision packages plus a 64-object paged manifest whose root and complete report are bound by the signed `import_commit` body.

Commit validates the staged root again and atomically publishes all selected revisions, canonical G5 `item-revision` events, signed outbox envelopes, one minimal encrypted `AuditAction::Import` record, report and replayable receipt. Replacement additionally publishes a human/device-signed G5 `disable(reason_code=replacement)` and disables local delegation in the same transaction. Imported items never create `credential_authorizations`. This preserves the existing ledger/reducer seam for tickets 16/17; no parallel engine, authority ledger, crypto, custody, or callback transaction was added.

The native tests cover:

- Chrome's exact required headers, RFC-4180 quotes/multiline fields and unknown columns;
- explicit Apple positional mapping including a real synthetic `otpauth://` value, and explicit semicolon/tab/UTF-16LE mappable profiles;
- exact versus candidate duplicates, invalid decisions, skip/keep/replace, replacement disable, 64-item manifest pagination, and stable receipt replay;
- Unicode, source-field preservation, malformed quoting, missing UTF-16 BOM, 257 columns and a row above 16 MiB;
- injected audit failure after staging, proving zero `vault_items`, authority events, outbox/report/receipt and audit effects until the same prepared transaction succeeds;
- absence of plaintext canaries in the SQLite database and sidecars, and reducer acceptance of the resulting canonical item-revision ledger.

## Real process/TLS laboratory

```text
./scripts/test-linux-csv-import-lab.sh
```

Observed result:

```text
PASS csv-import-e2e chrome=1 apple-explicit=1 mappable=1 unicode=1 unknown-preserved=1 malformed=no-effect symlink=rejected audit-failure=atomic response-loss=recovered restart=durable duplicate=explicit-skip paginated=2 source-unchanged=1 raw-canaries=absent
```

The lab creates real synthetic Chrome, Apple and mapped CSV files under a disposable user namespace. `pm-custody human-csv-import --confirm` opens a human-owned regular source with `O_NOFOLLOW`, validates stable identity/metadata before and after reading, then sends the actual preview/prepare request over TLS 1.3 with pinned human RPK and ALPN `pm-human/1`. Commit and receipt use the existing RPC opcodes. The lab exercises a deliberately dropped commit response, reconnects and recovers the durable receipt, restarts the custodian, reimports an exact duplicate through explicit skip policy, imports 70 records as two manifest pages, injects an audit-trigger failure, rejects malformed and symlink sources, confirms sources are byte-identical, and scans vault/sidecars for plaintext canaries.

No browser/keychain/private provider database is accessed and no source is deleted. The public laboratory profile is deliberately a non-TUI harness: arbitrary mapping composition is the stable `CsvMapping` engine API; ticket 25 owns interactive mapping UI and ticket 20 owns 1PUX.

## Repository gates and regression labs

Final commands recorded for the candidate:

```text
./scripts/check.sh
./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-csv-import-lab.sh
git diff --check
```

All are required to pass on the clean candidate. The CSV public route is the positive integrated evidence for this ticket; the older labs are regression evidence, not substitutes for it.

## Limits

This ticket does not implement 1PUX, production browser/keychain adapters, interactive TUI mapping, export, backup/restore, or provider sessions. The current public TLS lab transports a bounded source in the existing 18 MiB human frame, while the engine enforces the selected per-row/per-column/record limits; future streaming UI/adapters must feed the same preview/staging seam rather than bypassing the atomic commit.
