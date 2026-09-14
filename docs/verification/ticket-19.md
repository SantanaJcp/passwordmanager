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

Commit validates the staged root again and atomically publishes all selected revisions, canonical G5 `item-revision` events, signed outbox envelopes, one minimal encrypted `AuditAction::Import` record, report and replayable receipt. Replacement additionally publishes a human/device-signed G5 `disable(reason_code=replacement)` and disables local delegation in the same transaction. Imported items never create `credential_authorizations`; the laboratory enables the first item only through a second explicit signed human transaction so that replacement is exercised against a genuinely enabled credential. This preserves the existing ledger/reducer seam for tickets 16/17; no parallel engine, authority ledger, crypto, custody, or callback transaction was added.

Ticket 19 is self-contained on its declared 05/07 dependencies. Its reducer accepts the three already-issued legacy reason codes (`owner_request`, `replacement`, `suspected_compromise`) in the same narrow decoder block shared with ticket 17; it does not rely on ticket 17 being merged. The replacement native test opens the real persisted event database with `CausalReducer`, observes the replaced item and observes generation 1 disabled.

The native tests cover:

- Chrome's exact required headers, RFC-4180 quotes/multiline fields and unknown columns;
- explicit Apple positional mapping including a real synthetic `otpauth://` value, and explicit semicolon/tab/UTF-16LE mappable profiles;
- exact versus candidate duplicates, invalid decisions, skip/keep/replace, replacement disable plus reducer projection, 64-item manifest pagination, and stable receipt replay;
- Unicode, source-field preservation, malformed quoting, missing UTF-16 BOM, 257 columns and a row above 16 MiB;
- injected audit failure after staging, proving zero `vault_items`, authority events, outbox/report/receipt and audit effects until the same prepared transaction succeeds;
- absence of plaintext canaries in the SQLite database and sidecars, and reducer acceptance of the resulting canonical item-revision ledger.

## Real process/TLS laboratory

```text
./scripts/test-linux-csv-import-lab.sh
```

Observed result:

```text
PASS csv-import-e2e chrome=1 apple-explicit=1 mappable=1 unicode=1 unknown-preserved=1 malformed=no-effect symlink=rejected audit-failure=replace-atomic-enabled response-loss=recovered restart=durable duplicate=replace+explicit-skip disable=g5+reducer-compatible paginated=2 source-unchanged=1 raw-canaries=absent
```

The lab creates real synthetic Chrome, Apple and mapped CSV files under a disposable user namespace. `pm-custody human-csv-import --confirm` opens a human-owned regular source with `O_NOFOLLOW`, validates stable identity/metadata before and after reading, then sends the actual preview/prepare request over TLS 1.3 with pinned human RPK and ALPN `pm-human/1`. Commit, explicit enable and receipt use the existing authenticated human connection and `HumanVault` transaction engine. The lab first enables the imported Chrome credential explicitly. It then injects an audit-trigger failure while replacing that enabled credential and verifies that item revision, authorization status/digest, authority ledger, outbox, receipt, report and audit counts are unchanged. The successful retry publishes one replacement revision and one G5 disable, and an exact reimport after process restart follows the explicit skip policy. The lab also exercises a deliberately dropped commit response and durable receipt recovery, imports 70 records as two manifest pages, rejects malformed and symlink sources, confirms every source (including the replacement source) is byte-identical, and scans vault/sidecars for plaintext canaries.

## Restart-lab race diagnosis

The first combined regression run intermittently reached the final restarted-agent probe before the replacement custodian was listening and returned `CUSTODY_UNAVAILABLE`. The cause was reproducible: `wait_for_sockets` treated the two socket pathnames left by the terminated prior process as readiness. A deterministic probe with two bound-then-closed Unix sockets reported false readiness in `0.000019s`. The harness now requires successful `AF_UNIX` connections to both listeners, while also checking that the child is alive. The same stale-socket probe is rejected after the change, and the full human transaction/restart lab passed 5/5 consecutive runs. This changes laboratory readiness only, not product retry or failure semantics.

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

## Unified merger verification

Candidate `8801a5ad47d178010e74b7af382a024330f5d665` was verified as a
descendant of declared base `996ac5d47e3a58e805f9a2ac39c9ca7ce96a13d8` and merged without
rewriting history as `25cc2b049375ea065c5607014e83f10b52781db6` on top of the unified
08/09/16 tree. The only conflict was the `pm-custody` Linux import list. Its
semantic resolution retained the existing attempt types (`AttemptOutcome`,
`AttemptState`, `AttemptVault`, `IdempotencyKey`, `StartAttempt`) together with
all CSV import types; no engine, schema or behavior was selected wholesale
from either side. No conflict markers or global Clippy suppression remain.

Focused regression commands observed after that resolution:

```text
./scripts/cargo-local.sh test -p pm-vault --test csv_import --locked --offline
# 3 passed; exit 0

./scripts/cargo-local.sh test -p pm-vault --test causal_reducer --locked --offline
# 6 passed; exit 0

./scripts/cargo-local.sh test -p pm-cli --test delegated --locked --offline
# 2 passed; exit 0

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, 56 integration tests and
# clippy passed; exit 0

./scripts/clean-offline-build.sh
# LATEST.tar.gz and its minisign passed; removed 10174 files/1.8 GiB and
# compiled the locked/offline workspace in 27.08 s; exit 0

git diff --check
# exit 0
```

All six current Linux laboratories then returned exit 0. The first three
reported the synthetic bootstrap hashes below:

```text
./scripts/test-linux-custody-lab.sh
# bootstrap_sha256=9a2543059dfbec91d43e3eebbcd0ff454caaf793d9138d8c17764f477e950a57

./scripts/test-linux-human-transaction-lab.sh
# bootstrap_sha256=18fef79d086f1a9f36866e3280a6e839cd6de3402ae126c9eef72a10bff28732

./scripts/test-linux-content-lab.sh
# bootstrap_sha256=799cd71bb4ed823dd66c31c78a32cd77c2841de923433db9f22f5ac61dabc5e9

./scripts/test-linux-authorization-lab.sh
# PASS authorization-e2e ... same-set=1 human-lock-independent=1
# suspend=denied revoke=terminal generation=2 restart=durable
# PASS authorization-path ... prepare-commit-receipt=replayed audit=atomic

./scripts/test-linux-attempts-lab.sh
# PASS attempts-e2e tls=rpk+alpn/pm-agent/1 provider=separate-uid ...
# PASS attempts-crash provider-calls=1 ambiguous=INDETERMINATE ... audit=atomic

./scripts/test-linux-csv-import-lab.sh
# PASS csv-import-e2e chrome=1 apple-explicit=1 mappable=1 unicode=1
# unknown-preserved=1 malformed=no-effect symlink=rejected
# audit-failure=replace-atomic-enabled response-loss=recovered restart=durable
# duplicate=replace+explicit-skip disable=g5+reducer-compatible paginated=2
# source-unchanged=1 raw-canaries=absent
```

The CSV process laboratory therefore covered the complete requested sequence:
Chrome import, separate human enable, CSV replacement, G5 disable observed by
the real causal reducer, restart, and an exact explicit skip. Its injected
audit failure rolled back the replacement revision, authorization, authority
event, outbox, receipt, report and audit row together. The attempts laboratory
continued to compare the five real CLI and MCP operations against the same
custodian/provider/vault. The `wait_for_sockets` change is limited to the test
harness: it requires successful Unix-socket connections and a live child so
stale pathnames cannot signal readiness; it does not alter product retry
semantics.

The local reason-code decoder needed by replacement is present in this ticket,
so this integration does not depend on ticket 17. No ticket 17 or 10 code,
formal Astra review, host reboot, production systemd/FDE, real provider secret,
browser database or keychain was run or claimed.

## Limits

This ticket does not implement 1PUX, production browser/keychain adapters, interactive TUI mapping, export, backup/restore, or provider sessions. The current public TLS lab transports a bounded source in the existing 18 MiB human frame, while the engine enforces the selected per-row/per-column/record limits; future streaming UI/adapters must feed the same preview/staging seam rather than bypassing the atomic commit.
