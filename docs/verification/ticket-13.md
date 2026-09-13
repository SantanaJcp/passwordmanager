# Ticket 13 verification evidence

Date: 2026-09-13. Requirements: R03, R04, R09, R13. Observed host:
Linux x86_64. All identities, relying-party data, keys, certificates and
credentials used below are synthetic, and each process laboratory deletes its
private mount namespace, profiles and state when it exits.

## Implemented slice

`pm-crypto::PasskeyKeyPair` generates a distinct Ed25519 seed/public key for
each registration. It is not the TLS RPK, `SK_H`, an audit key, or an attempt
key. The signed human transaction stores exactly the G6 fields in the encrypted
logical revision: RP ID, user handle, credential ID, COSE algorithm -8,
private/public key, names, counter zero, backup-eligible true and backup-state
false. A passkey registration is not delegated automatically: a second,
explicit human `ENABLE <request-id>` ceremony uses the existing signed
`HumanVault::commit`/receipt/audit path.

Registration publication, encrypted provider response, authority event,
encrypted revision, outbox, audit head/record, challenge consumption and
receipt now share the same SQLite transaction. `passkey_registration_staging`
is only a narrow attachment to the existing human commit engine, not a second
transaction or authority engine. An audit insertion failure publishes neither
the item nor the browser response; after restart, the still-pending request can
be retried. Assertion confirmation similarly updates the durable ticket-08
attempt, encrypted browser response and encrypted audit in one transaction,
after rechecking current agent generation/revocation.

The fixed-ID MV3 extension has only `nativeMessaging` and one exact synthetic
origin permission. It has no popup, options/admin page, remote code, vault
access or key. Its isolated top-frame content script forwards a closed request;
the service worker replaces origin, RP, frame and document fields with
Chromium's `MessageSender`, binds each request ID to one document ID, and calls
only `org.passwordmanager.passkey`. The native host validates exact JSON fields,
the fixed extension origin, exact HTTPS origin/RP, top frame and bounded
document before using the existing TLS-1.3/RPK/ALPN agent channel. It returns
only public registration/assertion bytes; the passkey seed never leaves
custody.

`human-passkey-confirm` first retrieves the encrypted pending prompt through
the authenticated human TLS-RPK channel without `K_H`, then requires a real
`/dev/tty`, an exact request-bound `APPROVE`, and fresh hidden master-password
reauthentication. `presence` cannot satisfy required UV. Custody constructs the
WebAuthn client-data/authenticator-data sequence itself and signs only after
UP/UV plus live attempt/agent/credential checks. The same small TTY primitives
are reusable by later human surfaces; this ticket does not implement the full
23/24 interface.

## TDD and exact executable evidence

Red observations were behavioral, not missing-dependency substitutes:

- Before the passkey types existed, the public provider tests did not compile;
  their first green slice covered exact G6 persistence, independent keys,
  signatures, UV, idempotency and revocation.
- The first live CFT/MV3 request could not find its branded Native Messaging
  host. The lab now exposes CFT's documented system lookup only inside a
  disposable mount namespace; it never writes the host `/etc` or a human
  browser profile.
- A real post-restart registration poll returned `NOT_ALLOWED`: the durable
  nullable `attempt_id` was being decoded as a non-null vector. The public
  `response_for_peer` regression exposed the same failure and the decoder now
  handles the outer row and inner SQL `NULL` separately.
- Registration response publication was initially after the human commit. The
  test/lab contract was tightened so the encrypted response is staged and
  published by that same audited transaction; the audit-failure run stayed
  pending and retry succeeded after restart.

Focused public test:

```text
./scripts/cargo-local.sh test -p pm-vault --test passkey_provider --locked --offline
# 2 passed; 0 failed
```

Real browser/native/custody/TUI laboratory:

```text
PM_CFT_DIR=.scratch/lab-artifacts/cft/chrome-linux64 ./scripts/test-linux-passkey-lab.sh
PASS passkey-e2e browser=CFT-153.0.8010.36 mv3=real native-messaging=real bridge-uid=3 untrusted-agent-uid=4 agent-channel=tls1.3+rpk+alpn/pm-agent/1 human=tls1.3+rpk+alpn/pm-human/1
PASS passkey-custody key=independent+encrypted g6=exact registration=explicit-enable assertion=UP+UV audit=atomic restart=durable replay=idempotent
PASS passkey-adversarial origin+document+extension+host+unknown=denied iframe=no-content-script rogue-rpk=denied revoke-before-sign=denied secrets=absent
LIMIT cft=laboratory-instrument product-browser=ticket33-NOT_RUN passkey-login=ticket14-NOT_RUN cross-platform=NOT_RUN
```

The laboratory runs official pinned Google Chrome for Testing
153.0.8010.36 (`chrome` SHA-256
`79a4ebf6da53e4ceab11844257aabc5166f17b595dc694d6382cbee8ff50565f`)
with the real unpacked MV3 package and real Native Messaging framing. It uses
inherited CDP file descriptors only for laboratory observation; there is no
debugging port and no `--no-sandbox`. Browser profile, Native Messaging
manifest/config and RPK run under one dedicated browser-bridge UID, separate
from human, custodian and untrusted-agent UIDs. The untrusted agent cannot read
the bridge config/private key, process memory or CDP FDs and a rogue RPK is
refused. Thus manually launching the host from the agent UID cannot inherit the
browser bridge's technical identity.

The live path registers, survives a custody restart, exercises audit rollback,
replays the public response, explicitly enables the item, starts a real durable
attempt, refuses presence-only UV, signs after verified TTY approval, and
refuses a second pending assertion after agent revocation. It also rejects
false extension launcher, origin, document and native-host fields, verifies
that the iframe receives no content-script response, and scans custody/browser
artifacts for synthetic canaries.

Candidate quality gates:

```text
./scripts/check.sh
./scripts/clean-offline-build.sh
git diff --check
```

Observed candidate gates:

```text
./scripts/check.sh
# pinned inputs, fmt, workspace check/tests and clippy: exit 0

./scripts/clean-offline-build.sh
# removed 13,122 files / 3.0 GiB; locked/offline build finished in 31.48 s

git diff --check
# exit 0
```

The ten integrated Linux regression laboratories were then run sequentially,
followed by the ticket-13 laboratory; every command exited zero:

```text
./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-attempts-lab.sh
./scripts/test-linux-csv-import-lab.sh
./scripts/test-linux-sync-lab.sh
./scripts/test-linux-history-lab.sh
./scripts/test-linux-1pux-import-lab.sh
./scripts/test-linux-web-auth-lab.sh
./scripts/test-linux-passkey-lab.sh
# PASS: custody, signed human CRUD/audit, all content, two-RPK authority,
# durable attempts, CSV, three-custodian sync, history/purge, 1PUX,
# real Keycloak/CFT web auth, and real CFT/MV3/native passkey
```

Both CFT-using labs rechecked version 153.0.8010.36 and executable SHA-256
before launch. The baseline web-auth lab also ran real Keycloak 26.7.3; the
passkey laboratory deliberately does not treat its assertion as the ticket-14
OIDC login result.

## Exact limits

- CFT is a disposable Linux x86_64 laboratory instrument, not the product-owned
  Chromium build/package required by ticket 33 and not a production browser
  support claim.
- This is the custodial provider/bridge ceremony only. Ticket 14's P4 login via
  a real RP is not implemented or claimed here.
- No platform other than Linux x86_64 was run. Six-target packaging and native
  compatibility remain ticket 33.
- Formal Astra review remains the final DAG gate. Ticket resolution and unified
  integration verification belong to the separate merger.
