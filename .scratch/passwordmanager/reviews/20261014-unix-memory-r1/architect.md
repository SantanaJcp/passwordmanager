**Overall verdict: ISSUES.** The daemon candidate `7b7026e` has two P1 blockers. The two memory candidates, `a900a69` and `15bfaa2`, have no P0/P1 at source level. Nothing here was executed by me: every finding is read-only inspection or inference, and the runtime numbers below come from the workers' own reports.

All six SHAs resolve and all three diffs are non-empty:
- `ecc2e9d…7b7026e`: 9 files, +1611/−24 (contains the withdrawn `6728bbd`; I reviewed only the final head)
- `f56c993…a900a69`: 4 files, +347/−27
- `ea57a71…15bfaa2`: 3 files, +272/−15

## Standards

- **No new fallback (`no-fallbacks`).** `Provider::Laboratory` is built only inside `serve-attempt-lab` (`linux.rs:463,816ff` @7b7026e). The ordinary `serve-vault` always uses `Provider::Installed` (`linux.rs:804`). Missing config produces `ADAPTER_UNAVAILABLE`, and a missing registry rejects connections.
- **Withdrawn trust widening is gone.** `safe_parent` (`installed_unix.rs:27–45`) again accepts only ancestors owned by root (UID 0) or the custodian, plus root-owned sticky directories.
- **Synthetic data only.** Fixtures use the RFC 8032 §7.1 vector and `PM_CHEF_SYNTHETIC_*` values; no real credentials.
- **No synced, signed or event-format change.** `agent_wire.rs` only adds `verify_local()`, and the SSH frames are byte-identical (see below).
- **Inherited fallbacks, now active in the ordinary daemon (report only, not new):**
  - The worker loop discards errors with `let _` and polls every 5 ms (`linux.rs:975–976`).
  - Startup skips `recover_inflight` when the vault fails to open (`linux.rs:960–968`).
  - A full connection pool silently drops the new connection (`accept_one`).
  
  The author listed these. The hidden effect: a persistent error (for example `CLOCK_UNTRUSTED` inside `claim`) retries about 200 times a second with nothing visible. Each idle poll also opens two `IMMEDIATE` SQLite transactions, and I didn't measure how much that contends with human or agent writes. P2.

## Request

- **1A (registry): met at source level.** RPK→UID binding is tied to vault, device and server key. The bootstrap pair must be present. Migration requires a current human grant. Admission needs both the registry pin and the vault's per-operation grant check.
- **1A, partial (P2).** `publish` is create-only (`installed_unix.rs:201–213`) and `migrate` is the only writer. An agent the human enrols *after* migration can't be admitted unless someone deletes the custodian-owned 0400 file outside the tool and restarts. Without a registry, the daemon starts and silently drops every agent (`linux.rs:4185–4186`), so an operator can't tell "not migrated" from any other rejection. Not a security defect; a usability and truthful-state gap.
- **"Four connections per agent": not met.** See D1.
- **2A, "recovery without repeating authentication": contradicted on one path.** See D2.
- **Memory requests:** the 7 Ed25519 and 2 grant destinations are met (`a900a69`); SSH-owned wire buffers are met (`15bfaa2`). Remaining gaps are disclosed.

## Design

**D1 — P1 BLOCKER, new exposure.** The 4-connection limit is global across agents. Files: `connection_dispatch.rs:10,45` and `linux.rs:4185–4204` @7b7026e. Principles: `design`, `truthful-state`.

- **State:** the registry holds A (UID 2001) and B (UID 2002).
- **Sequence:**
  1. A opens 4 TLS connections and keeps them idle (the contract allows 5 minutes idle, renewable).
  2. B connects; `dispatch` sees `workers.len()==4` and returns `Ok(false)`, dropping B before its handshake.
- **Contract:** `agent-identity.md:117` @ecc2e9d says "4 conexiones/agente … cola llena rechaza, no elimina pendientes ajenos". The module comment "per-agent connection policy" is now false.
- **Why this is new:** at `ecc2e9d`, `accept_one` admitted only `bootstrap.agent_uid`, so global and per-agent were the same thing. This candidate turns it into a cross-agent limit.
- **Evidence:** the worker measured "A-full / B-denied"; I confirmed the code path by inspection.
- **Possible fix (a suggestion within 1A's representation latitude, not a new architecture):** the UID is the only identity known before the handshake. `Registry::parse` allows several RPKs per UID (`installed_unix.rs:173` checks only duplicate keys). Making UID→RPK one-to-one would let a per-UID counter enforce the per-agent bound. The total would then be bounded by 4 × registered agents.

**D2 — P1 BLOCKER, new bug.** The local preflight terminally fails reconciliation leases. Files: `installed_unix.rs:380–396,401ff` and `linux.rs:3636–3643,3686–3695` @7b7026e; `attempts.rs` `claim(true)`/`settle` @7b7026e. Principles: `truthful-state`, `no-fallbacks`. Evidence: INFERRED.

- **Sequence:**
  1. Attempt X reaches `waiting_for_human` or `indeterminate`.
  2. The adapter restarts, which is its external lifecycle under 2A, and its socket is missing for more than about 100 ms.
  3. `claim_waiting_for_reconciliation` picks X up.
  4. `select` → `endpoint_ready` gets NotFound and returns `Failed{ADAPTER_UNAVAILABLE}`.
  5. `settle` marks X terminal.
- **Other triggers:**
  - A metadata change on the adapters file or the custody files gives `ADAPTER_UNAVAILABLE` or `CUSTODY_UNAVAILABLE` the same way.
  - SSH waiting attempts are hit too, although `call_ssh_provider` never contacts the adapter during reconciliation.
- **Contrast with the lab path:** the same missing socket there gives connect `Err` → `Indeterminate`, which stays non-terminal.
- **Effect:** an attempt whose external outcome is unknown is published as FAILED. The agent can then start a new attempt and authenticate a second time.
- **Coverage:** the worker's "0-call" negative tests only cover new attempts, so this path is untested.
- **Fix:** for `reconciliation_only` leases, local readiness or config failure must not settle a terminal outcome. New `created` leases can keep the explicit `Failed`.

**D3 — P2.** `parse_routes` accepts an adapter UID equal to the custodian's (`installed_unix.rs:326–333`). The registry rejects that case (around `:168`). This is a role-boundary asymmetry; an agent can't exploit it.

**`a900a69`: no new findings.** The locked owners are scoped to each operation, and 64-byte allocations are negligible against the 32 MiB budget (`root.rs:26`). New behavior: when memlock is unavailable, signing and grant verification now fail with `ResourceUnavailable`. That is an intended fail-closed choice, consistent with `security-operations.md:58`. Disclosed, inherited P2: `open_audit_key` and `open_attempt_key` (`root.rs:1911,2116`) still decrypt key material into an ordinary `Vec`.

**`15bfaa2`: no findings.**
- `field_frame` matches `put_bytes` byte for byte (u32 big-endian length plus bytes), and `MAX_FRAME` is still enforced in `write_frame`.
- An out-of-memory failure after SSH auth succeeds maps to the existing status 3 (indeterminate), and the connection is not retained.
- Retained references and username/profile owners remain as disclosed.

## Not executed, needed before acceptance

Run under `flock /tmp/pm-cargo-window.lock`, in the ticket-03 UID-mapped namespace:
- `scripts/cargo-local.sh test -p pm-custody -p pm-crypto -p pm-ssh-client --locked --offline`
- `scripts/check.sh` once on the exact composed SHAs
- `chef_runtime_chroot.py registry|adapter …` as given in the report
- **New D1 repro:** A holds 4 connections while B connects; expected: B is admitted.
- **New D2 repro:** WAITING attempt, stop the adapter for 1 s, restart it; expected: attempt stays non-terminal and the adapter gets no second login call.

No native (Windows/macOS), security or G7 certification is implied. Integration of the exact sibling SHAs is still pending.

## Verdict

- `7b7026e`: **ISSUES**, blocked for merge by D1 and D2.
- `a900a69`: **PASS** at source level, nothing executed.
- `15bfaa2`: **PASS** at source level, nothing executed.
