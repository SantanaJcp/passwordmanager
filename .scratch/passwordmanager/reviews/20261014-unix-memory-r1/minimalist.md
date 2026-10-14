**Minimalist R1, source verdict: ISSUES.** From the Necessity lens I found nothing at P0 or P1, so nothing here blocks. All findings are P2. The vector still can't be PASS: the daemon candidate's own report says ISSUES (the GLOBAL4 problem, Windows and macOS NOT_RUN, full check never rc0), and exact-sibling composition is still pending.

Review route: done directly by Claude Opus 5.5 against an author on Codex gpt-6.1-sol, as R1 of 2. I ran no panel. Every SHA in the vector resolved with `git rev-parse --verify` and each diff had content (measured): 7b7026e has 9 files and +1611/−24, a900a69 has 4 files and +347/−27, 15bfaa2 has 3 files and +272/−15. I read 6728bbd only through 7b7026e and never judged it on its own. All evidence below comes from read-only `git show` and `git grep` on the pinned heads and is **inferred**, not runtime.

## Standards

Rules cited: AGENTS.md "keep changes focused", plus chef-mode `small-owned` (Minimize Reader Load) and `no-fallbacks` (migrate callers, then delete the old path).

- **S1 · P2 · 7b7026e `linux.rs:4280`: dead agent-pin parameter chain.** `handle_connection` now takes `_peer_rpk` and never uses it. The value is still passed down from `serve_independent_accept_lanes(agent_spki)` (`:1002`, `:1039`) through `accept_one(peer_rpk)` (`:4161`, `:4203`, `:4213`, `:4218`). In ordinary vault mode the agent key is now the RPK proven by TLS, matched against the registry (`:4337–4346`). A new reader will still believe the bootstrap SPKI pins the agent. Windows has its own separate `peer_rpk` (`windows.rs:354`), so deleting the Unix chain changes nothing there. Principles: `small-owned`, `no-fallbacks`.
- **S2 · P2 · 7b7026e `agent_wire.rs:31` and `:190`: the same file is checked several times in a row.**
  - The only Unix caller of `serve_agent` already ran `admission.verify()` at `linux.rs:4332`, and that call ends in `verify_local` (`custody_admission.rs:78`). On Windows, `local` is always empty, so line 31 does nothing. Before the first agent request, the registry is read three times: accept, handler, then `serve_agent`.
  - At `:190`, `verify_local` is followed by `verify_admission_custody`, which calls `verify()` again for opcodes 30, 33, 40 and 41. Those requests read the registry twice.
  - This is a cost and reader-load problem, not a correctness one. Keep `:190` because it is the per-request revocation point; `:31` can go. `small-owned`.
- **S3 · P2 · 7b7026e `installed_unix.rs:370`.** `Adapters::load` fingerprints the file again right after `read_installed`, which already compared the stamps by handle and by name. `select` (`:380`) checks again before every use, so these three lines add nothing. `small-owned`.

## Request

- **Covered (inferred):**
  - 1A: the registry format `PMAR1` is bound to vault, device and server RPK. Migration requires the current human grant for every RPK. There is no TOFU, and no learning of identity from labels.
  - 2A: `PMAC1` binds integration, version, profile, method, endpoint and UID.
    - Missing adapter config gives `ADAPTER_UNAVAILABLE`; a route that doesn't match gives `UNSUPPORTED_INTEGRATION`.
    - `Provider::Laboratory` is only built in `serve_attempt_lab`, so no lab fallback is new.
  - The version is checked to be 1 and then discarded (`:314`). That is equivalent to binding it today: pm-vault only admits version 1 (`attempts.rs:1809`), and the lease exposes no version. Not a finding.
- **Inherited silent drop:** this is not a new bug and I'm not asking for a rewrite.
  - Where: 7b7026e `linux.rs`, `accept_one`, the `let Some(registry) … else { return Ok(()) }` branch.
  - When it fires: `serve-vault` starts healthy without `.agent-registry`, and every agent connection is then closed without a reason. The report says the inherited labs hit exactly this.
  - What it hides: "not migrated" looks like an ordinary socket close. 1A only requires rejection, which happens, so I'm reporting it, not demanding a change.
- **GLOBAL4 A-full/B-denied:** this is a measured limitation the report carries openly as ISSUES. It is inherited from the global handler cap, not added by this diff. It belongs to the G4 admission contract and must not be counted as a partial PASS.
- **a900a69:** the seven Ed25519 destinations and two grant destinations match the request. The `decode_sealed_key_context` change (around `root.rs:4434`) is needed, because it stops copying the key onto the stack. Nothing extra was added.
- **15bfaa2:** the scope is exact. `put_bytes` (`lib.rs:633`) stays only for a public constant at `:353`. Moving it into `field_frame` would require memlock for public data, which is a new failure mode, so I'm **not** recommending it.

## Design

- **D1 · P2 · 7b7026e: two mechanisms for "this installed file is pinned since start".**
  - The registry uses `CustodyAdmission.local: Vec<(PathBuf, [u8;32], Fingerprint)>` (`custody_admission.rs:29`, `:50`). It has one caller (`linux.rs:792`), and the function pointer passed in is always `installed::fingerprint`.
  - The adapters use their own field, checked inside `select`.
  - A Vec plus a function pointer for a single entry is speculative flexibility. `small-owned`, `design`.
  - Side effect (inferred): if the registry is changed, `verify()` fails in `accept_one` for the **human lane too**. The human loses the TUI (and with it revocation) until a restart. This fails closed and matches "changes require restart", but it isn't written down.
- **D2 · P2 · 7b7026e: an illegal state can be represented.**
  - `Provider::Installed(Option<Adapters>)` (`linux.rs:440–442`) and `VaultService.registry: Option` are separate fields. The rule "installed mode requires a registry" is only enforced at runtime (`:3637–3639`).
  - Meanwhile `Adapters::load` accepts `registry=None` and skips UID separation (`installed_unix.rs:366`, `is_some_and`). This can't be exploited today because provider use fails with `CUSTODY_UNAVAILABLE` anyway.
  - Folding the registry into `Provider::Installed { registry, adapters }` removes both the runtime check and the skipped branch. `design` (Type System Discipline).
- **D3 · P2 · 7b7026e `installed_unix.rs:289`: duplicated knowledge.**
  - `supported()` repeats the integration/method matrix of `pm-vault::matches_authentication_profile` (`attempts.rs:1808`).
  - If the two drift, valid config is rejected. That is the safe direction, and the same pattern already exists in pm-interface and pm-cli, so this is a "consider".
  - Related: the "no adapter UID in the registry" check is written twice (`:366`, `:468`), and `Registry.entries` is read directly in three places even though `keys_for` exists.
- **D4 · P2 · a900a69, inherited.** The seed → expanded → public-key derivation is repeated seven times (`root.rs:1685`, `1712`, `1779`, `1852`, `3442`, `3708`, `4737`), and the diff edited all seven by hand. A future eighth site using a stack array wouldn't be caught. One helper would make the protected destination the only possible path. This is a "consider", not a merge condition.

## Coverage I did not run

Nothing was executed. These are the commands I would run, all with `--locked --offline`:

1. `scripts/cargo-local.sh build -p pm-custody -p pm-cli -p pm-web-auth --example chef_runtime_open_channel --bins`, then both modes (`registry` and `adapter`) of `chef_runtime_chroot.py`. These need Linux with the ticket-03 namespace and `/etc/subuid` and `/etc/subgid` maps.
2. `cargo test -p pm-crypto --test protected_signing --test protected_grant_context` and `cargo test -p pm-ssh-client wire_memory_tests`. These need Linux where `RLIMIT_MEMLOCK` can be lowered.
3. `scripts/check.sh` once on the integrated tree, then `kitchen integrate` on the exact SHA vector.

Results the author reported (RED→GREEN, clippy rc0 on the targeted packages, pm-web-auth with zero calls on the negative cases) are worker-reported, not mine. No native or security certification is claimed, and none should be inferred from this review.
