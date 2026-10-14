**Source verdict: ISSUES.** I found no P0/P1 blocker in any of the three diffs. There are four P2 findings, mostly proof gaps and one claim in the docs that I think is wrong, plus four P3 duplication notes. I read the source only and ran nothing. This review does not certify Windows support, security or ticket closure.

**Resolved (measured, read-only git):** all six SHAs resolve. Each range is one commit:
- f56c993b: +389/−2, `windows.rs` only
- 2801c489: +1671 across the 4 listed paths
- 4c3a90c8: +615 across the 5 listed paths

Every diffstat matches the brief's path lists. **Callers (measured, `git grep` at each head):** `create_agent_instance_for_sids` and `accepted_client_sid` have no callers. `InstalledConfigFile` is only re-exported. The only live agent-pipe caller is still the single-SID `pm-custody/src/windows.rs:868`. So everything below is about the new capabilities as written, not about wiring that doesn't exist yet.

## Standards

- **P2 `truthful-state`/`evidence` (inferred) — `docs/verification/chef-installed-config-20261014.md:49` @2801c489.** Rule: "Never invent counts, freshness, progress or success."
  - The doc says the retained ancestor handles "retienen componentes sin share-delete".
  - But those handles are opened with `READ_CONTROL | FILE_READ_ATTRIBUTES` only (`installed_config_windows.rs:513`), with share `FILE_SHARE_READ` (`:519-520`).
  - On NT, share access is only recorded or checked when an open asks for read/write/execute/delete data access. A metadata-only handle therefore doesn't stop another process from renaming or deleting the ancestor.
  - The real protection is the identity re-check against the named path on every verification (`verify_directories`, `same_directory` `:305`). That check is present.
  - Fix: reword the doc, or open the ancestors with an access mode that actually participates in sharing. No code change is required for safety.
- I found no new fallbacks, credentials or real-data fixtures. The lab uses synthetic canaries (`chef_human_entry_lab.py:197`).

## Request

- Kernel, met (inferred): the SID comes from the real impersonated token. The test puts the owner SID second, so it can't pass by picking the first expected entry. State is reset before each accept (`windows.rs:593-594`), clones copy the captured SID, and `accepted_client_sid` calls `verify()` first (`:614`).
  - Epoch: the crate has no `DisconnectNamedPipe` (measured, `git grep` at f56c993b). An instance therefore can't be reconnected, so a clone's cached SID always belongs to the same connection.
  - Other requirements met: `PIPE_REJECT_REMOTE_CLIENTS`, the 2..255 bounds, mask `0x0012019b` without `FILE_CREATE_PIPE_INSTANCE`, and the single-SID path left unchanged.
- Config: every requested property is present in the source. This covers the fixed principals and OS lookups, the ancestor bit 0x4 vs bit 0x2 split, null DACL and unknown ACE rejection, CREATE_NEW plus flush/readback, no-replace rename by handle, closing the writer before capturing mtime, and the two error flags. Proving the staging name before cleanup is also there, and the type is `Send` but not `Sync`.
- **P2 runtime prerequisite (my recollection of Windows defaults, not measured) — `installed_config.rs:149-151` @2801c489.**
  - Concrete case: config at `C:\ProgramData\PasswordManager\…`, the location in `docs/design/distribution.md:44`.
  - Stock `C:\ProgramData` grants `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`. That ACE is not inherit-only, so it applies to `C:\ProgramData` itself. In masks: `0x2`, `0x4`, `0x10`, `0x100`.
  - Under the policy the parent already decided, `0x2|0x10|0x100` held by `Other` on an `Ancestor` is a `Policy` error. `open` and `provision_new` would then fail closed at the designed location on every stock host.
  - The fixture also requires a root under ProgramData and forbids changing ProgramData. Every positive case in that matrix would fail.
  - I'm not reopening the decision. A native `icacls C:\ProgramData` should be run before the matrix is scheduled. If my recollection holds, this becomes P1 for usability and needs a decision on location or policy.
- CLI, met (inferred): `pm tui` goes through `linux::run`/`windows::run` with "tui" fixed as the first argument. That keeps `configure_macos_process` and the existing entry hardening. `pm-custody/src/main.rs` has no Windows-only hardening the bridge would skip. `--json` is rejected in both positions. There is no PATH/exe lookup. Windows `pm tui --vault-id` is NOT_RUN.

## Design

- **P2 `design`/`small-owned` — `windows.rs:153` @f56c993b: the crate now has two different ways to canonicalize a SID.**
  - `validate_canonical_sid` rejects leading zeros, then relies on `ConvertStringSidToSidW` plus `IsValidSid`.
  - The new `Sid::parse` (`installed_config_windows.rs`) converts and checks that the text round-trips. That is the stronger, deterministic rule.
  - The test case `"S-1-5-21-1-2-3-4294967296"` (`:2312`) assumes the Win32 parser rejects an overflowing sub-authority. I don't know whether it does (guess).
  - If it saturates or wraps instead, the DACL grants a different SID than the text the expected list holds. Accept would still reject that client, but the pipe ACE would have gone to the wrong principal.
  - The input comes from the admin-controlled registry, so impact is limited and it fails closed. Fix: compare against the existing `sid_string` (`:1526`) for a round-trip check and drop the leading-zero heuristic.
- **P3 — `windows.rs:112`, `:474`.** `agent_pipe_sddl_for_sids` re-implements the agent SDDL format from `windows_pipe_sddl`/`agent_pipe_sddl`. `create_agent_role_instance` copies `create_sync_named` (`:541`) almost line for line; only the create call differs. Two builders of the same agent ACE now have to stay in sync. A shared helper that takes the create function would remove the copy. Old single-SID behaviour stays as requested.
- **P3 — `windows.rs:93`/`:117` vs `installed_config.rs` `INSTALLED_CONFIG_MAX_BYTES`.** The same 16 KiB contract is defined twice in one crate, in commits that aren't integrated yet. Derive one from the other when integrating. The `service_sid.len()` bound is dead, because the canonical check already limits it.
- **P3 `design` — `installed_config.rs:39`.** The two bools can represent `published=true, publication_attempted=false`. No code path produces that, and the parent specified this shape. A three-state enum (not attempted / attempted, outcome unknown / published) would make it unrepresentable. Optional, not a defect.
- **P3 — `pm-custody/src/lib.rs:120`, `:136`.** Unix hardening runs twice (`pm-cli/src/lib.rs:47` already calls it; the call is idempotent). The failure-to-category mapping copies `pm-custody/src/main.rs`. Either is harmless; a shared `Failure` → category function would remove the copy.
- Accept epoch (P3, inferred): the correctness of `accepted_client_sid` rests on an unwritten invariant, "one connection per instance". If a future consumer adds `DisconnectNamedPipe` and re-accepts, older clones keep a stale `Some(sid)`. A client that reconnects with the same PID and an impersonated thread token would then pass the PID check. Document the invariant at `accept`, or make `accept` one-shot.

**Proof gaps (new):**
- Nothing on Windows has been compiled or run: the kernel tests, the whole FFI module, the ignored native matrix, and `GetDriveTypeW` on a `\\?\C:\` root (`:481`).
- The 4/4 pure-policy GREEN is Linux-only and proves none of the FFI.
- CLI GREEN covers Linux x86_64 only; macOS and Windows are NOT_RUN.

**Inherited, not counted as new:** LocalFree/CloseHandle results ignored in `create_role_instance`, `impersonated_client_sid` and `token_sid`. Also `UnavailableEngine`/env fallback and JSON exit masking. All of these are already reported, and no new path depends on them.

**Principles used:** `truthful-state`, `evidence`, `prove`, `design`, `small-owned`, `no-fallbacks`.
