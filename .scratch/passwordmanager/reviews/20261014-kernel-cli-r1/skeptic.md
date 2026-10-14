**Verdict: ISSUES.** This is a source-only review, and nothing was executed. I found no P0. There is one P1 in the design: the ancestor policy rejects the stock ACL of the folder where the design places this config. The rest are P2/P3 proof gaps.

- **Author:** Codex Sol medium, according to the brief. The commit trailers don't name a model. I'm the other family (Claude Opus 5.5) and reviewed directly, with no panel and no delegation (`cross-review`).
- **Mode:** Design+diff. All 6 SHAs resolve with `git rev-parse --verify`, and every diff is non-empty:
  - SID kernel identity `ea57a717..f56c993b`: 1 file, +389/−2.
  - Installed config `a900a69f..2801c489`: 4 files, +1671.
  - Human CLI entry `2f818c7d..4c3a90c8`: 5 files, +615.
  - `f56c993b` is an ancestor of `2801c489`. `4c3a90c8` contains neither of the other two.

## Standards

No findings. Fixtures and documents use synthetic data. I checked the links in `chef-cli-human-entry-20261014.md` against `4c3a90c8`: `decisions.md` exists, and the anchor `agent-identity.md#7-wireclimcp-v1` matches `## 7. Wire/CLI/MCP v1`. Both verification docs declare Windows/macOS NOT_RUN and don't overclaim support.

## Request

**R1 — P2, test coverage (`prove`). `installed_config_windows.rs:1188-1218` @2801c489.**
- The brief asks for "each test must catch fix revert". The native negative cases (`extra-write`, `permission-change`, `null-dacl`, `wrong-owner`, `unknown-ace`) change the DACL or owner *after* the snapshot. Then they only assert that `verify_snapshot().is_err()`.
- Any change already fails the byte comparison at `:859` (`&current != expected`).
- So the matrix would still pass if `check_ace`, `Principals::classify`, the OWNER_RIGHTS mapping or the ACE offset parsing (`:395-439`) all returned Ok.
- No native test opens a fresh object whose DACL or owner is disallowed but stable. No native test exercises an ancestor.
- Even once someone runs it, the FFI policy would stay unproven. Only the pure `check_ace` tests prove the masks.

**R2 — P3, proof gap. `windows.rs:153-171` @f56c993b.**
- `validate_canonical_sid` only rejects leading zeros and then trusts `ConvertStringSidToSidW`. It doesn't do a round-trip comparison.
- `Sid::parse` in `installed_config_windows.rs:132-156` does do the round-trip.
- The test at `windows.rs:2312` assumes Windows rejects `…-4294967296`. That's NOT_RUN.
- If Windows saturated that value instead, the DACL would grant access to a different binary SID than the allowlist entry. `accept()` compares strings, so it would still reject that client. Authentication fails closed, but the DACL would be broader than intended. Fix: compare the string back after conversion, as `Sid::parse` does.

**R3 — Noted (`truthful-state`).**
- No production code calls `create_agent_instance_for_sids` or `accepted_client_sid` at any of the three heads.
- Custody still uses the single-SID `create_agent_instance` (`pm-custody/src/windows.rs:868`).
- Multi-principal binding is not wired into the product. That matches the brief. It must not be reported as done.

**Human CLI: no findings.**
- `pm tui` dispatches the fixed `tui` command in-process (`pm-custody/src/lib.rs`, `human_tui`).
- Hardening matches the existing native entry (inferred from the code):
  - Unix: `harden_unix_process`, already called earlier by `pm_cli::run`; calling it twice is harmless.
  - macOS: `configure_macos_process`, inside `linux::run`.
  - Windows: neither entry applies any extra hardening.
- `--json` returns UNAUTHORIZED/3 before the TUI starts.
- The test `human_entry_invalid_arguments_never_enter_delegated_transport` does catch a revert: it expects exit 2, while the base gives 3.
- The MCP test is a regression guard; it does not catch this revert.
- On Windows the parser takes `--vault-id`, NOT_RUN.

## Design

**D1 — P1, but not a security blocker: the feature can't work in its designed location.**
- Code: `installed_config.rs:110-151`, used from `installed_config_windows.rs:564-571` @2801c489.
- The design places data in `%ProgramData%\PasswordManager` (`docs/design/distribution.md:44` @ecc2e9d). `canonical_path` makes `C:\ProgramData` an Ancestor.
- The stock ACL of `C:\ProgramData` includes `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`. Because the ACE has no inherit-only flag, it applies to the folder itself.
- The mask is `0x2|0x4|0x10|0x100`. `check_ace` rejects `0x2|0x10|0x100` for `Other`, so the result is `Op::Policy`.
- On stock Windows 11, `open` and `provision_new` would therefore always fail closed under ProgramData.
- The fixture in `chef-installed-config-20261014.md:68` ("Namespace efímero bajo ProgramData", without changing ProgramData) can't pass its positive cases.
- This is inferred from the widely documented default ACL; I did not measure it on a host. The policy as written is consistent with the parent's decision. The conflict is with the location.

**Decision for the parent or owner** (this doesn't reopen 1A/2A):

1. Before choosing, measure `icacls C:\ProgramData` once in an authorized native lab.
2. My recommendation is **B**. If the measurement confirms the ACE:
   - **A:** move the public config's ancestry under `%ProgramFiles%\PasswordManager`. Its stock ACL is owned by TrustedInstaller and gives Users only RX, so it passes the policy unchanged.
   - **B:** add a narrow exemption for exactly that Users ACE on that ancestor. This needs a separate, explicit approval because it changes the confirmed policy.

**D2 — P3, the doc overclaims.**
- `chef-installed-config-20261014.md:49` says the ancestor handles "retienen componentes sin share-delete".
- But the directories are opened with only `READ_CONTROL|FILE_READ_ATTRIBUTES` (`installed_config_windows.rs:512-519`). Handles with no read, write or delete access don't take part in sharing checks, so they don't stop anyone renaming or deleting those folders.
- The real controls are re-probing the paths (`same_directory`) plus the policy that denies DELETE and DELETE_CHILD to untrusted principals. The doc should say that.

**D3 — P3.**
- The `wrong-owner` case (`:1203`) assigns BA as owner. That needs SYSTEM or SeRestorePrivilege.
- So the matrix only runs as SYSTEM, despite "SYSTEM o cuenta virtual" in `:71` of the doc.
- `Principals::new` (`:215`) also requires `NT SERVICE\PasswordManager` to be installed. That's a runtime prerequisite that needs an install, which is not authorized.

**D4 — Noted, a future risk.**
- The connection epoch is safe today. There is no `DisconnectNamedPipe` anywhere, and each instance gets exactly one `accept`.
- Under static identification there's no reaccept or token change in a live connection, so clones stay consistent (inferred).
- If someone ever adds disconnect-and-reuse, clones would keep a stale `client_sid` while `verify()` only checks PID and Peek. That would need a connection generation counter.

## Merge danger

- **Kernel:** a two-way door, additive. It's safe because the SID check happens after impersonation and gates `accept`. Proof: I pointed at the lines; nothing ran on Windows.
- **Config:** additive, with no consumer yet, and it fails closed. I traced the cleanup and publication paths:
  - Staging is deleted only after verifying it still has the staging name.
  - The flags `published` and `publication_attempted` are truthful.
  - The writer is closed before the reader captures the timestamp.
  - Drop aborts if a close fails, so cleanup success is never faked.
- **CLI:** two-way door. Measured by the worker on Linux only.
- **Still unproven:**
  - The whole Windows FFI, including whether it compiles.
  - The ACE parser.
  - `GetDriveTypeW` with the `\\?\` prefix.
  - Relative rename via `RootDirectory`.
  - Any macOS or Windows execution of `pm tui`.

**Route:** direct review by Claude Opus 5.5, Standard tier, no subagents. I wrote no files; the parent persists this to `skeptic.md`.
