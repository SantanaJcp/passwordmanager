**Verdict: ISSUES.** I found no P0. There is one P1, and it is a design and usability conflict, not a security hole: the design puts the installed config under `%ProgramData%\PasswordManager`, and the new config policy, as written, would likely reject every path there. Nothing in this review was compiled or run on Windows; every point below comes from reading the source at the pinned heads.

All six commits resolved, plus ecc2e9d, and each diff is non-empty (measured): the SID-only kernel identity change is 1 file (+389/−2), the Windows installed-config capability is 4 files (+1671), and the human `pm tui` entry is 5 files (+615). I read the chef-mode skill and its principles first and followed them. I wrote no files.

## Standards
- **P2, `truthful-state` / AGENTS "distinguish verified evidence".** `docs/verification/chef-installed-config-20261014.md:49` @2801c489 says the retained parent folder handles "retienen componentes sin share-delete".
  - Those handles are opened at `installed_config_windows.rs:513` with only `READ_CONTROL | FILE_READ_ATTRIBUTES`. Under Windows' share-mode rules, a handle with no read/write/delete access doesn't take part in sharing checks at all (inferred from NT semantics).
  - So the handles do not stop anyone from renaming or deleting those folders. What actually protects them is the ACL rule that only fixed system accounts may delete or rename, plus the by-path re-check in `verify_directories` (`:594`).
  - The doc should say "detected by re-check", not "pinned".
- **P2, `prove`.** The native ignored matrix assumes a "trusted ProgramData fixture" (`doc:68`). See P1 below: that fixture would probably fail at the `C:\ProgramData` level before reaching any positive case.

## Request
- **P1 (inferred from Windows' stock ACL; not measured; fails closed).** The approved 2A decision requires installed config that actually works, and `docs/design/distribution.md:44` puts the data at `%ProgramData%\PasswordManager`.
  - Stock `C:\ProgramData` carries `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`. It has no inherit-only flag, so it applies to ProgramData itself.
  - `check_ace` (`installed_config.rs:149–155` @2801c489) treats Users as an untrusted account on parent folders and rejects bits 0x2, 0x10 and 0x100. That is the parent's resolved policy: only bit 0x4 is allowed alone.
  - Result: `snapshot` (`installed_config_windows.rs:439`) fails on the ProgramData level, so `open` and `provision_new` can never succeed at the designed location on a stock machine.
  - This doesn't reopen 1A or 2A. It is a conflict between the resolved policy and the documented path, and it needs one native measurement (`icacls C:\ProgramData`) and then a decision (below).
- **P2, unrequested surface (inherited, now public).** The new bridge passes all user arguments through to the existing TUI (`pm-custody/src/lib.rs:128` @4c3a90c8). On Windows that includes the ticket-27 lab flag `--console-diagnostics <file>` (`tui.rs:703`), which writes probe escape sequences to the terminal and creates a diagnostics file.
  - No secret leak is visible: the module comment says it never logs cell contents.
  - But the doc describes the arguments as "installed profile/key/endpoint and bounded timers" only. Either reject the flag in `human_tui` or document it.
- **Confirmed OK (inferred from code):**
  - `pm tui` reaches only the fixed `tui` command (`pm-cli/src/lib.rs:63`). The Unix and Windows `run` dispatchers never see a user-chosen custody command.
  - No shell, PATH or other-binary path. `--json` returns `UNAUTHORIZED`/3 in both positions.
  - The Unix hardening call is idempotent. macOS setup still runs inside `linux::run`. The Windows `run` has no process-level hardening that the custody binary has and `pm.exe` lacks; static CRT applies to every Windows binary.
  - The TUI still checks that the profile role is human.
  - No `pm tui` without arguments: the spec doesn't define one, so I don't count it as a gap.
- **Not done yet:** neither `create_agent_instance_for_sids` nor `accepted_client_sid` has any caller in the crates (measured with `git grep`). `InstalledConfigFile` has no consumer either. Nothing here can be called a finished Windows product.

## Design
- **P2, kernel identity, new code** (`windows.rs:153–175` @f56c993b). `validate_canonical_sid` only checks that Windows can parse the SID text. The accept check at `:601` compares the user SID read from the impersonation token against the caller's text exactly.
  - If Windows accepts a text that doesn't round-trip, the pipe's ACL would let principal X connect while the allowlist names Y. Accept still fails closed, but X can occupy a slot in the bounded instance pool.
  - The only uncovered input left is an out-of-range subauthority such as `…-4294967296`. The test expects rejection, but it never ran on Windows.
  - Fix: compare `sid_string(converted) == value`, the same round-trip check `Sid::parse` already does in the config module (`installed_config_windows.rs:151`).
- **Connection lifetime: no finding.**
  - There is no `DisconnectNamedPipe` anywhere in the crate (measured with grep), so each instance serves exactly one connection.
  - `accept` clears the saved PID and SID first. Clones made before accept carry `None`. Clones made after accept share the only connection that instance can ever have.
  - The PID check in `verify` compares a value fixed at connect time with itself, so it really only checks that the pipe is alive; the SID binding comes from the instance's single connection.
  - Residual risk: if someone later adds disconnect-and-reaccept, existing clones would keep a stale SID. That one-connection-per-instance rule should be written down next to `accepted_client_sid`.
- **Size limit: checked, no finding.** The 16 KiB cap on SID text keeps the ACL below 64 KiB: at most about 40 KiB even with the shortest SIDs (inferred arithmetic). Existing 2..255 instance bounds, client access mask `0x12019b` without `FILE_CREATE_PIPE_INSTANCE`, and local-only clients are all preserved.
- **P3, `small-owned`.** `create_agent_role_instance` (`:474`) duplicates the descriptor and creation code of `create_role_instance`, differing only in whether the free is checked.
- **Config policy matches the brief (inferred):**
  - The installed service SID is checked against the exact `NT SERVICE\PasswordManager` lookup; TrustedInstaller is resolved by fixed OS lookup; nothing is learned from whoever owns the file.
  - Owner rules: SYSTEM or the exact service for the file and private folder; Administrators/TrustedInstaller trusted only on parent folders.
  - Rejected: protected-ACL violations, null ACLs, unknown ACE types/flags/masks, reparse points, hard links, UNC paths and non-fixed drives.
  - Content read is 1..16 KiB from the original handle only.
  - Publication: owner taken only from the current token if it is SYSTEM/service; new file then rename by handle with no replace; writer closed before the final snapshot; staging copy deleted only after proving it still sits at its staging name.
  - `published` / `publication_attempted` behave truthfully, and the object is `Send` but not `Sync`.

**Missing proof:**
- No Windows build or run for any of the three changes.
- The DACL-on-pipe assertions, the multi-SID accept fixture and the whole native config matrix have never run.
- Pure-policy GREEN 4/4 on Linux does not prove the Windows calls work.

**Decisions:**
1. Run `icacls C:\ProgramData` on a stock Windows 11 host before the native config fixture. *Recommend: yes.* Yes means the P1 gets measured instead of inferred.
2. If the stock ACL is confirmed: (A) keep the policy and move the config path, which changes `distribution.md`; or (B) on parent folders only, also allow 0x2, 0x10 and 0x100 for untrusted accounts, while still rejecting delete, delete-child, change-permissions and change-owner. The argument for B: a folder must be empty before it can be turned into a junction, and ProgramData always contains our private folder. *Recommend: B, after decision 1.*

Principles: `prove`, `truthful-state`, `design`, `small-owned`, `evidence`.
