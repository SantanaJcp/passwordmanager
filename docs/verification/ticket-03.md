# Ticket 03 verification evidence

Date: 2026-09-12. Requirements: R02, R09, R10, R11. Observed host: Linux
x86_64, kernel 7.2.3, glibc profile available, systemd 261; Rust 1.98.1,
rustls 0.23.44 with aws-lc-rs 1.18.1. All keys, paths and payloads were
generated solely inside a disposable synthetic laboratory.

This evidence covers the ticket-03 **non-privileged Linux laboratory** and
process restart only. It does not certify the production systemd profile, a
host reboot, FDE/offline theft protection, Linux AArch64, macOS or Windows.
Those native/reboot gates remain in ticket 30. No host users, services or
configuration were created or changed.

## TDD red/green

Commands ran in the isolated ticket worktree. Before the recorded reds, the
new pinned dependencies were resolved; a failed offline resolution before that
setup is not counted as a behavioral red.

1. Bootstrap fail-closed seam red:
   `./scripts/cargo-local.sh test -p pm-custody --test bootstrap_fail_closed --locked --offline`
   exited 101 because the public `pm-custody` process did not exist. Green: the
   same command passed. The real process exits 4 with exactly
   `CUSTODY_UNAVAILABLE` for missing, malformed, or overly permissive bootstrap
   files, and emits no stdout.
2. Native process laboratory red: `./scripts/test-linux-custody-lab.sh` reached
   the real binary but failed because `keygen` was absent and exited 2. Green:
   the same command passed after adding only the key/bootstrap/profile,
   custodian and probe seams exercised by the test.

## Observable Linux laboratory

`scripts/test-linux-custody-lab.sh` builds offline, discovers the invoking
user's subordinate UID/GID ranges, enters an unprivileged user namespace and
runs `crates/pm-custody/tests/linux_lab.py`. The harness fails rather than
falling back if mappings or helpers are unavailable. It uses actual kernel
UIDs `1=custodian`, `2=human`, and `3=agent`; it never supplies a claimed peer
UID to the product.

The final observed run printed:

```text
PASS uid_map='0       1000          1\n         1     100000      65535'
PASS custody_uid=1 human_uid=2 agent_uid=3
PASS bootstrap_sha256=3aedc06151037cd7bd3d8366ec8d88a72d94c4398840d644a8b0eeb6f1c15478 restart=process tls=1.3 rpk=mutual alpn=role-specific
LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN
```

Observed assertions through public processes:

- custodian state/bootstrap is owner UID 1 and mode `0400`; UID 3 cannot read
  or overwrite it;
- root-owned installed profiles and the laboratory binary cannot be replaced
  by UID 3; the custodian-owned runtime directory prevents socket unlink;
- both client and server obtain `SO_PEERCRED` from each connected Unix socket;
  the agent is rejected on the human endpoint before TLS;
- rustls negotiates TLS 1.3 RPK with Ed25519 SPKIs pinned in both directions,
  X25519 only, role-specific ALPN, and no early data or resumption; a second
  key used by the correct agent UID is rejected, proving UID alone is not the
  credential;
- an invalid private-key ACL returns the same public exit 4 and
  `CUSTODY_UNAVAILABLE`, without an internal error or key material;
- after terminating and starting a distinct custodian process, the bootstrap
  SHA-256 is unchanged and the agent reconnects without a TUI, master password,
  or regenerated identity.

The probe is deliberately not an authentication operation, JSON-RPC/MCP flow,
human administration API, or external-session action. Tickets 04 and later own
those behaviors.

## Final quality commands

```text
./scripts/cargo-local.sh test -p pm-custody --all-targets --locked --offline
# 1 integration test passed

./scripts/test-linux-custody-lab.sh
# multi-UID/RPK/ACL/process-restart laboratory passed; limits printed above

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check, tests and clippy passed

./scripts/clean-offline-build.sh
# clean locked/offline workspace build passed
```

The final two repository-wide commands are recorded only after their final run
on the candidate commit. Formal Astra review remains intentionally deferred to
the end of all tickets; the merger still must integrate and independently
verify this candidate before resolving ticket 03.
