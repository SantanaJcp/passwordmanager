# SPDX-License-Identifier: AGPL-3.0-only
"""Observe the original custody-loss assertion without changing its outcome.

Run in the existing UID namespace with this worktree's built custody/CLI paths,
then bootstrap|vault and optional completed. No payloads or IDs are printed.
"""
import json
import pathlib
import sqlite3
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "crates/pm-custody/tests"))
import custody_loss_lab as lab

snapshots = []
AUTHORITY = (
    "vault_metadata", "encrypted_objects", "authority_events", "outbox",
    "human_receipts", "agent_authorizations", "delegated_state",
    "credential_authorizations", "vault_items", "revision_parts", "audit_keys",
)


def observe(vault):
    # One read-only transaction binds counts and full-row comparisons to the
    # same view even while the existing reconciliation worker is active.
    db = sqlite3.connect(vault.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("BEGIN")
        tables = dict.fromkeys((*lab.TABLES, *AUTHORITY))
        rows = {table: db.execute("SELECT * FROM " + table + " ORDER BY rowid").fetchall()
                for table in tables}
        states = db.execute("SELECT state,provider_sent FROM authentication_attempts").fetchall()
        counts = tuple(len(rows[table]) for table in lab.TABLES)
    finally:
        db.close()
    journal = json.loads((vault.parent.parent / "provider/journal.json").read_bytes())
    calls = [row["calls"] for row in journal.values()]
    assert calls == [1], "witness observed repeated login"
    summary = dict(snapshot=len(snapshots), counts=counts, states=states, provider_calls=calls)
    if snapshots:
        before = snapshots[0]
        summary["changed_authority_tables"] = [table for table in AUTHORITY
                                                if rows[table] != before[table]]
        old = before["encrypted_audit_records"]
        new = rows["encrypted_audit_records"]
        summary["audit_prefix_preserved"] = new[:len(old)] == old
        summary["audit_added"] = len(new) - len(old)
    snapshots.append(rows)
    print("CHEF_G7_LOSS_WITNESS " + json.dumps(summary, sort_keys=True), flush=True)
    return counts


if __name__ == "__main__":
    lab.counts = observe
    lab.main()  # Original assertions and strict cleanup still determine rc.
