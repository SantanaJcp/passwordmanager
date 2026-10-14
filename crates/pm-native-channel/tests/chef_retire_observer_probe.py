#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Probe the existing RETIRE query against synthetic SQLite, not native acceptance.

Uses the current schema and observer SQL verbatim. Does not run Windows code,
verify signatures, change the observer, or reproduce its unexplained native error.
"""
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_SOURCE = ROOT / "crates/pm-vault/src/lib.rs"
OBSERVER_SOURCE = ROOT / "crates/pm-custody/examples/windows_human_tui_seed.rs"


def source_contract():
    schema = re.search(
        r"CREATE TABLE authority_events \(.*?\) STRICT;",
        SCHEMA_SOURCE.read_text(),
        re.DOTALL,
    )
    query = re.search(
        r'db.query_row\("(SELECT count\(\*\) FROM authority_events[^"\n]+)", '
        r'\[vec!\[0x([0-9a-f]+)_u8;(\d+)\]\]',
        OBSERVER_SOURCE.read_text(),
    )
    if schema is None or query is None:
        raise AssertionError("current schema/observer seam changed; inspect before probing")
    return schema.group(), query[1], bytes([int(query[2], 16)]) * int(query[3])


def observe_rows(rows):
    schema, query, subject = source_contract()
    with tempfile.TemporaryDirectory(prefix="pm-chef-retire-probe-") as directory:
        path = Path(directory) / "synthetic.sqlite3"
        writer = sqlite3.connect(path)
        try:
            writer.execute(schema)
            for index, (kind, row_subject) in enumerate(rows, 1):
                writer.execute(
                    "INSERT INTO authority_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        bytes([index]) * 32, bytes([index]) * 16,
                        bytes([index + 10]) * 16, bytes([0x27]) * 16,
                        1, index, None, b"\x80", kind, row_subject, 1,
                        b"synthetic-not-a-signed-event", bytes([0x51]) * 64,
                        bytes([0x52]) * 64,
                    ),
                )
            writer.commit()
        finally:
            writer.close()
        reader = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            return reader.execute(query, (subject,)).fetchone()[0]
        finally:
            reader.close()


class RetireQueryProbe(unittest.TestCase):
    def test_no_event_is_rejected(self):
        self.assertEqual(observe_rows([]), 0)

    def test_exact_subject_one_event(self):
        # Independently specified by test-windows-custody-lab.ps1 remoteDevice.
        self.assertEqual(observe_rows([("device-retire", bytes([0x28]) * 16)]), 1)

    def test_other_subject_is_rejected(self):
        self.assertEqual(observe_rows([("device-retire", bytes([0x29]) * 16)]), 0)

    def test_other_kind_is_rejected(self):
        self.assertEqual(observe_rows([("device-grant", bytes([0x28]) * 16)]), 0)

    def test_duplicate_events_remain_rejected(self):
        self.assertEqual(observe_rows([("device-retire", bytes([0x28]) * 16)] * 2), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
