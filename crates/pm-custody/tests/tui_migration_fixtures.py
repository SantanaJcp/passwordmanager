# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic migration fixtures shared by native keyboard laboratories."""

import json
import os
import zipfile


def onepux(path, *, owner, group):
    document = "ticket25-document"
    data = {"accounts": [{"attrs": {"uuid": "ticket25-account"}, "vaults": [{"attrs": {"uuid": "ticket25-vault"}, "items": [
        {"uuid": "ticket25-login", "state": "archived", "favIndex": 1, "categoryUuid": "001", "details": {"loginFields": [{"designation": "username", "value": "u"}, {"designation": "password", "value": "synthetic-ticket25-1pux"}], "notesPlain": "synthetic note", "passwordHistory": [{"value": "synthetic-prior", "time": 1}]}, "overview": {"title": "Keyboard 1PUX", "url": "https://ticket25.invalid", "tags": ["imported"]}},
        {"uuid": "ticket25-file", "categoryUuid": "004", "details": {"documentAttributes": {"fileName": "ticket25.bin", "documentId": document, "decryptedSize": 2 * 1024 * 1024 + 7}}, "overview": {"title": "Keyboard 1PUX file"}}
    ]}]}]}
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr("export.attributes", json.dumps({"version": 3, "description": "synthetic"}))
        out.writestr("export.data", json.dumps(data, separators=(",", ":")))
        state = 0x251A1BC3D4E5F607
        content = bytearray(2 * 1024 * 1024 + 7)
        for index in range(len(content)):
            state ^= (state << 13) & 0xffffffffffffffff; state ^= state >> 7; state ^= (state << 17) & 0xffffffffffffffff
            content[index] = state & 0xff
        out.writestr(f"files/{document}___ignored.bin", content)
    os.chown(path, owner, group); path.chmod(0o400)


def cbor_length(data, offset, major):
    lead = data[offset]; assert lead >> 5 == major; value = lead & 31; offset += 1
    if value < 24: return value, offset
    width = 1 << (value - 24) if value <= 27 else 0
    assert width in (1, 2, 4, 8)
    return int.from_bytes(data[offset:offset + width], "big"), offset + width


def pairing_namespace(data):
    count, offset = cbor_length(data, 0, 4); assert count == 6
    length, offset = cbor_length(data, offset, 3); offset += length
    length, offset = cbor_length(data, offset, 2); assert length == 16; offset += length
    length, offset = cbor_length(data, offset, 2); assert length == 32
    return data[offset:offset + length].hex()
