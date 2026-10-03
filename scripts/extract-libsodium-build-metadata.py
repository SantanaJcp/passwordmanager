#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Select the exact libsodium out_dir from one Cargo JSON build stream."""

import json
import pathlib
import sys

PACKAGE_SUFFIX = "#libsodium-sys-stable@1.24.0"


def extract(lines):
    out_dirs = []
    for line in lines:
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise AssertionError("Cargo build metadata is malformed") from error
        rendered = message.get("message", {}).get("rendered")
        if isinstance(rendered, str):
            print(rendered, file=sys.stderr, end="")
        if message.get("reason") != "build-script-executed":
            continue
        package_id = message.get("package_id")
        if isinstance(package_id, str) and package_id.endswith(PACKAGE_SUFFIX):
            out_dir = message.get("out_dir")
            if not isinstance(out_dir, str):
                raise AssertionError("libsodium Cargo build metadata is unavailable")
            out_dirs.append(pathlib.Path(out_dir))
    if len(out_dirs) != 1 or not out_dirs[0].is_absolute() or not out_dirs[0].is_dir():
        raise AssertionError("libsodium Cargo build metadata is unavailable or ambiguous")
    return out_dirs[0]


if __name__ == "__main__":
    print(extract(sys.stdin.buffer))
