#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Public cleanup-error REDs using exact owned paths and one syscall failure."""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


HUMAN = 2
PREFIX = "pm-cleanup-fault-linux-lab-"


def as_human(command, environment):
    def identity():
        os.setgroups([])
        os.setgid(HUMAN)
        os.setuid(HUMAN)

    return subprocess.run(
        command,
        env=environment,
        capture_output=True,
        check=False,
        preexec_fn=identity,
        timeout=15,
    )


def expect_cleanup_surface(result, events, expected_events, residue):
    assert result.returncode == 4, result
    assert result.stdout == b"", result.stdout
    assert events.read_text().splitlines() == expected_events
    assert residue.is_file(), "the injected unlink failure must leave the exact owned file"
    return result.stderr == b"CUSTODY_UNAVAILABLE\nCLEANUP_FAILED\n"


def keygen_cleanup_red(binary, interposer, home):
    private, public, events = home / "keygen-private", home / "keygen-public", home / "keygen.events"
    public.write_bytes(b"synthetic-existing-public")
    events.write_bytes(b"")
    os.chown(events, HUMAN, HUMAN)
    environment = {
        "LD_PRELOAD": str(interposer),
        "PM_FAIL_UNLINK_PATH": str(private),
        "PM_INTERPOSE_LOG": str(events),
    }
    result = as_human([binary, "keygen", "--private", private, "--public", public], environment)
    surfaced = expect_cleanup_surface(result, events, ["unlink"], private)
    private.unlink()
    public.unlink()
    events.unlink()
    return surfaced, result.stderr


def write_new_cleanup_red(binary, interposer, home):
    private, public, events = home / "write-private", home / "write-public", home / "write.events"
    events.write_bytes(b"")
    os.chown(events, HUMAN, HUMAN)
    environment = {
        "LD_PRELOAD": str(interposer),
        "PM_FAIL_FSYNC_PATH": str(private),
        "PM_FAIL_UNLINK_PATH": str(private),
        "PM_INTERPOSE_LOG": str(events),
    }
    result = as_human([binary, "keygen", "--private", private, "--public", public], environment)
    surfaced = expect_cleanup_surface(result, events, ["fsync", "unlink"], private)
    private.unlink()
    assert not public.exists()
    events.unlink()
    return surfaced, result.stderr


def main():
    assert os.geteuid() == 0 and len(sys.argv) == 3
    source_binary = pathlib.Path(sys.argv[1]).resolve(strict=True)
    interposer_source = pathlib.Path(sys.argv[2]).resolve(strict=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix=PREFIX))
    try:
        root.chmod(0o711)
        binary, interposer, home = root / "pm-custody", root / "interposer.so", root / "human"
        shutil.copyfile(source_binary, binary)
        binary.chmod(0o755)
        subprocess.run(
            ["cc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
             "-o", interposer, interposer_source, "-ldl"],
            check=True,
        )
        interposer.chmod(0o755)
        home.mkdir(mode=0o700)
        os.chown(home, HUMAN, HUMAN)
        keygen_ok, keygen_stderr = keygen_cleanup_red(binary, interposer, home)
        write_ok, write_stderr = write_new_cleanup_red(binary, interposer, home)
        print(f"OBSERVED keygen-cleanup-surfaced={int(keygen_ok)} stderr={keygen_stderr!r}")
        print(f"OBSERVED write-new-cleanup-surfaced={int(write_ok)} stderr={write_stderr!r}")
        assert keygen_ok, ("keygen cleanup failure was discarded", keygen_stderr)
        assert write_ok, ("write_new cleanup failure was discarded", write_stderr)
    finally:
        shutil.rmtree(root)
    print("PASS cleanup-errors keygen=propagated write-new=propagated cleanup=verified")


if __name__ == "__main__":
    main()
