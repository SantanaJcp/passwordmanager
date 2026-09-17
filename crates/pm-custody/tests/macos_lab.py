#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Destructive-only-inside-ephemeral-CI native macOS custody laboratory."""

import ctypes
import errno
import fcntl
import hashlib
import os
import pathlib
import plistlib
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unicodedata
import pty

LABEL = "com.santanajcp.passwordmanager"
CUSTODIAN = "_passwordmanager"
AGENT = "_pmagent26"
OTHER = "_pmother26"
INSTALL = pathlib.Path("/usr/local/libexec/passwordmanager")
STATE = pathlib.Path("/Library/Application Support/PasswordManager")
RUNTIME = pathlib.Path("/var/run/passwordmanager")
PLIST = pathlib.Path(f"/Library/LaunchDaemons/{LABEL}.plist")
PASSWORD = b"synthetic ticket 26 master password"
TUI_PASSWORD_RECORD = b"ticket05-e2e-password-canary"
TUI_EXTERNAL_REPLACEMENT = b"ticket26-tui-external-replacement"

TUI23_BASE_FIELDS = (
    "title",
    "destination[0].label", "destination[0].value",
    "tag[0]", "favorite", "notes",
    "custom[0].id", "custom[0].label", "custom[0].text", "custom[0].concealed",
    "source[0].path", "source[0].encoding", "source[0].value",
)
TUI23_ATTACHMENT_FIELDS = (
    "attachment[0].id", "attachment[0].name", "attachment[0].mime",
    "attachment[0].size", "attachment[0].sha256", "attachment[0].content",
)
TUI23_FIELD_CATALOG = {
    "Password": TUI23_BASE_FIELDS + (
        "auth[0].username", "auth[0].password", "auth[0].destination_refs",
    ) + TUI23_ATTACHMENT_FIELDS,
    "TOTP": TUI23_BASE_FIELDS + (
        "auth[0].secret", "auth[0].algorithm", "auth[0].digits", "auth[0].period",
        "auth[0].t0", "auth[0].issuer", "auth[0].account", "auth[0].destination_refs",
    ),
    "Passkey": TUI23_BASE_FIELDS + (
        "auth[0].rp_id", "auth[0].user_handle", "auth[0].credential_id",
        "auth[0].cose_alg", "auth[0].private_key", "auth[0].public_key",
        "auth[0].user_name", "auth[0].display_name", "auth[0].sign_count",
        "auth[0].backup_eligible", "auth[0].backup_state",
    ),
    "SSH": TUI23_BASE_FIELDS + (
        "auth[0].private_format", "auth[0].private_key", "auth[0].public_key",
        "auth[0].username", "auth[0].destination_refs",
    ),
    "Token": TUI23_BASE_FIELDS + (
        "auth[0].secret", "auth[0].provider", "auth[0].profile_id",
        "auth[0].destination_refs",
    ),
    "ticket05-e2e-search-canary": TUI23_BASE_FIELDS,
    "File": TUI23_BASE_FIELDS + TUI23_ATTACHMENT_FIELDS,
    "Exchange Relationship": (
        "title", "destination[0].label", "destination[0].value", "tag[0]", "favorite", "notes",
        "auth[0].subject_token", "auth[0].requester_client_id",
        "auth[0].requester_client_secret", "auth[0].provider", "auth[0].profile_id",
        "auth[0].destination_refs", "auth[0].expires_at",
    ),
}
DIAGNOSTIC_ENV = "PM_MACOS_TICKET26_DIAGNOSTIC"
DIAGNOSTIC_LOG = STATE / "ticket26-diagnostic.log"
AGENT_MANAGER_COMMAND_TIMEOUT = 10
AGENT_PASTEBOARD_PROBE_TIMEOUT = 30
AGENT_LAUNCH_WAIT_TIMEOUT = (
    2 * AGENT_MANAGER_COMMAND_TIMEOUT + AGENT_PASTEBOARD_PROBE_TIMEOUT + 10
)
DIAGNOSTIC_LINE = re.compile(
    rb"(?:PM26_DIAGNOSTIC phase=[a-z-]+|"
    rb"PM26_DIAGNOSTIC accepted-stream-nonblocking-(?:before|after)=[01]|"
    rb"PM26_DIAGNOSTIC error=[a-z-]+|"
    rb"PM26_DIAGNOSTIC client-human-unlock-result="
    rb"(?:timeout|eof|other-io|malformed-frame|status-nonzero) elapsed-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC server-human-unlock-result="
    rb"(?:ok|vault-error) elapsed-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC launchd-service="
    rb"(?:same-pid|different-pid|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-human-canary-read="
    rb"(?:yes|no|indeterminate)|"
    rb"PM26_DIAGNOSTIC pasteboard-human-canary-(?:before|after)="
    rb"(?:yes|no|indeterminate)|"
    rb"PM26_DIAGNOSTIC pasteboard-agent-result="
    rb"(?:zero|nonzero|timeout)|"
    rb"PM26_DIAGNOSTIC pasteboard-agent-canary-stdout="
    rb"(?:present|absent)|"
    rb"PM26_DIAGNOSTIC pasteboard-agent-canary-stderr="
    rb"(?:present|absent)|"
    rb"PM26_DIAGNOSTIC pasteboard-agent-success-read="
    rb"(?:yes|no|indeterminate)|"
    rb"PM26_DIAGNOSTIC pasteboard-human-identity="
    rb"(?:expected|unexpected|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-agent-identity="
    rb"(?:expected|unexpected|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-human-domain="
    rb"(?:system|human|other|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-agent-domain="
    rb"(?:system|human|other|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-domain-relation="
    rb"(?:same|different|indeterminate)|"
    rb"PM26_DIAGNOSTIC pasteboard-shared-control=unsupported|"
    rb"PM26_DIAGNOSTIC pasteboard-shared-control-exit="
    rb"(?:natural-zero|natural-nonzero|owned-termination|unknown) "
    rb"returncode=(?:[0-9]{1,3}|unknown)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-agent-uid="
    rb"(?:expected|unexpected|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-manager-uid="
    rb"(?:system|human|other|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-manager-name="
    rb"(?:same|different|unavailable|unparseable)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-manager-domain="
    rb"(?:same|different|indeterminate)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-probe-result="
    rb"(?:zero|nonzero|timeout)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-probe-canary-stdout="
    rb"(?:present|absent)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-probe-canary-stderr="
    rb"(?:present|absent)|"
    rb"PM26_DIAGNOSTIC pasteboard-isolated-probe-success-read="
    rb"(?:yes|no|indeterminate)|"
    rb"PM26_DIAGNOSTIC unlock-phase="
    rb"(?:channel-verified|sqlite-opened|durability-configured|bundle-loaded|"
    rb"kdf-start|kdf-end|root-authenticated) elapsed-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC vault-root-create-ms=[0-9]{1,6}|"
    rb"PM26_DIAGNOSTIC sodium-cflags=(?:opt0|optimized))$"
)
PEER_UID_SCRIPT = """
import ctypes, socket, sys
stream = socket.socket(socket.AF_UNIX)
stream.connect(sys.argv[1])
uid = ctypes.c_uint(0)
gid = ctypes.c_uint(0)
libc = ctypes.CDLL(None, use_errno=True)
libc.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
libc.getpeereid.restype = ctypes.c_int
assert libc.getpeereid(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0
print(uid.value, flush=True)
if len(sys.argv) == 3:
    assert stream.recv(1) == b'x'
"""

AGENT_PASTEBOARD_LAUNCHER = r'''#!/usr/bin/python3
import os
import hashlib
import pathlib
import re
import subprocess
import sys

COMMAND_TIMEOUT = 10
PROBE_TIMEOUT = 30


def command_output(command):
    try:
        result = subprocess.run(
            command, check=False, capture_output=True, timeout=COMMAND_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or result.stderr:
        return None
    return result.stdout.strip()


def fixed_uid(value):
    if value is None or not re.fullmatch(rb"[0-9]+", value):
        return None
    return int(value, 10)


def fixed_name(value):
    if value is None or not re.fullmatch(rb"[A-Za-z0-9_.-]+", value):
        return None
    return value


def fixed_digest(value):
    if value is None or not re.fullmatch(r"[0-9a-f]{64}", value):
        return None
    return bytes.fromhex(value)


def fixed_length(value):
    if value is None or not re.fullmatch(r"[1-9][0-9]*", value):
        return None
    return int(value, 10)


def marker_present(payload, marker_length, marker_digest):
    if marker_length is None or marker_digest is None or len(payload) < marker_length:
        return False
    return any(
        hashlib.sha256(payload[offset:offset + marker_length]).digest() == marker_digest
        for offset in range(len(payload) - marker_length + 1)
    )


def relation(actual, expected):
    if actual is None or expected is None:
        return "unavailable"
    return "same" if actual == expected else "different"


result_path = pathlib.Path(sys.argv[1])
expected_agent_uid = int(sys.argv[2], 10)
human_manager_uid = int(sys.argv[3], 10)
human_manager_name = sys.argv[4].encode("ascii")
marker_length = fixed_length(sys.argv[5])
marker_digest = fixed_digest(sys.argv[6])
if marker_length is None or marker_digest is None:
    raise SystemExit(64)

agent_uid = os.getuid()
manager_uid = fixed_uid(command_output(["/bin/launchctl", "manageruid"]))
manager_name = fixed_name(command_output(["/bin/launchctl", "managername"]))
uid_category = "expected" if agent_uid == expected_agent_uid else "unexpected"
if manager_uid is None:
    manager_uid_category = "unavailable"
elif manager_uid == 0:
    manager_uid_category = "system"
elif manager_uid == human_manager_uid:
    manager_uid_category = "human"
else:
    manager_uid_category = "other"
manager_name_category = relation(manager_name, human_manager_name)
if manager_uid is None or manager_name_category == "unavailable":
    manager_domain_category = "indeterminate"
elif manager_uid == human_manager_uid and manager_name_category == "same":
    manager_domain_category = "same"
else:
    manager_domain_category = "different"

try:
    probe = subprocess.run(
        ["/usr/bin/osascript", "-e", "the clipboard as text"],
        check=False, capture_output=True, timeout=PROBE_TIMEOUT,
    )
except subprocess.TimeoutExpired as error:
    probe_status = "timeout"
    probe_stdout = error.stdout or b""
    probe_stderr = error.stderr or b""
else:
    probe_status = "zero" if probe.returncode == 0 else "nonzero"
    probe_stdout = probe.stdout
    probe_stderr = probe.stderr

stdout_canary = marker_present(probe_stdout, marker_length, marker_digest)
stderr_canary = marker_present(probe_stderr, marker_length, marker_digest)
probe_success = (
    "yes" if stdout_canary or stderr_canary
    else "indeterminate" if probe_status == "timeout" else "no"
)
result_path.write_text(
    "\n".join((
        "PM26_PASTEBOARD agent-uid=" + uid_category,
        "PM26_PASTEBOARD manager-uid=" + manager_uid_category,
        "PM26_PASTEBOARD manager-name=" + manager_name_category,
        "PM26_PASTEBOARD manager-domain=" + manager_domain_category,
        "PM26_PASTEBOARD probe-result=" + probe_status,
        "PM26_PASTEBOARD probe-canary-stdout="
        + ("present" if stdout_canary else "absent"),
        "PM26_PASTEBOARD probe-canary-stderr="
        + ("present" if stderr_canary else "absent"),
        "PM26_PASTEBOARD probe-success-read=" + probe_success,
    )) + "\n",
    encoding="ascii",
)
'''

AGENT_PASTEBOARD_RESULT_LINE = re.compile(
    rb"PM26_PASTEBOARD "
    rb"(?:agent-uid=(?:expected|unexpected|unavailable|unparseable)|"
    rb"manager-uid=(?:system|human|other|unavailable|unparseable)|"
    rb"manager-name=(?:same|different|unavailable|unparseable)|"
    rb"manager-domain=(?:same|different|indeterminate)|"
    rb"probe-result=(?:zero|nonzero|timeout)|"
    rb"probe-canary-stdout=(?:present|absent)|"
    rb"probe-canary-stderr=(?:present|absent)|"
    rb"probe-success-read=(?:yes|no|indeterminate))$"
)


def run(command, *, check=True, input=None, timeout=30):
    return subprocess.run(
        [str(value) for value in command], check=check, capture_output=True,
        input=input, timeout=timeout,
    )


def sudo(command, *, user=None, check=True, input=None):
    prefix = ["sudo", "-n"]
    if user is not None:
        prefix += ["-u", user]
    return run(prefix + list(command), check=check, input=input)


def wire_fields(values):
    result = bytearray()
    for value in values:
        result += len(value).to_bytes(4, "big") + value
    return bytes(result)


class UnsupportedVtSequence(AssertionError):
    """A terminal capability outside the observer's deliberately small contract."""

    def __init__(self, category):
        self.category = category
        super().__init__(f"unsupported VT sequence category={category}")


class VtScreen:
    """Decode the pinned TUI's cursor-addressed bytes into visible screen cells."""

    def __init__(self, columns, rows):
        assert columns > 0 and rows > 0
        self.columns = columns
        self.rows = rows
        self._cells = self._blank_cells()
        self._primary = None
        self._last_application = None
        self._cursor_row = 0
        self._cursor_column = 0
        self._wrap_pending = False
        self._last_base = None
        self._saved_cursor = (0, 0, False)
        self._state = "ground"
        self._csi = bytearray()
        self._utf8 = bytearray()
        self._utf8_expected = 0
        self.revision = 0

    def _blank_cells(self):
        return [[" " for _ in range(self.columns)] for _ in range(self.rows)]

    @staticmethod
    def _cell_width(character):
        category = unicodedata.category(character)
        if category in {"Mn", "Mc", "Me"} or character == "\u200d":
            return 0
        if category.startswith("C"):
            raise UnsupportedVtSequence("unicode-control")
        return 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1

    @staticmethod
    def _render_cells(cells):
        return "\n".join(
            "".join("" if cell is None else cell for cell in row)
            for row in cells
        )

    def text(self):
        return self._render_cells(self._cells)

    def application_text(self):
        if self._primary is None:
            return self._last_application or self._render_cells(self._cells)
        return self._render_cells(self._cells)

    def _changed(self):
        self.revision += 1

    def _reset_cursor_state(self):
        self._wrap_pending = False
        self._last_base = None

    def _linefeed(self):
        self._reset_cursor_state()
        if self._cursor_row == self.rows - 1:
            self._cells.pop(0)
            self._cells.append([" " for _ in range(self.columns)])
            self._changed()
        else:
            self._cursor_row += 1

    def _reverse_index(self):
        self._reset_cursor_state()
        if self._cursor_row == 0:
            self._cells.insert(0, [" " for _ in range(self.columns)])
            self._cells.pop()
            self._changed()
        else:
            self._cursor_row -= 1

    def _put(self, character):
        width = self._cell_width(character)
        if width == 0:
            if self._last_base is None:
                raise UnsupportedVtSequence("orphan-combining")
            row, column = self._last_base
            self._cells[row][column] += character
            self._changed()
            return
        if width > self.columns:
            raise UnsupportedVtSequence("wide-cell")
        if self._wrap_pending:
            self._cursor_column = 0
            self._linefeed()
        if self._cursor_column + width > self.columns:
            self._cursor_column = 0
            self._linefeed()
        row, column = self._cursor_row, self._cursor_column
        self._cells[row][column] = character
        if width == 2:
            self._cells[row][column + 1] = None
        self._last_base = (row, column)
        if column + width == self.columns:
            self._cursor_column = self.columns - 1
            self._wrap_pending = True
        else:
            self._cursor_column = column + width
            self._wrap_pending = False
        self._changed()

    def _move_cursor(self, row, column):
        self._cursor_row = max(0, min(self.rows - 1, row))
        self._cursor_column = max(0, min(self.columns - 1, column))
        self._reset_cursor_state()

    @staticmethod
    def _params(raw):
        private = raw.startswith(b"?")
        body = raw[1:] if private else raw
        if not re.fullmatch(rb"[0-9;]*", body):
            raise UnsupportedVtSequence("csi-parameters")
        if not body:
            return private, []
        values = []
        for value in body.split(b";"):
            if not value:
                values.append(None)
                continue
            try:
                values.append(int(value))
            except ValueError as error:
                raise UnsupportedVtSequence("csi-parameters") from error
        return private, values

    @staticmethod
    def _one(values, default, maximum=1):
        if len(values) > maximum:
            raise UnsupportedVtSequence("csi-arity")
        value = values[0] if values else None
        return default if value is None else value

    def _erase_line(self, mode):
        if mode not in (0, 1, 2):
            raise UnsupportedVtSequence("erase-line-mode")
        start = 0 if mode == 1 else self._cursor_column
        end = self._cursor_column if mode == 1 else self.columns - 1
        if mode == 2:
            start, end = 0, self.columns - 1
        changed = False
        for column in range(start, end + 1):
            if self._cells[self._cursor_row][column] != " ":
                self._cells[self._cursor_row][column] = " "
                changed = True
        self._reset_cursor_state()
        if changed:
            self._changed()

    def _erase_display(self, mode):
        if mode not in (0, 1, 2, 3):
            raise UnsupportedVtSequence("erase-display-mode")
        changed = False
        if mode == 0:
            row_ranges = [
                (self._cursor_row, self._cursor_column, self.columns),
                *[(row, 0, self.columns) for row in range(self._cursor_row + 1, self.rows)],
            ]
        elif mode == 1:
            row_ranges = [
                *[(row, 0, self.columns) for row in range(self._cursor_row)],
                (self._cursor_row, 0, self._cursor_column + 1),
            ]
        else:
            row_ranges = [(row, 0, self.columns) for row in range(self.rows)]
        for row, start, end in row_ranges:
            for column in range(start, end):
                if self._cells[row][column] != " ":
                    self._cells[row][column] = " "
                    changed = True
        self._reset_cursor_state()
        if changed:
            self._changed()

    def _set_private_mode(self, value, enabled):
        if value == 25:
            return
        if value != 1049:
            raise UnsupportedVtSequence("private-mode")
        if enabled:
            if self._primary is not None:
                raise UnsupportedVtSequence("nested-alternate-screen")
            self._primary = (
                self._cells, self._cursor_row, self._cursor_column,
                self._wrap_pending, self._last_base, self._saved_cursor,
            )
            self._cells = self._blank_cells()
            self._cursor_row = 0
            self._cursor_column = 0
            self._reset_cursor_state()
            self._last_application = None
            return
        if self._primary is None:
            raise UnsupportedVtSequence("alternate-screen-exit")
        self._last_application = self._render_cells(self._cells)
        (
            self._cells, self._cursor_row, self._cursor_column,
            self._wrap_pending, self._last_base, self._saved_cursor,
        ) = self._primary
        self._primary = None
        self._reset_cursor_state()

    def _dispatch_csi(self, raw, final):
        parameter_end = 0
        while parameter_end < len(raw) and 0x30 <= raw[parameter_end] <= 0x3F:
            parameter_end += 1
        parameters = raw[:parameter_end]
        intermediates = raw[parameter_end:]
        if intermediates or any(not 0x20 <= value <= 0x2F for value in intermediates):
            raise UnsupportedVtSequence("csi-intermediate")
        private, values = self._params(parameters)
        if private:
            if final not in ("h", "l") or len(values) != 1 or values[0] is None:
                raise UnsupportedVtSequence("private-mode")
            self._set_private_mode(values[0], final == "h")
            return
        if final == "n":
            raise UnsupportedVtSequence("terminal-query")
        if final in ("H", "f"):
            if len(values) > 2:
                raise UnsupportedVtSequence("csi-arity")
            row = 1 if not values or values[0] is None else values[0]
            column = 1 if len(values) < 2 or values[1] is None else values[1]
            self._move_cursor(row - 1, column - 1)
            return
        if final == "m":
            return
        if final == "J":
            self._erase_display(self._one(values, 0))
            return
        if final == "K":
            self._erase_line(self._one(values, 0))
            return
        if final in ("A", "B", "C", "D"):
            amount = self._one(values, 1)
            if amount < 0:
                raise UnsupportedVtSequence("csi-range")
            if amount == 0:
                amount = 1
            delta_row = amount if final == "B" else -amount if final == "A" else 0
            delta_column = amount if final == "C" else -amount if final == "D" else 0
            self._move_cursor(
                self._cursor_row + delta_row,
                self._cursor_column + delta_column,
            )
            return
        if final == "G":
            self._move_cursor(self._cursor_row, self._one(values, 1) - 1)
            return
        if final == "d":
            self._move_cursor(self._one(values, 1) - 1, self._cursor_column)
            return
        if final == "s":
            if values:
                raise UnsupportedVtSequence("csi-arity")
            self._saved_cursor = (
                self._cursor_row, self._cursor_column, self._wrap_pending,
            )
            return
        if final == "u":
            if values:
                raise UnsupportedVtSequence("csi-arity")
            self._cursor_row, self._cursor_column, self._wrap_pending = self._saved_cursor
            self._last_base = None
            return
        raise UnsupportedVtSequence("csi-command")

    def _feed_byte(self, value):
        if self._utf8:
            if not 0x80 <= value <= 0xBF:
                raise UnsupportedVtSequence("invalid-utf8")
            self._utf8.append(value)
            if len(self._utf8) == self._utf8_expected:
                try:
                    character = bytes(self._utf8).decode("utf-8", "strict")
                except UnicodeDecodeError as error:
                    raise UnsupportedVtSequence("invalid-utf8") from error
                self._utf8.clear()
                self._utf8_expected = 0
                self._put(character)
            return
        if self._state == "escape":
            if value == ord("["):
                self._state = "csi"
                self._csi.clear()
                return
            if value == ord("]"):
                raise UnsupportedVtSequence("osc")
            if value == ord("7"):
                self._saved_cursor = (
                    self._cursor_row, self._cursor_column, self._wrap_pending,
                )
                self._state = "ground"
                return
            if value == ord("8"):
                self._cursor_row, self._cursor_column, self._wrap_pending = self._saved_cursor
                self._last_base = None
                self._state = "ground"
                return
            if value == ord("D"):
                self._linefeed()
                self._state = "ground"
                return
            if value == ord("E"):
                self._cursor_column = 0
                self._linefeed()
                self._state = "ground"
                return
            if value == ord("M"):
                self._reverse_index()
                self._state = "ground"
                return
            raise UnsupportedVtSequence("escape")
        if self._state == "csi":
            if 0x30 <= value <= 0x3F or 0x20 <= value <= 0x2F:
                self._csi.append(value)
                return
            if 0x40 <= value <= 0x7E:
                raw = bytes(self._csi)
                self._csi.clear()
                self._state = "ground"
                self._dispatch_csi(raw, chr(value))
                return
            raise UnsupportedVtSequence("csi")
        if value == 0x1B:
            self._state = "escape"
            return
        if value in (0x00, 0x07, 0x7F):
            return
        if value == 0x08:
            self._cursor_column = max(0, self._cursor_column - 1)
            self._reset_cursor_state()
            return
        if value == 0x09:
            self._cursor_column = min(self.columns - 1, ((self._cursor_column // 8) + 1) * 8)
            self._reset_cursor_state()
            return
        if value in (0x0A, 0x0B, 0x0C):
            self._linefeed()
            return
        if value == 0x0D:
            self._cursor_column = 0
            self._reset_cursor_state()
            return
        if value < 0x20:
            raise UnsupportedVtSequence("control")
        if value < 0x80:
            self._put(chr(value))
            return
        if 0xC2 <= value <= 0xDF:
            self._utf8.extend((value,))
            self._utf8_expected = 2
            return
        if 0xE0 <= value <= 0xEF:
            self._utf8.extend((value,))
            self._utf8_expected = 3
            return
        if 0xF0 <= value <= 0xF4:
            self._utf8.extend((value,))
            self._utf8_expected = 4
            return
        raise UnsupportedVtSequence("invalid-utf8")

    def feed(self, value, *, final=False):
        for byte in value:
            self._feed_byte(byte)
        if final:
            if self._utf8:
                raise UnsupportedVtSequence("incomplete-utf8")
            if self._state != "ground":
                raise UnsupportedVtSequence("incomplete-control")

    def resize(self, columns, rows):
        assert columns > 0 and rows > 0
        cells = [
            row[:columns] + [" "] * max(0, columns - len(row))
            for row in self._cells[:rows]
        ]
        cells.extend([[" " for _ in range(columns)] for _ in range(rows - len(cells))])
        self.columns = columns
        self.rows = rows
        self._cells = cells
        self._cursor_row = min(self._cursor_row, rows - 1)
        self._cursor_column = min(self._cursor_column, columns - 1)
        self._reset_cursor_state()
        self._changed()


class MacPtySession:
    """Drive the real macOS TUI through a controlling pseudo-terminal."""

    def __init__(self, pid, master):
        self.pid = pid
        self.master = master
        self.output = bytearray()
        self.screen = VtScreen(80, 24)
        self._decode_at = 0
        self._screen_revision = self.screen.revision
        self._screen_events = []
        self._screen_finalized = False
        self.returncode = None
        self.reaped = False
        self.owned_termination_sent = False
        self.eof = False

    @classmethod
    def start(cls, binary, profile, private, endpoint, *, idle, reveal, copy):
        command = [
            str(binary), "tui", "--profile", str(profile), "--private", str(private),
            "--socket", str(endpoint), "--idle-seconds", str(idle),
            "--reveal-seconds", str(reveal), "--copy-seconds", str(copy),
        ]
        pid, master = pty.fork()
        if pid == 0:
            environment = os.environ.copy()
            environment["TERM"] = "xterm-256color"
            try:
                os.execve(command[0], command, environment)
            except BaseException:
                os._exit(127)
        session = cls(pid, master)
        try:
            session.resize(80, 24)
        except BaseException:
            close_session_preserving_primary(session)
            raise
        return session

    def mark(self):
        # Drain bytes already queued by the PTY before defining the action
        # boundary.  A raw-output offset alone can classify a frame emitted
        # before the key as post-action when that frame was still unread.
        self.drain()
        return len(self._screen_events)

    def resize(self, columns, rows):
        dimensions = struct.pack("HHHH", rows, columns, 0, 0)
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, dimensions)
        self.screen.resize(columns, rows)
        self._screen_revision = self.screen.revision

    def _consume_output(self, *, final=False):
        if self._screen_finalized:
            return
        value = bytes(self.output[self._decode_at:])
        self._decode_at = len(self.output)
        self.screen.feed(value, final=final)
        self._record_screen_event()
        if final:
            self._screen_finalized = True

    def _record_screen_event(self):
        if self.screen.revision == self._screen_revision:
            return
        self._screen_events.append((len(self.output), self.screen.application_text()))
        self._screen_revision = self.screen.revision

    def _read_once(self, timeout):
        if self.eof:
            return False
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return False
        try:
            value = os.read(self.master, 64 * 1024)
        except OSError as error:
            if error.errno == errno.EIO:
                self.eof = True
                self._consume_output(final=True)
                return False
            raise
        if not value:
            self.eof = True
            self._consume_output(final=True)
            return False
        self.output.extend(value)
        self._consume_output()
        return True

    def drain(self):
        while self._read_once(0):
            pass

    def text(self, since=0):
        return "\n".join(rendered for _, rendered in self._screen_events[since:])

    def _current_text_after(self, since):
        if len(self._screen_events) <= since:
            return None
        return self.screen.application_text()

    def _screen_diagnostic(self, since):
        rendered = self.screen.application_text()
        render = "other"
        for category, marker in (
            ("password-prompt", "Password required"),
            ("unlocked-catalog", "Unlocked: selection never reveals secrets"),
            ("search-prompt", "Search (engine-decrypted):"),
            ("search-result", "Search returned"),
            ("catalog", "Items (selection is metadata only)"),
            ("field-list", "Fields (explicit selection; values hidden)"),
            ("copy-status", "Copied explicitly"),
            ("clipboard-expired", "Clipboard custody expired"),
            ("idle-lock", "Locked after"),
        ):
            if marker in rendered:
                render = category
                break
        mode = "alternate" if self.screen._primary is not None else "primary"
        if self.screen._utf8:
            parser = "pending-utf8"
        elif self.screen._state == "ground":
            parser = "ground"
        else:
            parser = "pending-control"
        frame = "post-mark" if len(self._screen_events) > since else "none"
        child = "eof" if self.eof else "alive"
        return f"mode={mode} render={render} event={frame} parser={parser} child={child}"

    def wait_text(self, expected, *, timeout=8, since=0):
        deadline = time.monotonic() + timeout
        while True:
            rendered = self._current_text_after(since)
            if rendered is not None and expected in rendered:
                return rendered
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "TUI PTY screen observation timed out "
                    + self._screen_diagnostic(since)
                )
            self._read_once(min(0.1, remaining))

    def wait_selected(self, label, *, timeout=8, since=0):
        pattern = re.compile(rf"›\s+{re.escape(label)}(?:\s|\(|$)")
        deadline = time.monotonic() + timeout
        while True:
            rendered = self._current_text_after(since)
            if rendered is not None and any(
                pattern.search(line) for line in rendered.splitlines()
            ):
                return rendered
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "TUI PTY selected-row observation timed out "
                    + self._screen_diagnostic(since)
                )
            self._read_once(min(0.1, remaining))

    def write(self, value):
        remaining = memoryview(value)
        while remaining:
            try:
                count = os.write(self.master, remaining)
            except OSError as error:
                raise AssertionError("TUI PTY write failed") from error
            if count <= 0:
                raise AssertionError("TUI PTY write made no progress")
            remaining = remaining[count:]

    def send_key(self, value):
        keys = {"enter": b"\r", "escape": b"\x1b"}
        self.write(keys.get(value, value.encode("utf-8")))

    def send_text(self, value, *, enter=False, hidden=False):
        start = self.mark()
        self.write(value.encode("utf-8"))
        if enter:
            if not hidden:
                self.wait_text(f"Input: {value}", since=start)
            self.send_key("enter")

    def run_while_draining(self, command, *, check=True, timeout=30):
        """Run a fixture helper while continuously consuming this PTY."""
        argv = [str(value) for value in command]
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout_fd = process.stdout.fileno()
        stderr_fd = process.stderr.fileno()
        streams = {
            stdout_fd: process.stdout,
            stderr_fd: process.stderr,
        }
        captured = {fd: bytearray() for fd in streams}

        def pump(deadline, *, read_pty=True):
            while streams or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                read_fds = list(streams)
                if read_pty and not self.eof:
                    read_fds.insert(0, self.master)
                if not read_fds:
                    time.sleep(min(0.05, remaining))
                    continue
                ready, _, _ = select.select(
                    read_fds, [], [], min(0.05, remaining),
                )
                if read_pty and self.master in ready:
                    self._read_once(0)
                for fd, stream in list(streams.items()):
                    if fd not in ready:
                        continue
                    value = os.read(fd, 64 * 1024)
                    if value:
                        captured[fd].extend(value)
                    else:
                        streams.pop(fd)
                        stream.close()
            return True

        termination_sent = False

        def terminate_owned_group():
            nonlocal termination_sent
            if termination_sent:
                return
            termination_sent = True
            try:
                # start_new_session gives this fixture helper an owned process
                # group.  Kill the group even if the Popen leader has already
                # exited: a descendant may still hold a pipe open.  This is
                # the single owned teardown action; no second signal or retry
                # is used when it fails to close cleanly.
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        primary = None
        try:
            complete = pump(time.monotonic() + timeout)
        except BaseException as error:
            primary = error
        if primary is None and not complete:
            primary = subprocess.TimeoutExpired(
                argv, timeout,
                output=bytes(captured[stdout_fd]),
                stderr=bytes(captured[stderr_fd]),
            )
        cleanup_errors = []
        if primary is not None:
            try:
                terminate_owned_group()
            except BaseException as error:
                cleanup_errors.append(error)

        teardown_deadline = time.monotonic() + 5
        try:
            teardown_complete = pump(
                teardown_deadline,
                read_pty=not isinstance(primary, UnsupportedVtSequence),
            )
            if not teardown_complete:
                cleanup_errors.append(
                    AssertionError("fixture helper streams did not close during cleanup")
                )
        except BaseException as error:
            cleanup_errors.append(error)
        if process.poll() is None:
            try:
                process.wait(timeout=max(0, teardown_deadline - time.monotonic()))
            except BaseException as error:
                cleanup_errors.append(error)
        if process.poll() is None:
            cleanup_errors.append(
                AssertionError("fixture helper did not exit during cleanup")
            )
        for fd, stream in list(streams.items()):
            try:
                stream.close()
            except BaseException as error:
                cleanup_errors.append(error)
            streams.pop(fd)
        # A VT parser failure is already the primary error.  Re-running drain
        # would feed the same unsupported bytes a second time and obscure the
        # original category; the enclosing session cleanup will close the PTY.
        if not isinstance(primary, UnsupportedVtSequence):
            try:
                self.drain()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    cleanup_errors.append(error)

        stdout = bytes(captured[stdout_fd])
        stderr = bytes(captured[stderr_fd])
        if isinstance(primary, subprocess.TimeoutExpired):
            primary.output = stdout
            primary.stderr = stderr
        if primary is not None:
            if cleanup_errors:
                primary.__cause__ = BaseExceptionGroup(
                    "fixture helper cleanup failed", cleanup_errors,
                )
            raise primary
        if cleanup_errors:
            raise BaseExceptionGroup("fixture helper cleanup failed", cleanup_errors)
        returncode = process.wait()
        result = subprocess.CompletedProcess(argv, returncode, stdout, stderr)
        if check and returncode:
            raise subprocess.CalledProcessError(
                returncode, argv, output=stdout, stderr=stderr,
            )
        return result

    def run_sudo_while_draining(self, command, *, user=None, check=True, timeout=30):
        prefix = ["sudo", "-n"]
        if user is not None:
            prefix += ["-u", user]
        return self.run_while_draining(
            prefix + list(command), check=check, timeout=timeout,
        )

    @staticmethod
    def _exit_code(status):
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status)
        if os.WIFSIGNALED(status):
            return 128 + os.WTERMSIG(status)
        raise AssertionError("TUI PTY child returned an unknown wait status")

    def wait_exit(self, *, timeout=8):
        if self.returncode is not None:
            return self.returncode
        if self.reaped:
            raise AssertionError("TUI PTY child exit status was already reaped")
        deadline = time.monotonic() + timeout
        while True:
            child, status = os.waitpid(self.pid, os.WNOHANG)
            if child == self.pid:
                self.reaped = True
                self.returncode = self._exit_code(status)
                self.drain()
                return self.returncode
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("TUI PTY child did not exit within the existing bound")
            self._read_once(min(0.1, remaining))

    def close(self):
        errors = []
        if self.returncode is None and not self.reaped:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            else:
                self.owned_termination_sent = True
            try:
                self.wait_exit(timeout=5)
            except BaseException as error:
                errors.append(error)
        try:
            os.close(self.master)
        except OSError as error:
            if error.errno != errno.EBADF:
                errors.append(error)
        if errors:
            raise AssertionError("TUI PTY cleanup failed") from errors[0]


def close_session_preserving_primary(session):
    """Run strict PTY cleanup without replacing an already-raised error."""
    primary = sys.exc_info()[1]
    try:
        session.close()
    except BaseException as cleanup_error:
        if primary is None:
            raise
        prior_cause = primary.__cause__
        if prior_cause is not None:
            cleanup_error.__context__ = prior_cause
        primary.__cause__ = cleanup_error


def observe_child_exit_without_termination(session):
    """Reap an already-finished PTY child before owned cleanup can signal it."""
    if session.returncode is not None or session.reaped:
        return
    try:
        child, status = os.waitpid(session.pid, os.WNOHANG)
    except ChildProcessError as error:
        raise AssertionError("TUI PTY child exit state was unavailable") from error
    if child != session.pid:
        return
    session.reaped = True
    session.returncode = session._exit_code(status)
    session.drain()


def classify_shared_control_exit(returncode, owned_termination_sent):
    """Classify a supporting control exit without exposing PTY bytes."""
    if returncode is None:
        return b"unknown", b"unknown"
    status = str(returncode).encode("ascii")
    if returncode == 0:
        return b"natural-zero", status
    if owned_termination_sent and returncode == 128 + signal.SIGTERM:
        return b"owned-termination", status
    return b"natural-nonzero", status


def assert_screen_observer_regression():
    """The PTY observer must preserve cells addressed by cursor-positioned output."""
    captured = (
        b"\x1b[2J\x1b[4;1HItems\x1b[4;7H(selection is metadata only)"
        b"\x1b[6;1HPassword\x1b[6;10Hrequired\x1b[8;1Hcafe\xcc\x81"
    )
    screen = VtScreen(40, 10)
    for offset in range(len(captured)):
        screen.feed(captured[offset:offset + 1])
    screen.feed(b"", final=True)
    rendered = screen.text()
    assert "Items (selection is metadata only)" in rendered, (
        "cursor-positioned screen regression: item title lost its separating cell"
    )
    assert "Password required" in rendered, (
        "cursor-positioned screen regression: prompt lost its separating cell"
    )
    assert "cafe\u0301" in rendered, (
        "cursor-positioned screen regression: combining mark was not retained"
    )
    wide = VtScreen(6, 2)
    wide.feed("a界b".encode("utf-8"), final=True)
    assert wide.text().splitlines()[0] == "a界b  ", (
        "cursor-positioned screen regression: wide-cell continuation became text"
    )
    erased = VtScreen(8, 3)
    erased.feed(b"\x1b[1;1Hprior0\x1b[2;1Hprior1\x1b[3;1Hcurrent\x1b[3;4H\x1b[1J", final=True)
    erased_rows = erased.text().splitlines()
    assert erased_rows[0] == "        " and erased_rows[1] == "        " \
        and erased_rows[2] == "    ent ", (
            "cursor-positioned screen regression: CSI 1J erased the wrong cells"
        )
    movement = VtScreen(5, 3)
    movement.feed(
        b"\x1b[2;2H\x1b[0AY\x1b[2;2H\x1b[0BZ"
        b"\x1b[2;2H\x1b[0CD\x1b[2;2H\x1b[0DL\x1b[2;2HX",
        final=True,
    )
    movement_rows = movement.text().splitlines()
    assert movement_rows[0] == " Y   " and movement_rows[1] == "LXD  " \
        and movement_rows[2] == " Z   ", (
        "cursor-positioned screen regression: CSI zero movement was not defaulted"
    )
    screen.resize(12, 4)
    screen.feed(b"\x1b[1;1Hwide\xe7\x95\x8c")
    resized = screen.text().splitlines()
    assert len(resized) == 4 and resized[0].startswith("wide界"), (
        "cursor-positioned screen regression: resize changed visible rows"
    )
    screen.feed(b"\x1b[?1049h\x1b[1;1Halternate")
    alternate = screen.text()
    screen.feed(b"\x1b[?1049l")
    assert "alternate" not in screen.text() and "alternate" in screen.application_text(), (
        "cursor-positioned screen regression: alternate-screen snapshot was lost"
    )
    assert alternate.startswith("alternate"), (
        "cursor-positioned screen regression: alternate screen was not rendered"
    )
    try:
        screen.feed(b"\x1b[6n")
    except UnsupportedVtSequence as error:
        assert error.category == "terminal-query"
    else:
        raise AssertionError("cursor-positioned screen regression: terminal query was accepted")
    try:
        screen.feed(b"\xc3", final=True)
    except UnsupportedVtSequence as error:
        assert error.category == "incomplete-utf8"
    else:
        raise AssertionError("cursor-positioned screen regression: incomplete UTF-8 was accepted")

    marker = object.__new__(MacPtySession)
    marker._screen_events = []
    marker.drain = lambda: marker._screen_events.append((0, "fresh frame"))
    assert marker.mark() == 1, (
        "cursor-positioned screen regression: action mark did not drain queued output"
    )

    boundary = object.__new__(MacPtySession)
    boundary.screen = VtScreen(40, 4)
    boundary.screen.feed(b"Items (selection is metadata only)", final=True)
    boundary._screen_events = [
        (16, "Search (engine-decrypted):"),
        (32, "Items (selection is metadata only)"),
    ]
    boundary.eof = False
    assert "Search (engine-decrypted):" in boundary.text(), (
        "cursor-positioned screen regression: event history was discarded"
    )
    assert "Search (engine-decrypted):" not in boundary._current_text_after(0), (
        "cursor-positioned screen regression: current screen used stale event history"
    )
    try:
        boundary.wait_text("Search (engine-decrypted):", timeout=0)
    except AssertionError as error:
        assert str(error).endswith(
            "mode=primary render=catalog event=post-mark parser=ground child=alive"
        ), str(error)
    else:
        raise AssertionError(
            "cursor-positioned screen regression: stale screen history satisfied wait"
        )

    selection = object.__new__(MacPtySession)
    selection.screen = VtScreen(40, 4)
    selection.screen.feed(b"auth[0].username", final=True)
    selection._screen_events = [(24, "› auth[0].password (32 bytes)")]
    selection.eof = False
    try:
        selection.wait_selected("auth[0].password", timeout=0)
    except AssertionError as error:
        assert str(error).startswith("TUI PTY selected-row observation timed out "), str(error)
    else:
        raise AssertionError(
            "cursor-positioned screen regression: stale selected-row history satisfied wait"
        )

    split_expiry = object.__new__(MacPtySession)
    split_expiry.screen = VtScreen(64, 4)
    split_expiry.output = bytearray()
    split_expiry._decode_at = 0
    split_expiry._screen_revision = split_expiry.screen.revision
    split_expiry._screen_events = []
    split_expiry._screen_finalized = False
    split_expiry.eof = False
    split_expiry.reads = 0
    expiry_frames = iter((
        b"\x1b[2J\x1b[1;1HStatus: Secret revealed temporarily"
        + "\x1b[2;1H│Exposure: ticket05-e2e-password-canary│".encode("utf-8")
        + b"\x1b[3;1Hkind: note",
        b"\x1b[1;1H\x1b[2KStatus: Reveal expired",
        "\x1b[2;1H\x1b[2K│Exposure: <hidden>│".encode("utf-8"),
    ))

    def read_expiry_frame(_timeout):
        try:
            value = next(expiry_frames)
        except StopIteration:
            return False
        split_expiry.reads += 1
        split_expiry.output.extend(value)
        split_expiry._consume_output()
        return True

    split_expiry._read_once = read_expiry_frame
    assert wait_stable_reveal_expiry(
        split_expiry, forbidden="ticket05-e2e-password-canary", timeout=1,
    ).find("Reveal expired") >= 0
    assert split_expiry.reads == 3, (
        "cursor-positioned screen regression: intermediate expiry frame was accepted"
    )
    stable_expiry = split_expiry.screen.application_text()
    assert "Exposure: <hidden>" in stable_expiry and \
        "ticket05-e2e-password-canary" not in stable_expiry, (
            "cursor-positioned screen regression: stable expiry retained exposure"
    )
    try:
        wait_stable_reveal_expiry(
            split_expiry, forbidden="note", timeout=0,
        )
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "cursor-positioned screen regression: generic metadata passed a global canary check"
        )
    assert wait_stable_reveal_expiry(
        split_expiry, forbidden="note", forbidden_in_exposure=True, timeout=0,
    ).find("Exposure: <hidden>") >= 0
    assert_pasteboard_diagnostic_regression()
    assert_pty_helper_drain_regression()


def assert_pty_helper_drain_regression():
    """Exercise helper drainage and owned teardown without product processes."""
    def start_fixture_pty(payload, *, repeat=False, initial_delay=0):
        pid, master = pty.fork()
        if pid == 0:
            try:
                if initial_delay:
                    time.sleep(initial_delay)
                if repeat:
                    for _ in range(200):
                        os.write(1, payload)
                        time.sleep(0.005)
                else:
                    os.write(1, payload)
                time.sleep(30)
            finally:
                os._exit(0)
        return MacPtySession(pid, master)

    def helper_script(body):
        return [sys.executable, "-c", body]

    def wait_for_absence(path, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            assert not path.exists(), "owned helper descendant survived group cleanup"
            time.sleep(0.05)
        assert not path.exists(), "owned helper descendant survived group cleanup"

    def wait_for_presence(path, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.05)
        assert path.exists(), "owned helper descendant did not start"

    # Keep the repeated drain writer ASCII-only: teardown must not interrupt a
    # multi-byte UTF-8 or VT control sequence and create a false cleanup RED.
    session = start_fixture_pty(b"synthetic PTY heartbeat ", repeat=True)
    try:
        result = session.run_while_draining(
            helper_script(
                "import sys; sys.stdout.write('helper-stdout\\n'); "
                "sys.stderr.write('helper-stderr\\n')"
            ),
            timeout=2,
        )
        assert result.returncode == 0
        assert result.stdout == b"helper-stdout\n"
        assert result.stderr == b"helper-stderr\n"
        assert b"synthetic PTY heartbeat" in session.output

        canary = b"synthetic-hidden-canary"
        result = session.run_while_draining(
            helper_script(
                "import sys; sys.stdout.buffer.write(%r); "
                "sys.stderr.buffer.write(b'helper-diagnostic')"
                % (canary + b"\\n",)
            ),
            check=False,
            timeout=2,
        )
        assert classify_pasteboard_output(
            canary, result.stdout, result.stderr, result.returncode,
        ) == (b"zero", True, False, b"yes")
    finally:
        close_session_preserving_primary(session)

    started_fd, started_name = tempfile.mkstemp(prefix="pm26-helper-descendant-started-")
    os.close(started_fd)
    started = pathlib.Path(started_name)
    started.unlink()
    marker_fd, marker_name = tempfile.mkstemp(prefix="pm26-helper-descendant-survived-")
    os.close(marker_fd)
    marker = pathlib.Path(marker_name)
    marker.unlink()
    session = start_fixture_pty(b"synthetic timeout stream ", repeat=True)
    try:
        try:
            session.run_while_draining(
                helper_script(
                    "import os, pathlib, sys, time\n"
                    "read_fd, write_fd = os.pipe()\n"
                    "child = os.fork()\n"
                    "if child == 0:\n"
                    "    os.close(read_fd)\n"
                    "    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\n"
                    "    os.write(write_fd, b'x')\n"
                    "    os.close(write_fd)\n"
                    "    time.sleep(0.5)\n"
                    "    pathlib.Path(sys.argv[2]).write_text('survived')\n"
                    "    os._exit(0)\n"
                    "os.close(write_fd)\n"
                    "os.read(read_fd, 1)\n"
                    "os.close(read_fd)\n"
                    "os._exit(0)\n"
                ) + [str(started), str(marker)],
                timeout=0.1,
            )
        except subprocess.TimeoutExpired as error:
            assert error.output == b""
            assert error.stderr == b""
        else:
            raise AssertionError("helper timeout regression did not time out")
        wait_for_presence(started)
        wait_for_absence(marker)
    finally:
        close_session_preserving_primary(session)
        started.unlink(missing_ok=True)
        marker.unlink(missing_ok=True)

    parser_started_fd, parser_started_name = tempfile.mkstemp(
        prefix="pm26-helper-parser-started-",
    )
    os.close(parser_started_fd)
    parser_started = pathlib.Path(parser_started_name)
    parser_started.unlink()
    parser_marker_fd, parser_marker_name = tempfile.mkstemp(prefix="pm26-helper-parser-")
    os.close(parser_marker_fd)
    parser_marker = pathlib.Path(parser_marker_name)
    parser_marker.unlink()
    session = start_fixture_pty(b"\x1b[6n", initial_delay=0.1)
    try:
        try:
            session.run_while_draining(
                helper_script(
                    "import pathlib, sys, time; "
                    "pathlib.Path(sys.argv[1]).write_text('started'); "
                    "time.sleep(0.5); "
                    "pathlib.Path(sys.argv[2]).write_text('survived')"
                ) + [str(parser_started), str(parser_marker)],
                timeout=2,
            )
        except UnsupportedVtSequence as error:
            assert error.category == "terminal-query"
        else:
            raise AssertionError("parser error regression was accepted")
        wait_for_presence(parser_started)
        wait_for_absence(parser_marker)
    finally:
        close_session_preserving_primary(session)
        parser_started.unlink(missing_ok=True)
        parser_marker.unlink(missing_ok=True)


def read_appkit_pasteboard(session=None):
    command = ["osascript", "-e", "the clipboard as text"]
    result = (
        run(command, check=False, timeout=10)
        if session is None
        else session.run_while_draining(command, check=False, timeout=10)
    )
    assert result.returncode == 0 and result.stderr == b"", (
        "AppKit pasteboard observer failed", result.returncode, result.stderr[:1024],
    )
    return result.stdout.rstrip(b"\r\n")


def write_appkit_pasteboard(value, session=None):
    expression = f'set the clipboard to "{value.decode("ascii")}"'
    command = ["osascript", "-e", expression]
    result = (
        run(command, check=False, timeout=10)
        if session is None
        else session.run_while_draining(command, check=False, timeout=10)
    )
    assert result.returncode == 0 and result.stderr == b"", (
        "AppKit pasteboard replacement failed", result.returncode, result.stderr[:1024],
    )


def emit_diagnostic(line):
    diagnostic_lines(line)
    print(line.decode("ascii"))


def classify_identity(result, expected_uid):
    if result.returncode != 0:
        return b"unavailable"
    if result.stderr:
        return b"unparseable"
    return b"expected" if result.stdout.strip() == str(expected_uid).encode() else b"unexpected"


def classify_launchd_domain(result, human_uid):
    if result.returncode != 0:
        return b"unavailable", None
    if result.stderr:
        return b"unparseable", None
    manager_uid = result.stdout.strip()
    try:
        parsed_uid = int(manager_uid, 10)
    except ValueError:
        return b"unparseable", None
    if parsed_uid == 0:
        category = b"system"
    elif parsed_uid == human_uid:
        category = b"human"
    else:
        category = b"other"
    return category, parsed_uid


def classify_domain_relation(human_domain, agent_domain):
    human_category, human_uid = human_domain
    agent_category, agent_uid = agent_domain
    if human_category in {b"unavailable", b"unparseable"} \
            or agent_category in {b"unavailable", b"unparseable"} \
            or human_uid is None or agent_uid is None:
        return b"indeterminate"
    return b"same" if human_uid == agent_uid else b"different"


def classify_pasteboard_output(secret, stdout, stderr, returncode):
    canary_stdout = secret in stdout
    canary_stderr = secret in stderr
    result_status = (
        b"timeout" if returncode is None
        else b"zero" if returncode == 0 else b"nonzero"
    )
    success_read = (
        b"yes" if canary_stdout or canary_stderr
        else b"indeterminate" if returncode is None else b"no"
    )
    return result_status, canary_stdout, canary_stderr, success_read


def assert_pasteboard_diagnostic_regression():
    canary = b"synthetic-pasteboard-canary"
    status, stdout, stderr, success = classify_pasteboard_output(
        canary, b"", b"", 0
    )
    assert (status, stdout, stderr, success) == (b"zero", False, False, b"no")
    status, stdout, stderr, success = classify_pasteboard_output(
        canary, canary + b"\n", b"", 0
    )
    assert (status, stdout, stderr, success) == (b"zero", True, False, b"yes")
    status, stdout, stderr, success = classify_pasteboard_output(
        canary, b"", canary + b"\n", 1
    )
    assert (status, stdout, stderr, success) == (b"nonzero", False, True, b"yes")
    status, stdout, stderr, success = classify_pasteboard_output(
        canary, b"", b"", None
    )
    assert (status, stdout, stderr, success) == (b"timeout", False, False, b"indeterminate")
    assert classify_shared_control_exit(0, False) == (b"natural-zero", b"0")
    assert classify_shared_control_exit(4, False) == (b"natural-nonzero", b"4")
    assert classify_shared_control_exit(143, False) == (b"natural-nonzero", b"143")
    assert classify_shared_control_exit(4, True) == (b"natural-nonzero", b"4")
    assert classify_shared_control_exit(1, True) == (b"natural-nonzero", b"1")
    assert classify_shared_control_exit(0, True) == (b"natural-zero", b"0")
    assert classify_shared_control_exit(143, True) == (b"owned-termination", b"143")
    assert classify_shared_control_exit(None, False) == (b"unknown", b"unknown")
    assert parse_launchd_last_exit_code(
        b"state = not running\nlast exit code = 0\n"
    ) == 0
    assert parse_launchd_last_exit_code(
        b"last exit code = 4\n"
    ) == 4
    for malformed in (
        b"state = not running\n",
        b"last exit code = nope\n",
        b"last exit code = 4: EXAMPLE\n",
        b"last exit code = 0\nlast exit code = 0\n",
    ):
        try:
            parse_launchd_last_exit_code(malformed)
        except AssertionError:
            pass
        else:
            raise AssertionError("launchd last-exit parser accepted malformed output")


def assert_human_pasteboard_canary(secret, *, diagnostic=False, phase=None, session=None):
    value = read_appkit_pasteboard(session=session)
    canary_read = value == secret
    if diagnostic:
        emit_diagnostic(
            b"PM26_DIAGNOSTIC pasteboard-human-canary-read="
            + (b"yes" if canary_read else b"no")
        )
        if phase is not None:
            assert phase in ("before", "after")
            phase_name = {
                "before": b"pasteboard-human-canary-before",
                "after": b"pasteboard-human-canary-after",
            }[phase]
            emit_diagnostic(
                b"PM26_DIAGNOSTIC " + phase_name + b"="
                + (b"yes" if canary_read else b"no")
            )
    assert canary_read, "human AppKit pasteboard control did not read the exact canary"


def assert_agent_cannot_read_pasteboard(
    secret, *, diagnostic=False, require_denied=True, session=None,
):
    run_command = run if session is None else session.run_while_draining
    sudo_command = sudo if session is None else session.run_sudo_while_draining
    if diagnostic:
        human_uid = os.getuid()
        agent_uid = pwd.getpwnam(AGENT).pw_uid
        human_identity = classify_identity(run_command(["id", "-u"], check=False), human_uid)
        agent_identity = classify_identity(
            sudo_command(["id", "-u"], user=AGENT, check=False), agent_uid
        )
        human_domain = classify_launchd_domain(
            run_command(["launchctl", "manageruid"], check=False), human_uid
        )
        agent_domain = classify_launchd_domain(
            sudo_command(["launchctl", "manageruid"], user=AGENT, check=False), human_uid
        )
    try:
        result = sudo_command(
            ["osascript", "-e", "the clipboard as text"],
            user=AGENT, check=False,
        )
    except subprocess.TimeoutExpired as error:
        if not diagnostic:
            raise
        result = None
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    else:
        stdout = result.stdout
        stderr = result.stderr
        result_status = b"zero" if result.returncode == 0 else b"nonzero"

    result_status, canary_stdout, canary_stderr, success_read = classify_pasteboard_output(
        secret, stdout, stderr, None if result is None else result.returncode
    )
    if diagnostic:
        for name, value in (
            (b"pasteboard-agent-result", result_status),
            (b"pasteboard-agent-canary-stdout", b"present" if canary_stdout else b"absent"),
            (b"pasteboard-agent-canary-stderr", b"present" if canary_stderr else b"absent"),
            (b"pasteboard-agent-success-read", success_read),
            (b"pasteboard-human-identity", human_identity),
            (b"pasteboard-agent-identity", agent_identity),
            (b"pasteboard-human-domain", human_domain[0]),
            (b"pasteboard-agent-domain", agent_domain[0]),
            (b"pasteboard-domain-relation", classify_domain_relation(human_domain, agent_domain)),
        ):
            emit_diagnostic(b"PM26_DIAGNOSTIC " + name + b"=" + value)
    if require_denied:
        assert not canary_stdout and not canary_stderr, (
            "agent pasteboard probe exposed the exact human canary", result_status,
        )
        assert result is not None, "agent pasteboard probe result was indeterminate"
    return result_status, canary_stdout, canary_stderr, success_read


def parse_agent_pasteboard_result(value):
    lines = value.splitlines()
    assert len(lines) == 8 and all(
        AGENT_PASTEBOARD_RESULT_LINE.fullmatch(line) for line in lines
    ), "isolated pasteboard launch result was missing or malformed"
    fields = {}
    for line in lines:
        name, category = line.removeprefix(b"PM26_PASTEBOARD ").split(b"=", 1)
        assert name not in fields, "isolated pasteboard launch result was duplicated"
        fields[name] = category
    assert set(fields) == {
        b"agent-uid", b"manager-uid", b"manager-name", b"manager-domain",
        b"probe-result", b"probe-canary-stdout", b"probe-canary-stderr",
        b"probe-success-read",
    }, "isolated pasteboard launch result had an unexpected schema"
    return fields


def launchd_manager_context():
    uid_result = run(["launchctl", "manageruid"], check=False)
    name_result = run(["launchctl", "managername"], check=False)
    assert uid_result.returncode == 0 and uid_result.stderr == b"", (
        "human launchd manager UID was unavailable"
    )
    assert name_result.returncode == 0 and name_result.stderr == b"", (
        "human launchd manager name was unavailable"
    )
    uid = uid_result.stdout.strip()
    name = name_result.stdout.strip()
    assert re.fullmatch(rb"[0-9]+", uid) and re.fullmatch(rb"[A-Za-z0-9_.-]+", name), (
        "human launchd manager metadata was malformed"
    )
    return int(uid, 10), name.decode("ascii")


def parse_launchd_last_exit_code(output):
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("isolated pasteboard launch status was malformed") from error
    matches = [line.strip() for line in lines if line.strip().startswith("last exit code = ")]
    if len(matches) != 1:
        raise AssertionError("isolated pasteboard launch status lacked one last-exit field")
    match = re.fullmatch(r"last exit code = (-?[0-9]+)", matches[0])
    if match is None:
        raise AssertionError("isolated pasteboard launch status had malformed last-exit field")
    return int(match.group(1), 10)


def wait_for_agent_launch(label, result_path, *, session=None):
    # The job may spend both fixed 10-second metadata bounds before the exact
    # public probe's fixed 30-second bound.  This is a fixture lifecycle bound,
    # not a product or clipboard-lease extension.
    sudo_command = sudo if session is None else session.run_sudo_while_draining
    deadline = time.monotonic() + AGENT_LAUNCH_WAIT_TIMEOUT
    while time.monotonic() < deadline:
        result_exists = sudo_command(["test", "-s", result_path], check=False).returncode == 0
        details = sudo_command(["launchctl", "print", f"system/{label}"], check=False)
        if details.returncode != 0:
            raise AssertionError("isolated pasteboard launch job disappeared")
        running = re.search(rb"\bpid = [0-9]+\b", details.stdout) is not None
        if result_exists and not running:
            if parse_launchd_last_exit_code(details.stdout) != 0:
                raise AssertionError("isolated pasteboard launch exited nonzero")
            return
        if session is None:
            time.sleep(0.1)
        else:
            session._read_once(0.1)
    raise AssertionError("isolated pasteboard launch job did not finish")


def prepare_launchd_agent(
    secret, scratch, agent_directory, agent_uid, owned_paths, owned_launchd_labels,
):
    """Load an idle system-domain job before a fresh clipboard lease starts."""
    human_manager_uid, human_manager_name = launchd_manager_context()
    assert agent_uid != os.getuid(), "isolated pasteboard job reused the human UID"
    label = f"{LABEL}.pasteboard-agent"
    plist_path = scratch / "pasteboard-agent.plist"
    launcher_path = scratch / "pasteboard-agent-launcher.py"
    result_path = agent_directory / "pasteboard-result"
    stdout_path = agent_directory / "pasteboard-stdout"
    stderr_path = agent_directory / "pasteboard-stderr"
    assert sudo(["launchctl", "print", f"system/{label}"], check=False).returncode != 0, (
        "isolated pasteboard launch label already exists"
    )

    owned_paths.append(("pasteboard-launcher", launcher_path))
    with open(launcher_path, "w", encoding="ascii", newline="\n") as launcher:
        launcher.write(AGENT_PASTEBOARD_LAUNCHER)
    sudo(["chown", "root:wheel", launcher_path])
    sudo(["chmod", "0555", launcher_path])

    for name, path in (("pasteboard-result", result_path),
                       ("pasteboard-stdout", stdout_path),
                       ("pasteboard-stderr", stderr_path)):
        owned_paths.append((name, path))
        sudo(["touch", path], user=AGENT)
        sudo(["chmod", "0600", path], user=AGENT)
        require_owner_mode(path, (agent_uid, 0o600))

    launchd_config = {
        "Label": label,
        "ProgramArguments": [
            sys.executable, str(launcher_path), str(result_path), str(agent_uid),
            str(human_manager_uid), human_manager_name, str(len(secret)),
            hashlib.sha256(secret).hexdigest(),
        ],
        "UserName": AGENT,
        "GroupName": AGENT,
        "LimitLoadToSessionType": "System",
        # Bootstrap the job before the copy lease, but trigger its one shot
        # only after the isolated session has copied the marker.
        "RunAtLoad": False,
        # Keep this on-demand job loaded after its one kickstart so the
        # harness can observe the result and last exit status before the
        # owned bootout.  The one-shot-only setting makes launchd
        # garbage-collect the job as soon as it exits, which races that
        # observation.
        "KeepAlive": False,
        "ProcessType": "Background",
        "WorkingDirectory": "/var/empty",
        "Umask": 63,
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
    }
    owned_paths.append(("pasteboard-plist", plist_path))
    with open(plist_path, "wb") as plist_file:
        plistlib.dump(launchd_config, plist_file)
    sudo(["chown", "root:wheel", plist_path])
    sudo(["chmod", "0644", plist_path])
    sudo(["plutil", "-lint", plist_path])
    require_owner_mode(launcher_path, (0, 0o555))
    require_owner_mode(plist_path, (0, 0o644))
    owned_launchd_labels.append(label)
    sudo(["launchctl", "bootstrap", "system", plist_path])
    return {
        "label": label,
        "result_path": result_path,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
    }


def assert_launchd_agent_cannot_read_pasteboard(
    prepared, *, diagnostic=False, session=None,
):
    """Run the exact pasteboard probe from an owned system-domain launchd job."""
    sudo_command = sudo if session is None else session.run_sudo_while_draining
    label = prepared["label"]
    result_path = prepared["result_path"]
    stdout_path = prepared["stdout_path"]
    stderr_path = prepared["stderr_path"]
    assert sudo_command(["test", "!", "-s", result_path], check=False).returncode == 0, (
        "isolated pasteboard launch result was nonempty before kickstart"
    )
    sudo_command(["launchctl", "kickstart", f"system/{label}"])
    wait_for_agent_launch(label, result_path, session=session)

    result = sudo_command(["cat", result_path])
    fields = parse_agent_pasteboard_result(result.stdout)
    for path in (stdout_path, stderr_path):
        output = sudo_command(["cat", path])
        assert output.returncode == 0 and output.stdout == b"" and output.stderr == b"", (
            "isolated pasteboard launch emitted unclassified output"
        )
    if diagnostic:
        for name in (
            b"agent-uid", b"manager-uid", b"manager-name", b"manager-domain",
            b"probe-result", b"probe-canary-stdout", b"probe-canary-stderr",
            b"probe-success-read",
        ):
            emit_diagnostic(b"PM26_DIAGNOSTIC pasteboard-isolated-"
                            + name + b"=" + fields[name])
    assert fields[b"agent-uid"] == b"expected", "isolated pasteboard job UID was not the agent"
    assert fields[b"manager-uid"] == b"system" \
        and fields[b"manager-domain"] == b"different", (
            "isolated pasteboard job was not in a distinct system domain"
        )
    assert fields[b"probe-canary-stdout"] == b"absent" \
        and fields[b"probe-canary-stderr"] == b"absent", (
            "isolated pasteboard probe exposed the exact human canary"
        )
    assert fields[b"probe-success-read"] == b"no", (
        "isolated pasteboard probe result was indeterminate or exposed the canary"
    )


def create_account(name, uid, owned_records):
    group = f"/Groups/{name}"
    user = f"/Users/{name}"
    sudo(["dscl", ".", "-create", group])
    owned_records.append(group)
    sudo(["dscl", ".", "-create", group, "PrimaryGroupID", str(uid)])
    sudo(["dscl", ".", "-create", user])
    owned_records.append(user)
    for attribute, value in [
        ("RealName", f"Password Manager ticket 26 {name}"),
        ("UniqueID", str(uid)), ("PrimaryGroupID", str(uid)),
        ("NFSHomeDirectory", "/var/empty"), ("UserShell", "/usr/bin/false"),
        ("IsHidden", "1"), ("Password", "*"),
    ]:
        sudo(["dscl", ".", "-create", user, attribute, value])


def require_no_login_account(name):
    for attribute, expected in (
        ("UserShell", "/usr/bin/false"),
        ("NFSHomeDirectory", "/var/empty"),
    ):
        result = sudo(["dscl", ".", "-read", f"/Users/{name}", attribute], check=False)
        assert result.returncode == 0 and result.stderr == b"" \
            and result.stdout == f"{attribute}: {expected}\n".encode("ascii"), (
                "synthetic launchd account is not a no-login account"
            )


class OwnedCleanupError(AssertionError):
    def __init__(self, errors):
        self.errors = tuple(errors)
        super().__init__("; ".join(str(error) for error in self.errors))


def parse_launchctl_labels(output):
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("launchd cleanup inventory is malformed") from error
    assert lines and lines[0] == "PID\tStatus\tLabel", \
        "launchd cleanup inventory is malformed"
    labels = set()
    for line in lines[1:]:
        fields = line.split("\t")
        assert len(fields) == 3, "launchd cleanup inventory is malformed"
        pid, status, label = fields
        assert (pid == "-" or pid.isascii() and pid.isdecimal()), \
            "launchd cleanup inventory is malformed"
        assert re.fullmatch(r"-?[0-9]+", status), \
            "launchd cleanup inventory is malformed"
        assert label and not any(ord(character) < 0x20 for character in label), \
            "launchd cleanup inventory is malformed"
        labels.add(label)
    return labels


def parse_directory_records(output):
    try:
        records = output.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AssertionError("directory cleanup inventory is malformed") from error
    assert records, "directory cleanup inventory is malformed"
    assert all(record and not any(ord(character) < 0x20 for character in record)
               for record in records), "directory cleanup inventory is malformed"
    return set(records)


def require_safe_existing_parent(path):
    result = sudo(["stat", "-f", "%u %p", path])
    try:
        owner, encoded_mode = result.stdout.decode().strip().split()
        full_mode = int(encoded_mode, 8)
        assert int(owner) == 0 and stat.S_ISDIR(full_mode)
        assert stat.S_IMODE(full_mode) & 0o022 == 0
    except (AssertionError, UnicodeDecodeError, ValueError) as error:
        raise AssertionError("fixed install parent is not a safe root directory") from error


def cleanup_owned_resources(
    bootstrapped, owned_paths, owned_empty_directories, owned_records, invoke=sudo,
    path_exists=os.path.lexists, owned_launchd_labels=(),
):
    errors = []

    def attempt(action, command):
        try:
            result = invoke(command, check=False)
            if result.returncode != 0:
                errors.append(AssertionError(
                    f"owned cleanup failed: action={action} returncode={result.returncode}"
                ))
        except BaseException as error:
            errors.append(AssertionError(f"owned cleanup raised: action={action}"))
            errors[-1].__cause__ = error

    launchd_labels = list(owned_launchd_labels)
    if bootstrapped:
        launchd_labels.insert(0, LABEL)
    for label in launchd_labels:
        action = "launchd-bootout" if label == LABEL else f"launchd-bootout-{label}"
        attempt(action, ["launchctl", "bootout", f"system/{label}"])
    for name, path in reversed(owned_paths):
        attempt(f"remove-{name}", ["rm", "-rf", path])
    for name, path in reversed(owned_empty_directories):
        attempt(f"rmdir-{name}", ["rmdir", path])
    for record in reversed(owned_records):
        kind = "user" if record.startswith("/Users/") else "group"
        attempt(f"delete-{kind}", ["dscl", ".", "-delete", record])

    if launchd_labels:
        try:
            result = invoke(["launchctl", "list"], check=False)
            if result.returncode != 0:
                raise AssertionError("launchd cleanup inventory query failed")
            labels = parse_launchctl_labels(result.stdout)
            for label in launchd_labels:
                if label in labels:
                    errors.append(AssertionError("owned cleanup left launchd job"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: launchd")
            wrapped.__cause__ = error
            errors.append(wrapped)
    for name, path in owned_paths:
        try:
            if path_exists(path):
                errors.append(AssertionError(f"owned cleanup left path: name={name}"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: path")
            wrapped.__cause__ = error
            errors.append(wrapped)
    for name, path in owned_empty_directories:
        try:
            if path_exists(path):
                errors.append(AssertionError(f"owned cleanup left directory: name={name}"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: directory")
            wrapped.__cause__ = error
            errors.append(wrapped)
    for kind, root in (("user", "/Users"), ("group", "/Groups")):
        prefix = f"/{root.strip('/')}/"
        expected = {
            record.rsplit("/", 1)[1]
            for record in owned_records
            if record.startswith(prefix)
        }
        if not expected:
            continue
        try:
            result = invoke(["dscl", ".", "-list", root], check=False)
            if result.returncode != 0:
                raise AssertionError("directory cleanup inventory query failed")
            inventory = parse_directory_records(result.stdout)
            if expected & inventory:
                errors.append(AssertionError(f"owned cleanup left record: kind={kind}"))
        except BaseException as error:
            wrapped = AssertionError("owned cleanup absence check raised: directory-record")
            wrapped.__cause__ = error
            errors.append(wrapped)
    return errors


def finish_owned_resources(
    lab_error, bootstrapped, owned_paths, owned_empty_directories,
    owned_records, invoke=sudo, owned_launchd_labels=(),
):
    cleanup_errors = cleanup_owned_resources(
        bootstrapped, owned_paths, owned_empty_directories, owned_records, invoke,
        owned_launchd_labels=owned_launchd_labels,
    )
    if lab_error is not None:
        if cleanup_errors:
            aggregate = OwnedCleanupError(cleanup_errors)
            if lab_error.__cause__ is not None:
                aggregate.__context__ = lab_error.__cause__
            raise lab_error from aggregate
        raise lab_error
    if cleanup_errors:
        raise OwnedCleanupError(cleanup_errors)


def unused_ids(count):
    listings = [
        run(["dscl", ".", "-list", "/Users", "UniqueID"]).stdout.decode(),
        run(["dscl", ".", "-list", "/Groups", "PrimaryGroupID"]).stdout.decode(),
    ]
    used = {
        int(line.rsplit(None, 1)[1])
        for output in listings
        for line in output.splitlines()
        if line.split()
    }
    values = [candidate for candidate in range(450, 500) if candidate not in used]
    assert len(values) >= count, "no unused synthetic system-account UIDs"
    return values[:count]


def keygen(binary, user, private, public):
    command = [binary, "keygen", "--private", private, "--public", public]
    result = run(command, check=False) if user is None else sudo(
        command, user=user, check=False,
    )
    identity = "runner" if user is None else user
    if result.returncode != 0:
        raise AssertionError(
            f"synthetic keygen failed for {identity}: returncode={result.returncode}, "
            f"stdout={result.stdout[:1024]!r}, stderr={result.stderr[:1024]!r}"
        )


def parse_owner_mode(output):
    owner, mode = output.strip().split()
    full_mode = int(mode, 8)
    assert not stat.S_ISLNK(full_mode), (
        f"refusing symbolic link metadata: owner={owner}, mode={mode}"
    )
    return int(owner), stat.S_IMODE(full_mode)


def owner_mode(path):
    result = sudo(["stat", "-f", "%u %p", path])
    try:
        return parse_owner_mode(result.stdout.decode())
    except (AssertionError, UnicodeDecodeError, ValueError) as error:
        raise AssertionError(
            f"invalid owner/mode metadata: path={path}, raw={result.stdout[:128]!r}"
        ) from error


def require_owner_mode(path, expected):
    actual = owner_mode(path)
    assert actual == expected, (
        f"owner/mode mismatch: path={path}, expected={expected}, actual={actual}"
    )


def parse_regular_metadata(output):
    owner, mode, links, size = output.strip().split()
    full_mode = int(mode, 8)
    assert stat.S_ISREG(full_mode), (
        f"fixture is not a regular file: owner={owner}, mode={mode}, "
        f"links={links}, size={size}"
    )
    return int(owner), stat.S_IMODE(full_mode), int(links), int(size)


def require_readable_regular(user, path, expected_uid, expected_mode):
    metadata = sudo(["stat", "-f", "%u %p %l %z", path])
    actual = parse_regular_metadata(metadata.stdout.decode())
    expected = (expected_uid, expected_mode)
    assert actual[:2] == expected and actual[2] == 1 and 1 <= actual[3] <= 16 * 1024, (
        f"unsafe readable-file metadata: path={path}, expected={expected}, actual={actual}"
    )
    readable = sudo(["test", "-r", path], user=user, check=False)
    assert readable.returncode == 0 and readable.stdout == b"" and readable.stderr == b"", (
        f"effective fixture read failed: user={user}, path={path}, "
        f"returncode={readable.returncode}, stderr={readable.stderr[:1024]!r}"
    )


def require_traversal(user, path):
    result = sudo(["test", "-x", path], user=user, check=False)
    assert result.returncode == 0, (
        f"fixture traversal prerequisite failed: user={user}, path={path}, "
        f"returncode={result.returncode}, stdout={result.stdout[:1024]!r}, "
        f"stderr={result.stderr[:1024]!r}"
    )


def peer_uid(stream):
    uid = ctypes.c_uint(0)
    gid = ctypes.c_uint(0)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getpeereid.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
    ]
    libc.getpeereid.restype = ctypes.c_int
    result = libc.getpeereid(stream.fileno(), ctypes.byref(uid), ctypes.byref(gid))
    assert result == 0, f"synthetic getpeereid failed: errno={ctypes.get_errno()}"
    return uid.value


def cross_uid_peer_diagnostic(agent_uid, scratch):
    endpoint = scratch / "cross-uid-diagnostic.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(endpoint)); endpoint.chmod(0o666)
    require_owner_mode(endpoint, (os.getuid(), 0o666))
    listener.listen(1); listener.settimeout(5)
    client = subprocess.Popen(
        ["sudo", "-n", "-u", AGENT, sys.executable, "-c", PEER_UID_SCRIPT,
         str(endpoint), "wait"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        connection, _ = listener.accept()
        with connection:
            assert peer_uid(connection) == agent_uid
            connection.sendall(b"x")
        stdout, stderr = client.communicate(timeout=5)
        assert client.returncode == 0 and stderr == b"", (
            client.returncode, stdout[:1024], stderr[:1024],
        )
        assert stdout == f"{os.getuid()}\n".encode(), stdout[:1024]
    finally:
        listener.close()
        if client.poll() is None:
            client.kill(); client.wait(timeout=5)
        if endpoint.exists():
            endpoint.unlink()


def launchd_peer_uid(user, endpoint):
    result = sudo(
        [sys.executable, "-c", PEER_UID_SCRIPT, endpoint],
        user=user, check=False,
    )
    assert result.returncode == 0 and result.stderr == b"", (
        result.returncode, result.stdout[:1024], result.stderr[:1024],
    )
    return int(result.stdout.decode().strip())


def publish_rpk(source, destination):
    sudo(["install", "-o", "root", "-g", "wheel", "-m", "0444", source, destination])
    require_owner_mode(destination, (0, 0o444))
    assert sudo(["cmp", "-s", source, destination], check=False).returncode == 0


def create_vault(cli, path, diagnostic):
    process = subprocess.Popen(
        ["sudo", "-n", "-u", CUSTODIAN, str(cli), "vault", "create", str(path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert process.stdout.readline() == b"Master password (read from stdin):\n"
    process.stdin.write(PASSWORD + b"\n"); process.stdin.flush()
    assert process.stdout.readline() == b"Confirm master password:\n"
    process.stdin.write(PASSWORD + b"\n"); process.stdin.flush()
    derivation_started = time.monotonic_ns()
    recovery = process.stdout.readline()
    derivation_ms = min((time.monotonic_ns() - derivation_started) // 1_000_000, 999_999)
    if diagnostic:
        creation_status = f"PM26_DIAGNOSTIC vault-root-create-ms={derivation_ms}".encode()
        diagnostic_lines(creation_status)
        print(creation_status.decode())
    assert recovery.startswith(b"Recovery code (store externally): PMR1-")
    assert process.stdout.readline() == b"Reintroduce recovery code to confirm the external copy:\n"
    process.stdin.write(recovery.split(b": ", 1)[1]); process.stdin.close()
    stdout, stderr = process.stdout.read(), process.stderr.read()
    assert process.wait(timeout=30) == 0, (stdout, stderr)
    assert stdout.startswith(b"Vault created: ") and stderr == b""


def wait_for_service():
    deadline = time.monotonic() + 20
    sockets = [RUNTIME / "agent.sock", RUNTIME / "human.sock"]
    while time.monotonic() < deadline:
        if all(path.exists() for path in sockets):
            try:
                for path in sockets:
                    probe = socket.socket(socket.AF_UNIX)
                    probe.settimeout(0.2); probe.connect(str(path)); probe.close()
                return
            except OSError:
                pass
        time.sleep(0.1)
    details = sudo(["launchctl", "print", f"system/{LABEL}"], check=False)
    raise AssertionError((details.returncode, details.stdout, details.stderr))


def diagnostic_lines(value):
    lines = value.splitlines()
    assert lines and len(lines) <= 32 and all(DIAGNOSTIC_LINE.fullmatch(line) for line in lines), (
        "unsafe or missing ticket-26 diagnostic output", len(lines),
    )
    return lines


def parse_sodium_cflags(config_log):
    values = re.findall(rb"(?m)^CFLAGS='([^']*)'$", config_log)
    assert len(values) == 1, "native libsodium build metadata is unavailable or ambiguous"
    try:
        flags = shlex.split(values[0].decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise AssertionError(
            "native libsodium build metadata is unavailable or ambiguous"
        ) from error
    opt0 = "-O0" in flags
    optimized = any(flag in {"-O1", "-O2", "-O3", "-Os", "-Oz", "-Ofast"} for flag in flags)
    assert opt0 != optimized, "native libsodium build metadata is unavailable or ambiguous"
    return b"opt0" if opt0 else b"optimized"


def classify_native_sodium(config_log, diagnostic):
    assert config_log.is_file(), "native libsodium build metadata is unavailable"
    classification = parse_sodium_cflags(config_log.read_bytes())
    assert classification == b"optimized", "native libsodium build is not optimized"
    if diagnostic:
        status = b"PM26_DIAGNOSTIC sodium-cflags=" + classification
        diagnostic_lines(status)
        print(status.decode())
    else:
        print("PASS macos-libsodium cflags=optimized")


def classify_launchd_service(result, expected_pid):
    if result.returncode != 0:
        return b"unavailable"
    if result.stderr:
        return b"unparseable"
    match = re.search(rb"\bpid = ([0-9]+)\b", result.stdout)
    if match is None:
        return b"unparseable"
    return b"same-pid" if int(match.group(1)) == expected_pid else b"different-pid"


def human_authorization_setup(
    binary, profile, private, endpoint, first, second, service_pid, diagnostic,
):
    command = [
        binary, "human-authorization",
        "--profile", profile, "--private", private, "--socket", endpoint,
        "--action", "setup",
    ]
    if diagnostic:
        command = ["env", f"{DIAGNOSTIC_ENV}=1"] + command
    result = run(command, check=False, input=wire_fields([PASSWORD, first, second]))
    if not diagnostic:
        assert result.returncode == 0, (
            "human authorization setup failed in normal mode", result.returncode,
        )
        assert result.stdout == b"PASS human-authorization action=setup\n"
        assert result.stderr == b""
        return result
    diagnostic_stderr = result.stderr
    if result.returncode == 4:
        assert diagnostic_stderr.endswith(b"CUSTODY_UNAVAILABLE\n")
        diagnostic_stderr = diagnostic_stderr.removesuffix(b"CUSTODY_UNAVAILABLE\n")
    assert result.returncode in (0, 4), (
        "human authorization setup exited outside its public contract",
        result.returncode,
    )
    client = diagnostic_lines(diagnostic_stderr)
    if result.returncode == 4:
        launchd = sudo(["launchctl", "print", f"system/{LABEL}"], check=False)
        classification = classify_launchd_service(launchd, service_pid)
        status = b"PM26_DIAGNOSTIC launchd-service=" + classification
        diagnostic_lines(status + b"\n")
        print(status.decode())
    service = sudo(["tail", "-n", "32", DIAGNOSTIC_LOG], check=False)
    assert service.returncode == 0 and service.stderr == b"", (
        "custodian diagnostic log unavailable", service.returncode,
    )
    server = diagnostic_lines(service.stdout)
    print("PM26_DIAGNOSTIC client=" + ",".join(line.decode() for line in client))
    print("PM26_DIAGNOSTIC server=" + ",".join(line.decode() for line in server))
    if result.returncode == 0:
        assert result.stdout == b"PASS human-authorization action=setup\n"
        return result
    assert result.stdout == b""
    raise AssertionError(
        "human authorization setup remained unavailable; see fixed PM26_DIAGNOSTIC lines"
    )


def seed_tui_content(binary, profile, private, endpoint):
    result = run(
        [binary, "human-content-flow", "--profile", profile, "--private", private,
         "--socket", endpoint],
        check=False, input=wire_fields([PASSWORD]),
    )
    assert result.returncode == 0 and result.stdout.startswith(b"PASS content-e2e types=7") \
        and result.stderr == b"", (
            "TUI content seed failed", result.returncode, result.stdout[:1024],
            result.stderr[:1024],
        )


def agent_discovery(binary, profile, private, endpoint, *, allowed=True):
    result = sudo(
        [binary, "agent-discover", "--profile", profile, "--private", private,
         "--socket", endpoint],
        user=AGENT, check=False,
    )
    if not allowed:
        expect_unavailable(result)
        return None
    assert result.returncode == 0 and result.stdout.startswith(b"PASS delegated-discovery") \
        and result.stderr == b"", (
            "agent discovery failed after TUI lock", result.returncode,
            result.stdout[:1024], result.stderr[:1024],
        )
    return result.stdout.decode("utf-8")


def require_agent_discovery(binary, profile, private, endpoint):
    return agent_discovery(binary, profile, private, endpoint)


def wait_selected_access_row(session, marker, *, timeout=8, limit=64):
    """Select one metadata-only access row without assuming credential order."""
    deadline = time.monotonic() + timeout
    for _ in range(limit):
        session.drain()
        rendered = session.screen.application_text()
        if any("›" in line and marker in line for line in rendered.splitlines()):
            return session.mark()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        start = session.mark()
        session.send_key("j")
        session.wait_text("Delegated authority (metadata only)", since=start,
                          timeout=remaining)
    raise AssertionError(f"TUI access row was not selected: {marker}")


def start_agent_attempt(binary, profile, private, endpoint, item):
    """Start one real agent attempt for the standard vault service."""
    result = sudo(
        [binary, "agent-attempt", "--profile", profile, "--private", private,
         "--socket", endpoint, "--action", "start", "--item", item,
         "--issued-at", str(int(time.time() * 1_000_000)), "--nonce", "24" * 16,
         "--context", "ticket24-macos-pending-canary"],
        user=AGENT, check=False,
    )
    assert result.returncode == 0 and result.stderr == b"", (
        "agent attempt start failed", result.returncode, result.stdout[:1024],
        result.stderr[:1024],
    )
    output = result.stdout.decode("utf-8")
    match = re.search(r"PASS attempt id=([0-9a-f]{32}).*state=([A-Z_]+)", output)
    assert match and match.group(2) == "CREATED", output
    assert b"ticket24-macos-pending-canary" not in result.stdout
    return match.group(1)


def agent_attempt_state(binary, profile, private, endpoint, attempt):
    result = sudo(
        [binary, "agent-attempt", "--profile", profile, "--private", private,
         "--socket", endpoint, "--action", "get", "--attempt", attempt],
        user=AGENT, check=False,
    )
    assert result.returncode == 0 and result.stderr == b"", (
        "agent attempt state query failed", result.returncode,
        result.stdout[:1024], result.stderr[:1024],
    )
    output = result.stdout.decode("utf-8")
    match = re.search(r"PASS attempt id=[0-9a-f]{32}.*state=([A-Z_]+)", output)
    assert match, output
    return match.group(1), output


def start_macos_tui(binary, profile, private, endpoint, *, idle, reveal, copy):
    session = MacPtySession.start(
        binary, profile, private, endpoint, idle=idle, reveal=reveal, copy=copy,
    )
    try:
        session.wait_text("Password required")
        assert b"\x1b[6n" not in bytes(session.output), (
            "TUI PTY startup must not require a terminal-emulator cursor response"
        )
        session.send_text(PASSWORD.decode("ascii"), enter=True, hidden=True)
        session.wait_text("Unlocked: selection never reveals secrets")
        return session
    except BaseException:
        close_session_preserving_primary(session)
        raise


def tui_search(session, value):
    start = session.mark()
    session.send_key("/")
    session.wait_text("Search (engine-decrypted):", since=start)
    search_start = session.mark()
    session.send_text(value, enter=True)
    return session.wait_text("Search returned 1 active items", since=search_start)


def selected_tui_row(rendered, title):
    rows = [
        line for line in rendered.splitlines()
        if "›" in line and title in line
    ]
    assert len(rows) == 1, ("TUI selected-row observation was ambiguous", rows)
    return rows[0]


def select_tui_password_for_copy(session):
    # Catalog order is defined by opaque item IDs, not fixture insertion order.
    # Establish the intended record through the same human-visible search used
    # by the product before relying on the field descriptor index.
    tui_search(session, "Password")
    start = session.mark()
    session.send_key("c")
    session.wait_text("Fields (explicit selection; values hidden)", since=start)
    start = session.mark()
    session.send_text("j" * 14)
    session.wait_selected("auth[0].password", since=start)
    copy_start = session.mark()
    session.send_key("enter")
    return copy_start


def select_tui_field(session, title, action, label, index):
    tui_search(session, title)
    start = session.mark()
    session.send_key(action)
    session.wait_text("Fields (explicit selection; values hidden)", since=start)
    start = session.mark()
    session.send_text("j" * index)
    session.wait_selected(label, since=start)
    selected = session.mark()
    session.send_key("enter")
    return selected


def assert_tui_field_catalog(session, title, fields):
    tui_search(session, title)
    start = session.mark()
    session.send_key("r")
    session.wait_text("Fields (explicit selection; values hidden)", since=start)
    for index, label in enumerate(fields):
        if index:
            move = session.mark()
            session.send_key("j")
            session.wait_selected(label, since=move)
        else:
            session.wait_selected(label, since=start)
    escaped = session.mark()
    session.send_key("escape")
    session.wait_text("Exposure cancelled", since=escaped)


def reveal_tui_field(session, title, label, index, expected):
    revealed = select_tui_field(session, title, "r", label, index)
    deadline = time.monotonic() + 8
    while True:
        rendered = session._current_text_after(revealed)
        if (rendered is not None and "Secret revealed temporarily" in rendered
                and (expected is None or any(
                    expected in line for line in exposure_rows(rendered)))):
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("TUI field reveal did not render the expected synthetic value")
        session._read_once(min(0.1, remaining))
    wait_stable_reveal_expiry(
        session,
        forbidden=expected,
        forbidden_in_exposure=(expected == "note"),
        since=revealed,
    )


def exposure_rows(rendered):
    """Read the actual bordered footer, not catalog metadata or VT bytes."""
    rows = []
    for line in rendered.splitlines():
        line = line.rstrip(" ")
        if line.startswith("│") and line.endswith("│"):
            content = line[1:-1].strip()
            if content.startswith("Exposure:"):
                rows.append(content)
    return tuple(rows)


def wait_stable_reveal_expiry(
    session, *, forbidden=None, forbidden_in_exposure=False, timeout=8, since=0,
):
    """Observe expiry only on one current frame with the exposure removed.

    ``App::expire`` updates the status before the next complete terminal draw.
    A PTY read can therefore expose a repaint where ``Reveal expired`` is
    visible while the previous exposure line is still present.  Do not accept
    that intermediate frame or search historical screen events: the status,
    hidden exposure marker and forbidden value must agree on the current
    screen before the original wait deadline expires.  Distinctive synthetic
    canaries are forbidden on the whole current screen.  The one generic
    ``note`` field uses ``forbidden_in_exposure`` so its catalog label cannot
    be mistaken for the revealed value.
    """
    deadline = time.monotonic() + timeout
    while True:
        rendered = session._current_text_after(since)
        exposure_lines = () if rendered is None else exposure_rows(rendered)
        forbidden_absent = rendered is not None and (
            forbidden is None
            or (
                all(forbidden not in line for line in exposure_lines)
                if forbidden_in_exposure
                else forbidden not in rendered
            )
        )
        if (
            rendered is not None
            and any("Reveal expired" in line for line in rendered.splitlines())
            and "Exposure: <hidden>" in exposure_lines
            and forbidden_absent
        ):
            return rendered
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(
                "TUI PTY stable reveal-expiry observation timed out "
                + session._screen_diagnostic(since)
            )
        session._read_once(min(0.1, remaining))


def run_tui_ticket23_matrix(binary, profile, private, endpoint):
    """Exercise Ticket 23 content contracts through the real macOS PTY."""
    wrong = MacPtySession.start(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=2,
    )
    try:
        wrong.wait_text("Password required")
        wrong.send_text("synthetic-definitely-wrong", enter=True, hidden=True)
        assert wrong.wait_exit(timeout=8) != 0
        assert b"synthetic-definitely-wrong" not in bytes(wrong.output)
    finally:
        close_session_preserving_primary(wrong)

    session = MacPtySession.start(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=2,
    )
    try:
        session.wait_text("Password required")
        session.send_text(PASSWORD.decode("ascii"), enter=True, hidden=True)
        session.wait_text("Unlocked: selection never reveals secrets")
        initial = session.screen.application_text()
        for title in TUI23_FIELD_CATALOG:
            assert title in initial, (
                "TUI content seed omitted a Ticket 23 title", title,
            )
        for title, fields in TUI23_FIELD_CATALOG.items():
            assert_tui_field_catalog(session, title, fields)

        for title, label, index, expected in (
            ("Password", "auth[0].password", 14, "ticket05-e2e-password-canary"),
            ("TOTP", "auth[0].secret", 13, "ticket05-e2e-totp-canary"),
            ("Passkey", "auth[0].private_key", 17, "s" * 32),
            ("SSH", "auth[0].private_key", 14, "ticket05-e2e-ssh-canary"),
            ("Token", "auth[0].secret", 13, "ticket05-e2e-token-canary"),
            ("ticket05-e2e-search-canary", "notes", 5, "note"),
            ("File", "attachment[0].content", 18,
             "ticket05-e2e-attachment-canary 🌎"),
            ("Exchange Relationship", "auth[0].subject_token", 6,
             "ticket11-e2e-subject-token-canary"),
            ("Exchange Relationship", "auth[0].requester_client_secret", 8,
             "ticket11-e2e-requester-secret-canary"),
        ):
            reveal_tui_field(session, title, label, index, expected)

        copied = select_tui_field(session, "Password", "c", "auth[0].password", 14)
        session.wait_text("Copied explicitly", since=copied)
        assert read_appkit_pasteboard(session=session) == TUI_PASSWORD_RECORD
        write_appkit_pasteboard(TUI_EXTERNAL_REPLACEMENT, session=session)
        session.wait_text("Clipboard custody expired", since=copied)
        assert read_appkit_pasteboard(session=session) == TUI_EXTERNAL_REPLACEMENT

        tui_search(session, "ticket05-e2e-search-canary")
        organized = session.mark()
        session.send_key("t")
        session.send_text("keyboard-ticket23", enter=True)
        organized_text = session.wait_text("Organization committed", since=organized)
        selected_before = selected_tui_row(
            organized_text, "ticket05-e2e-search-canary",
        )
        favorite_before = "★" in selected_before
        favorite = session.mark()
        session.send_key("f")
        favorite_text = session.wait_text("Favorite committed", since=favorite)
        selected_after = selected_tui_row(
            favorite_text, "ticket05-e2e-search-canary",
        )
        favorite_after = "★" in selected_after
        assert favorite_after is not favorite_before, (
            "favorite key did not toggle the selected row",
            selected_before, selected_after,
        )

        generated = session.mark()
        session.send_key("g")
        session.send_text("24", enter=True)
        session.wait_text("Generated secret revealed temporarily", since=generated)
        wait_stable_reveal_expiry(session, since=generated)

        history = session.mark()
        session.send_key("h")
        history_text = session.wait_text("History:", since=history)
        assert "lifecycle active" in history_text

        purge_revisions = session.mark()
        session.send_key("p")
        session.send_text("PURGE", enter=True)
        session.wait_text("Purged ", since=purge_revisions)
        trashed = session.mark()
        session.send_key("d")
        session.wait_text("Moved to trash", since=trashed)
        trash_history = session.mark()
        session.send_key("h")
        assert "lifecycle trash" in session.wait_text("History:", since=trash_history)
        restored = session.mark()
        session.send_key("u")
        session.wait_text("Restored with a new revision", since=restored)
        trashed_again = session.mark()
        session.send_key("d")
        session.wait_text("Moved to trash", since=trashed_again)
        purged = session.mark()
        session.send_key("P")
        session.send_text("PURGE", enter=True)
        session.wait_text("Item permanently purged", since=purged)

        session.send_key("l")
        assert session.wait_exit(timeout=8) == 0
    finally:
        close_session_preserving_primary(session)


def run_tui_ticket24_matrix(
    binary, profile, private, endpoint, agent_profile, agent_private, agent_endpoint,
    agent_directory,
):
    """Exercise Ticket 24 authority and pending keyboard contracts on macOS."""
    enrollment_private = agent_directory / "ticket24-enrollment.key"
    enrollment_public = agent_directory / "ticket24-enrollment.pub"
    assert not enrollment_private.exists() and not enrollment_public.exists()
    keygen(binary, AGENT, enrollment_private, enrollment_public)
    enrollment_rpk = sudo(["cat", enrollment_public]).stdout
    assert len(enrollment_rpk) == 44

    session = start_macos_tui(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=5,
    )
    try:
        resized = session.mark()
        session.resize(240, 30)
        session.wait_text("Items (selection is metadata only)", since=resized)

        access = session.mark()
        session.send_key("a")
        page = session.wait_text("Delegated authority (metadata only)", since=access)
        for marker in (
            "[agent active] Synthetic agent A",
            "[agent active] Synthetic agent B",
            "[credential enabled] Synthetic TLS shared account",
        ):
            assert marker in page, ("Ticket 24 access overview omitted safe metadata", marker)
        assert "ticket07-userns" in page
        assert TUI_PASSWORD_RECORD.decode("ascii") not in page

        # Enrollment is a closed keyboard payload.  The key is generated by
        # the existing real agent account and its public RPK is read through
        # the fixture's privileged observer; no second transport is fabricated.
        enroll_start = session.mark()
        session.send_key("n")
        session.wait_text("Enroll subject|request|SPKI|label|environment:", since=enroll_start)
        enrollment = (
            "c3" * 16 + "|" + "24" * 16 + "|" + enrollment_rpk.hex()
            + "|ticket24-agent-c|macos-lab"
        )
        session.send_text(enrollment, enter=True, hidden=True)
        session.wait_text("Delegated authority (metadata only)", since=enroll_start)
        wait_selected_access_row(session, "ticket24-agent-c")
        assert "[agent active] ticket24-agent-c" in session.screen.application_text()

        revoked_b = wait_selected_access_row(session, "Synthetic agent B")
        session.send_key("x")
        session.wait_text("[agent revoked] Synthetic agent B", since=revoked_b)
        revoked_c = wait_selected_access_row(session, "ticket24-agent-c")
        session.send_key("x")
        session.wait_text("[agent revoked] ticket24-agent-c", since=revoked_c)

        disabled = wait_selected_access_row(session, "Synthetic TLS shared account")
        session.send_key("e")
        session.wait_text("[credential disabled] Synthetic TLS shared account", since=disabled)
        empty = agent_discovery(
            binary, agent_profile, agent_private, agent_endpoint,
        )
        assert empty == "PASS delegated-discovery count=0 set=\n", empty

        enabled = wait_selected_access_row(session, "Synthetic TLS shared account")
        session.send_key("e")
        session.wait_text("[credential enabled] Synthetic TLS shared account", since=enabled)
        baseline = agent_discovery(
            binary, agent_profile, agent_private, agent_endpoint,
        )
        item = re.search(
            r"set=([0-9a-f]{32}):password:Synthetic TLS shared account:", baseline,
        )
        assert item, baseline

        suspended = session.mark()
        session.send_key("s")
        session.wait_text("Delegated access: SUSPENDED", since=suspended)
        agent_discovery(
            binary, agent_profile, agent_private, agent_endpoint, allowed=False,
        )
        resumed = session.mark()
        session.send_key("s")
        session.wait_text("Delegated access: RESUMED", since=resumed)
        assert agent_discovery(
            binary, agent_profile, agent_private, agent_endpoint,
        ).startswith("PASS delegated-discovery count=1"), "agent did not resume"

        # The standard macOS LaunchDaemon has no provider worker, so this
        # real agent operation remains CREATED.  It still exercises the
        # human-safe pending view and terminal cancellation without inventing
        # a passkey/provider response in a fixture that does not own one.
        content = session.mark()
        session.send_key("escape")
        session.wait_text("Content view", since=content)
        attempt = start_agent_attempt(
            binary, agent_profile, agent_private, agent_endpoint, item.group(1),
        )
        pending = session.mark()
        session.send_key("w")
        page = session.wait_text("Attempts (safe context only)", since=pending)
        assert "[CREATED] Synthetic TLS shared account" in page
        assert "integration=controlled.external" in page
        assert attempt in page
        assert "ticket24-macos-pending-canary" not in page
        assert PASSWORD.decode("ascii") not in page
        assert TUI_PASSWORD_RECORD.decode("ascii") not in page
        cancelled = session.mark()
        session.send_key("x")
        session.wait_text("Attempt CANCELLED", since=cancelled)
        state, output = agent_attempt_state(
            binary, agent_profile, agent_private, agent_endpoint, attempt,
        )
        assert state == "CANCELLED", output

        content = session.mark()
        session.send_key("escape")
        session.wait_text("Content view", since=content)
        session.send_key("l")
        assert session.wait_exit(timeout=8) == 0
        assert agent_discovery(
            binary, agent_profile, agent_private, agent_endpoint,
        ).startswith("PASS delegated-discovery count=1"), "human lock suspended agent"
        assert PASSWORD not in bytes(session.output)
        assert TUI_PASSWORD_RECORD not in bytes(session.output)
        assert b"\x1b]52;" not in bytes(session.output)
    finally:
        close_session_preserving_primary(session)


def run_shared_pasteboard_control(
    binary, profile, private, endpoint, *, pasteboard_observation,
):
    """Keep the shared-bootstrap negative separate from the timed TUI flow.

    The direct UID-switched probe is intentionally an unsupported control.  On
    a runner where that probe reaches its existing 30-second bound, keeping it
    in the same 30-second-idle TUI session would race the product's existing
    idle behavior and make the later explicit-lock assertion ambiguous.  This
    disposable session exercises the same real TUI copy path, while the main
    session remains reserved for the normal keyboard flow.
    """
    shared = start_macos_tui(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=30,
    )
    try:
        copied_start = select_tui_password_for_copy(shared)
        shared.wait_text("Copied explicitly", since=copied_start)
        if pasteboard_observation:
            emit_diagnostic(b"PM26_DIAGNOSTIC pasteboard-shared-control=unsupported")
            assert_agent_cannot_read_pasteboard(
                TUI_PASSWORD_RECORD, diagnostic=True, require_denied=False,
                session=shared,
            )
        # Close a still-running supporting TUI through the same human keyboard
        # path as the normal flow.  This keeps the PTY stream complete before
        # strict cleanup observes it; a child that already exited is classified
        # from its natural status instead of being signalled by cleanup.
        observe_child_exit_without_termination(shared)
        if shared.returncode is None and not shared.reaped:
            shared.send_key("l")
            assert shared.wait_exit(timeout=8) == 0, (
                "shared pasteboard control did not lock and exit normally",
                shared.returncode,
            )
    finally:
        try:
            observe_child_exit_without_termination(shared)
        finally:
            try:
                close_session_preserving_primary(shared)
            finally:
                if pasteboard_observation:
                    category, returncode = classify_shared_control_exit(
                        shared.returncode, shared.owned_termination_sent,
                    )
                    emit_diagnostic(
                        b"PM26_DIAGNOSTIC pasteboard-shared-control-exit="
                        + category + b" returncode=" + returncode
                    )
    category, returncode = classify_shared_control_exit(
        shared.returncode, shared.owned_termination_sent,
    )
    assert TUI_PASSWORD_RECORD not in bytes(shared.output)
    assert b"\x1b]52;" not in bytes(shared.output)
    if category not in (b"natural-zero", b"owned-termination"):
        raise AssertionError(
            "shared pasteboard control exit was not accepted",
            category,
            returncode,
        )


def run_tui_core_lab(
    binary, profile, private, endpoint, agent_profile, agent_private, agent_endpoint,
    *, diagnostic=False, pasteboard_diagnostic=False, scratch, agent_directory,
    agent_uid, owned_paths, owned_launchd_labels,
):
    seed_tui_content(binary, profile, private, endpoint)
    pasteboard_observation = diagnostic or pasteboard_diagnostic
    prepared_agent = prepare_launchd_agent(
        TUI_PASSWORD_RECORD, scratch, agent_directory, agent_uid,
        owned_paths, owned_launchd_labels,
    )
    if pasteboard_observation:
        run_shared_pasteboard_control(
            binary, profile, private, endpoint,
            pasteboard_observation=True,
        )
    first = start_macos_tui(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=30,
    )
    try:
        initial = first.text()
        assert "Items (selection is metadata only)" in initial
        for forbidden in (
            TUI_PASSWORD_RECORD,
            b"ticket05-e2e-totp-canary",
            b"ticket05-e2e-token-canary",
            b"ticket11-e2e-subject-token-canary",
            b"ticket11-e2e-requester-secret-canary",
        ):
            assert forbidden not in bytes(first.output), (
                "TUI PTY output contained a protected synthetic value"
            )

        for columns, rows, expected in (
            (42, 12, "Password Manager"),
            (100, 30, "selection is metadata only"),
        ):
            start = first.mark()
            first.resize(columns, rows)
            first.wait_text(expected, since=start)

        for title in (
            "Password", "TOTP", "Passkey", "SSH", "Token",
            "ticket05-e2e-search-canary", "File", "Exchange Relationship",
        ):
            tui_search(first, title)
        copied_start = select_tui_password_for_copy(first)
        first.wait_text("Copied explicitly", since=copied_start)
        first.send_key("l")
        assert first.wait_exit(timeout=8) == 0
        assert b"\x1b[6n" not in bytes(first.output), (
            "TUI PTY exit must not require a terminal-emulator cursor response"
        )
    finally:
        close_session_preserving_primary(first)
    assert TUI_PASSWORD_RECORD not in bytes(first.output)
    assert b"\x1b]52;" not in bytes(first.output)
    require_agent_discovery(binary, agent_profile, agent_private, agent_endpoint)

    # Use a fresh copy lease for the isolated job.  The shared-bootstrap
    # control above is intentionally separate and may consume its own bound.
    isolated = start_macos_tui(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=30,
    )
    try:
        copied_start = select_tui_password_for_copy(isolated)
        isolated.wait_text("Copied explicitly", since=copied_start)
        assert_human_pasteboard_canary(
            TUI_PASSWORD_RECORD, diagnostic=pasteboard_observation, phase="before",
            session=isolated,
        )
        probe_error = None
        try:
            assert_launchd_agent_cannot_read_pasteboard(
                prepared_agent, diagnostic=pasteboard_observation, session=isolated,
            )
        except BaseException as error:
            probe_error = error
        after_error = None
        try:
            assert_human_pasteboard_canary(
                TUI_PASSWORD_RECORD, diagnostic=pasteboard_observation, phase="after",
                session=isolated,
            )
        except BaseException as error:
            after_error = error
        if probe_error is not None:
            if after_error is not None:
                raise probe_error from after_error
            raise probe_error
        if after_error is not None:
            raise after_error
        isolated.send_key("l")
        assert isolated.wait_exit(timeout=8) == 0
        assert b"\x1b[6n" not in bytes(isolated.output), (
            "TUI PTY isolated-copy exit must not require a terminal-emulator cursor response"
        )
    finally:
        close_session_preserving_primary(isolated)
    assert TUI_PASSWORD_RECORD not in bytes(isolated.output)
    assert PASSWORD not in bytes(isolated.output)
    assert b"\x1b]52;" not in bytes(isolated.output)

    second = start_macos_tui(
        binary, profile, private, endpoint, idle=2, reveal=1, copy=5,
    )
    try:
        idle_start = second.mark()
        assert second.wait_exit(timeout=8) == 0
        assert b"\x1b[6n" not in bytes(second.output), (
            "TUI PTY idle exit must not require a terminal-emulator cursor response"
        )
        idle_text = second.text(idle_start)
        assert "Locked after 5 minutes without human input" in idle_text, (
            "TUI PTY idle lock status was not rendered"
        )
    finally:
        close_session_preserving_primary(second)
    assert PASSWORD not in bytes(second.output)
    assert TUI_PASSWORD_RECORD not in bytes(second.output)
    assert b"\x1b]52;" not in bytes(second.output)
    require_agent_discovery(binary, agent_profile, agent_private, agent_endpoint)

    expiry = start_macos_tui(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=5,
    )
    try:
        copied_start = select_tui_password_for_copy(expiry)
        expiry.wait_text("Copied explicitly", since=copied_start)
        assert_human_pasteboard_canary(TUI_PASSWORD_RECORD, session=expiry)
        write_appkit_pasteboard(TUI_EXTERNAL_REPLACEMENT, session=expiry)
        expiry_start = expiry.mark()
        expiry.wait_text("Clipboard custody expired", since=expiry_start)
        assert read_appkit_pasteboard(session=expiry) == TUI_EXTERNAL_REPLACEMENT
        expiry.send_key("l")
        assert expiry.wait_exit(timeout=8) == 0
    finally:
        close_session_preserving_primary(expiry)
    assert PASSWORD not in bytes(expiry.output)
    assert TUI_PASSWORD_RECORD not in bytes(expiry.output)
    assert b"\x1b]52;" not in bytes(expiry.output)
    require_agent_discovery(binary, agent_profile, agent_private, agent_endpoint)

    run_tui_ticket23_matrix(binary, profile, private, endpoint)
    run_tui_ticket24_matrix(
        binary, profile, private, endpoint, agent_profile, agent_private, agent_endpoint,
        agent_directory,
    )


def probe(binary, user, profile, private, endpoint, *, allowed=True, diagnostic=False):
    command = [binary, "probe", "--profile", profile, "--private", private,
               "--socket", endpoint]
    if diagnostic:
        command = ["env", f"{DIAGNOSTIC_ENV}=1"] + command
    result = sudo(command, user=user, check=False)
    diagnostic_stderr = result.stderr
    if diagnostic and result.returncode == 4:
        assert diagnostic_stderr.endswith(b"CUSTODY_UNAVAILABLE\n")
        diagnostic_stderr = diagnostic_stderr.removesuffix(b"CUSTODY_UNAVAILABLE\n")
    if diagnostic:
        client = diagnostic_lines(diagnostic_stderr)
        service = sudo(["cat", DIAGNOSTIC_LOG]).stdout
        server = diagnostic_lines(service)[-32:]
        assert b"PM26_DIAGNOSTIC accepted-stream-nonblocking-before=1" in server
        assert b"PM26_DIAGNOSTIC accepted-stream-nonblocking-after=0" in server
        print("PM26_DIAGNOSTIC client=" + ",".join(line.decode() for line in client))
        print("PM26_DIAGNOSTIC server=" + ",".join(line.decode() for line in server))
    if allowed:
        assert result.returncode == 0 and (diagnostic or result.stderr == b""), result
        assert result.stdout.startswith(b"READY role="), result.stdout
    else:
        assert result.returncode == 4 and result.stdout == b""
        assert result.stderr == b"CUSTODY_UNAVAILABLE\n", result.stderr


def expect_unavailable(result):
    assert result.returncode == 4 and result.stdout == b"", result
    assert result.stderr == b"CUSTODY_UNAVAILABLE\n", result.stderr


def fake_server_rejected_before_tls(binary, profile, private, impostor_home):
    endpoint = impostor_home / "impostor.sock"
    code = (
        "import os,socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); "
        "os.chmod(sys.argv[1], 0o666); "
        "s.listen(1); c,_=s.accept(); c.settimeout(2); "
        "\ntry: data=c.recv(1)\nexcept TimeoutError: data=b''\n"
        "print(len(data), flush=True)"
    )
    server = subprocess.Popen(
        ["sudo", "-n", "-u", OTHER, sys.executable, "-c", code, str(endpoint)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not endpoint.exists() and server.poll() is None:
        time.sleep(0.02)
    assert endpoint.exists(), server.communicate(timeout=1)
    probe(binary, AGENT, profile, private, endpoint, allowed=False)
    stdout, stderr = server.communicate(timeout=5)
    assert server.returncode == 0 and stdout == b"0\n" and stderr == b"", (stdout, stderr)


def parse_lab_arguments(values):
    arguments = list(values)
    diagnostic = bool(arguments and arguments[0] == "--diagnostic")
    pasteboard_diagnostic = bool(arguments and arguments[0] == "--pasteboard-diagnostic")
    if diagnostic or pasteboard_diagnostic:
        arguments.pop(0)
    assert len(arguments) == 4 and not any(
        value.startswith("--") for value in arguments
    ), "usage: macos_lab.py [--diagnostic|--pasteboard-diagnostic] CUSTODY CLI PLIST SODIUM_CONFIG"
    return diagnostic, pasteboard_diagnostic, tuple(
        pathlib.Path(value).resolve() for value in arguments
    )


def main():
    assert sys.platform == "darwin" and os.geteuid() != 0
    assert os.environ.get("PM_MACOS_EPHEMERAL_CI") == "1"
    assert DIAGNOSTIC_ENV not in os.environ, (
        "ticket 26 diagnostic activation must be injected only into owned fixture processes"
    )
    assert_screen_observer_regression()
    diagnostic, pasteboard_diagnostic, paths = parse_lab_arguments(sys.argv[1:])
    binary, cli, source_plist, sodium_config = paths
    classify_native_sodium(sodium_config, diagnostic)
    guarded = [INSTALL, STATE, RUNTIME, PLIST]
    collisions = [str(path) for path in guarded if path.exists()]
    assert not collisions, f"refusing to replace pre-existing host paths: {collisions}"
    assert sudo(["launchctl", "print", f"system/{LABEL}"], check=False).returncode != 0, \
        f"refusing to replace pre-existing launchd job: {LABEL}"
    for name in (CUSTODIAN, AGENT, OTHER):
        for record in (f"/Users/{name}", f"/Groups/{name}"):
            assert run(["dscl", ".", "-read", record], check=False).returncode != 0

    owned_records = []
    owned_paths = []
    owned_empty_directories = []
    owned_launchd_labels = []
    bootstrapped = False
    lab_error = None
    tui_core_verified = False
    scratch = pathlib.Path("/private/var/tmp/passwordmanager-ticket26")
    require_owner_mode(scratch.parent, (0, 0o1777))
    assert not scratch.exists(), f"refusing to replace pre-existing scratch path: {scratch}"
    try:
        scratch.mkdir(mode=0o711)
        owned_paths.append(("scratch", scratch))
        scratch.chmod(0o711)
        require_owner_mode(scratch, (os.getuid(), 0o711))
        custodian_uid, agent_uid, other_uid = unused_ids(3)
        for name, uid in [(CUSTODIAN, custodian_uid), (AGENT, agent_uid), (OTHER, other_uid)]:
            create_account(name, uid, owned_records)
            require_no_login_account(name)
        for name in (CUSTODIAN, AGENT, OTHER):
            require_traversal(name, scratch.parent)
            require_traversal(name, scratch)
        observed_agent_uid = sudo(["id", "-u"], user=AGENT).stdout.decode().strip()
        assert observed_agent_uid == str(agent_uid), observed_agent_uid
        cross_uid_peer_diagnostic(agent_uid, scratch)

        install_parent = INSTALL.parent
        if os.path.lexists(install_parent):
            require_safe_existing_parent(install_parent)
        else:
            sudo(["install", "-d", "-o", "root", "-g", "wheel", "-m", "0755", install_parent])
            owned_empty_directories.append(("install-parent", install_parent))
            require_owner_mode(install_parent, (0, 0o755))

        for name, path in [("install", INSTALL), ("state", STATE), ("runtime", RUNTIME)]:
            sudo(["mkdir", path])
            owned_paths.append((name, path))
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0755", binary, INSTALL / "pm-custody"])
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0755", cli, INSTALL / "pm"])
        sudo(["chown", f"{CUSTODIAN}:{CUSTODIAN}", STATE, RUNTIME])
        sudo(["chmod", "0700", STATE]); sudo(["chmod", "0755", RUNTIME])

        human = scratch / "human"; profiles = scratch / "profiles"
        publics = scratch / "public-rpks"
        sudo(["mkdir", "-p", human, profiles, publics])
        sudo(["chown", f"{os.getuid()}:{os.getgid()}", human]); sudo(["chmod", "0700", human])
        sudo(["chown", "root:wheel", profiles, publics])
        sudo(["chmod", "0755", profiles, publics])
        agent = scratch / "agent"; other = scratch / "other"
        impostor = scratch / "impostor"
        sudo(["mkdir", "-p", agent, other, impostor])
        sudo(["chown", f"{AGENT}:{AGENT}", agent]); sudo(["chmod", "0700", agent])
        sudo(["chown", f"{OTHER}:{OTHER}", other]); sudo(["chmod", "0700", other])
        sudo(["chown", f"{OTHER}:{OTHER}", impostor]); sudo(["chmod", "0755", impostor])
        for user, private in [(AGENT, human), (OTHER, human),
                              (CUSTODIAN, agent), (OTHER, agent),
                              (CUSTODIAN, other), (AGENT, other)]:
            denied = sudo(["test", "-r", private], user=user, check=False)
            assert denied.returncode != 0 and denied.stdout == b"", (user, private)

        server_key, server_pub = STATE / "server.key", STATE / "server.pub"
        human_key, human_pub = human / "human.key", human / "human.pub"
        agent_key, agent_pub = agent / "agent.key", agent / "agent.pub"
        other_key, other_pub = other / "other.key", other / "other.pub"
        keygen(INSTALL / "pm-custody", CUSTODIAN, server_key, server_pub)
        keygen(INSTALL / "pm-custody", None, human_key, human_pub)
        keygen(INSTALL / "pm-custody", AGENT, agent_key, agent_pub)
        keygen(INSTALL / "pm-custody", OTHER, other_key, other_pub)
        published_human_pub = publics / "human.pub"
        published_agent_pub = publics / "agent.pub"
        published_other_pub = publics / "other.pub"
        for source, destination in [(human_pub, published_human_pub),
                                    (agent_pub, published_agent_pub),
                                    (other_pub, published_other_pub)]:
            publish_rpk(source, destination)

        bootstrap = STATE / "bootstrap"
        sudo([INSTALL / "pm-custody", "provision-bootstrap", "--path", bootstrap,
              "--server-private", server_key, "--server-public", server_pub,
              "--agent-public", published_agent_pub, "--agent-uid", str(agent_uid),
              "--human-public", published_human_pub, "--human-uid", str(os.getuid())],
             user=CUSTODIAN)
        agent_profile, human_profile = profiles / "agent.profile", profiles / "human.profile"
        for role, profile in [("agent", agent_profile), ("human", human_profile)]:
            sudo([INSTALL / "pm-custody", "provision-profile", "--path", profile,
                  "--server-public", server_pub, "--server-uid", str(custodian_uid),
                  "--role", role])
        sudo(["chmod", "0444", agent_profile, human_profile])
        create_vault(INSTALL / "pm", STATE / "vault.sqlite3", diagnostic)

        with open(source_plist, "rb") as source:
            launchd_config = plistlib.load(source)
        assert "EnvironmentVariables" not in launchd_config
        assert "StandardErrorPath" not in launchd_config
        plist_to_install = source_plist
        if diagnostic:
            diagnostic_plist = scratch / "ticket26-launchd.plist"
            launchd_config["EnvironmentVariables"] = {DIAGNOSTIC_ENV: "1"}
            launchd_config["StandardErrorPath"] = str(DIAGNOSTIC_LOG)
            with open(diagnostic_plist, "wb") as destination:
                plistlib.dump(launchd_config, destination)
            plist_to_install = diagnostic_plist
        sudo(["install", "-o", "root", "-g", "wheel", "-m", "0644", plist_to_install, PLIST])
        owned_paths.append(("plist", PLIST))
        sudo(["plutil", "-lint", PLIST])
        sudo(["launchctl", "bootstrap", "system", PLIST]); bootstrapped = True
        wait_for_service()
        service = sudo(["launchctl", "print", f"system/{LABEL}"]).stdout.decode()
        pid = int(re.search(r"\bpid = (\d+)", service).group(1))
        process_user = run(["ps", "-o", "user=", "-p", str(pid)]).stdout.decode().strip()
        assert process_user == CUSTODIAN, (pid, process_user)
        process_command = run(["ps", "-o", "command=", "-p", str(pid)]).stdout.decode().strip()
        assert process_command.split()[0] == str(INSTALL / "pm-custody"), process_command

        for path, uid, mode in [(INSTALL / "pm-custody", 0, 0o755),
                                (PLIST, 0, 0o644), (bootstrap, custodian_uid, 0o400),
                                (agent_profile, 0, 0o444),
                                (published_agent_pub, 0, 0o444),
                                (agent_key, agent_uid, 0o400),
                                (RUNTIME / "agent.sock", custodian_uid, 0o666)]:
            require_owner_mode(path, (uid, mode))
        require_owner_mode(profiles, (0, 0o755))
        require_traversal(AGENT, profiles)
        require_traversal(AGENT, agent)
        require_readable_regular(AGENT, agent_profile, 0, 0o444)
        require_readable_regular(AGENT, agent_key, agent_uid, 0o400)
        assert launchd_peer_uid(AGENT, RUNTIME / "agent.sock") == custodian_uid
        probe(INSTALL / "pm-custody", AGENT, agent_profile, agent_key,
              RUNTIME / "agent.sock", diagnostic=diagnostic)
        probe(INSTALL / "pm-custody", pwd.getpwuid(os.getuid()).pw_name,
              human_profile, human_key, RUNTIME / "human.sock")

        # Give the wrong native UID the correct synthetic TLS key. Kernel peer
        # authentication must still reject it before request processing.
        copied_key = other / "agent-copy.key"
        sudo(["cp", agent_key, copied_key]); sudo(["chown", f"{OTHER}:{OTHER}", copied_key])
        sudo(["chmod", "0400", copied_key])
        probe(INSTALL / "pm-custody", OTHER, agent_profile, copied_key,
              RUNTIME / "agent.sock", allowed=False)
        probe(INSTALL / "pm-custody", AGENT, human_profile, agent_key,
              RUNTIME / "human.sock", allowed=False)
        probe(INSTALL / "pm-custody", pwd.getpwuid(os.getuid()).pw_name,
              agent_profile, human_key, RUNTIME / "agent.sock", allowed=False)
        fake_server_rejected_before_tls(INSTALL / "pm-custody", agent_profile,
                                        agent_key, impostor)

        for protected in [bootstrap, STATE / "vault.sqlite3"]:
            denied = sudo(["cat", protected], user=AGENT, check=False)
            assert denied.returncode != 0 and denied.stdout == b""
        for protected in [INSTALL / "pm-custody", PLIST, bootstrap]:
            denied = sudo(["chmod", "0777", protected], user=AGENT, check=False)
            assert denied.returncode != 0
        denied_service_control = sudo(
            ["launchctl", "bootout", f"system/{LABEL}"], user=AGENT, check=False,
        )
        assert denied_service_control.returncode != 0
        sudo(["chmod", "0600", agent_key], user=AGENT)
        probe(INSTALL / "pm-custody", AGENT, agent_profile, agent_key,
              RUNTIME / "agent.sock", allowed=False)
        sudo(["chmod", "0400", agent_key], user=AGENT)

        # Missing, malformed, or permission-broadened bootstrap must terminate
        # explicitly rather than generating or selecting substitute identity.
        for bad_bootstrap in [scratch / "missing-bootstrap", other / "corrupt-bootstrap",
                              other / "wide-bootstrap"]:
            if bad_bootstrap.name == "corrupt-bootstrap":
                sudo([sys.executable, "-c",
                      "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'synthetic-corruption')",
                      bad_bootstrap], user=OTHER)
                sudo(["chmod", "0400", bad_bootstrap], user=OTHER)
            elif bad_bootstrap.name == "wide-bootstrap":
                sudo(["cp", bootstrap, bad_bootstrap])
                sudo(["chown", f"{OTHER}:{OTHER}", bad_bootstrap]); sudo(["chmod", "0440", bad_bootstrap])
            failure = sudo(
                [INSTALL / "pm-custody", "serve", "--bootstrap", bad_bootstrap,
                 "--agent-socket", other / f"{bad_bootstrap.name}-agent.sock",
                 "--human-socket", other / f"{bad_bootstrap.name}-human.sock"],
                user=OTHER, check=False,
            )
            expect_unavailable(failure)

        human_authorization_setup(
            INSTALL / "pm-custody", human_profile, human_key, RUNTIME / "human.sock",
            published_agent_pub.read_bytes(), published_other_pub.read_bytes(), pid,
            diagnostic,
        )
        run_tui_core_lab(
            INSTALL / "pm-custody", human_profile, human_key, RUNTIME / "human.sock",
            agent_profile, agent_key, RUNTIME / "agent.sock",
            diagnostic=diagnostic,
            pasteboard_diagnostic=pasteboard_diagnostic,
            scratch=scratch, agent_directory=agent, agent_uid=agent_uid,
            owned_paths=owned_paths, owned_launchd_labels=owned_launchd_labels,
        )
        tui_core_verified = True
        suspend = run([INSTALL / "pm-custody", "human-authorization", "--profile", human_profile,
                       "--private", human_key, "--socket", RUNTIME / "human.sock", "--action", "suspend"],
                      input=wire_fields([PASSWORD]))
        assert suspend.stdout == b"PASS human-authorization action=suspend\n" and suspend.stderr == b""
        sudo(["launchctl", "kickstart", "-k", f"system/{LABEL}"])
        time.sleep(1); wait_for_service()
        discover = sudo([INSTALL / "pm-custody", "agent-discover", "--profile", agent_profile,
                         "--private", agent_key, "--socket", RUNTIME / "agent.sock"],
                        user=AGENT, check=False)
        assert discover.returncode == 4 and discover.stdout == b""
        assert discover.stderr == b"CUSTODY_UNAVAILABLE\n"

        tty_clipboard = run(["script", "-q", "/dev/null", INSTALL / "pm-custody", "macos-native-probe"])
        assert b"PASS macos-native tty=real rlimit-core=0 clipboard=AppKit-changeCount" in tty_clipboard.stdout
        if not diagnostic:
            diagnostic_log = sudo(["test", "-e", DIAGNOSTIC_LOG], check=False)
            assert diagnostic_log.returncode != 0 and diagnostic_log.stdout == b"", (
                "normal mode created a diagnostic log"
            )
    except BaseException as error:
        lab_error = error

    finish_owned_resources(
        lab_error,
        bootstrapped, owned_paths, owned_empty_directories, owned_records,
        owned_launchd_labels=owned_launchd_labels,
    )
    print("PASS macos-launchdaemon account=_passwordmanager peer=getpeereid bilateral=tls-rpk")
    print("PASS macos-acl bootstrap=0400 binary+plist=root-owned wrong-uid=rejected")
    print("PASS macos-persistence suspension=durable launchd-restart=real")
    print("PASS macos-native tty=/dev/tty clipboard=AppKit-changeCount fullfsync=queried-tests")
    if tui_core_verified:
        print("PASS macos-tui-core keyboard=1 pty=1 tty=/dev/tty service=launchd human-tls-rpk=1 "
              "search=1 copy=AppKit-changeCount clipboard-race=preserved hostile-agent=denied "
              "explicit-lock=1 idle-lock=1 resize=80x24+42x12+100x30")
    print("LIMIT reboot=NOT_RUN intel+arm64=handled-by-ticket31 signing+notarization=NOT_RUN")


if __name__ == "__main__":
    main()
