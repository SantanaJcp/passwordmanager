#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Destructive-only-inside-ephemeral-CI native macOS custody laboratory."""

import ctypes
import errno
import fcntl
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
DIAGNOSTIC_ENV = "PM_MACOS_TICKET26_DIAGNOSTIC"
DIAGNOSTIC_LOG = STATE / "ticket26-diagnostic.log"
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
            session.close()
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
    assert_pasteboard_diagnostic_regression()


def read_appkit_pasteboard():
    result = run(["osascript", "-e", "the clipboard as text"], check=False, timeout=10)
    assert result.returncode == 0 and result.stderr == b"", (
        "AppKit pasteboard observer failed", result.returncode, result.stderr[:1024],
    )
    return result.stdout.rstrip(b"\r\n")


def write_appkit_pasteboard(value):
    expression = f'set the clipboard to "{value.decode("ascii")}"'
    result = run(["osascript", "-e", expression], check=False, timeout=10)
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
        return b"unavailable"
    if result.stderr:
        return b"unparseable"
    manager_uid = result.stdout.strip()
    if manager_uid == b"0":
        return b"system"
    if manager_uid == str(human_uid).encode():
        return b"human"
    try:
        int(manager_uid, 10)
    except ValueError:
        return b"unparseable"
    return b"other"


def classify_domain_relation(human_domain, agent_domain):
    if human_domain in {b"unavailable", b"unparseable"} \
            or agent_domain in {b"unavailable", b"unparseable"}:
        return b"indeterminate"
    return b"same" if human_domain == agent_domain else b"different"


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


def assert_human_pasteboard_canary(secret, *, diagnostic=False):
    value = read_appkit_pasteboard()
    canary_read = value == secret
    if diagnostic:
        emit_diagnostic(
            b"PM26_DIAGNOSTIC pasteboard-human-canary-read="
            + (b"yes" if canary_read else b"no")
        )
    assert canary_read, "human AppKit pasteboard control did not read the exact canary"


def assert_agent_cannot_read_pasteboard(secret, *, diagnostic=False):
    if diagnostic:
        human_uid = os.getuid()
        agent_uid = pwd.getpwnam(AGENT).pw_uid
        human_identity = classify_identity(run(["id", "-u"], check=False), human_uid)
        agent_identity = classify_identity(
            sudo(["id", "-u"], user=AGENT, check=False), agent_uid
        )
        human_domain = classify_launchd_domain(
            run(["launchctl", "manageruid"], check=False), human_uid
        )
        agent_domain = classify_launchd_domain(
            sudo(["launchctl", "manageruid"], user=AGENT, check=False), human_uid
        )
    try:
        result = sudo(
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
            (b"pasteboard-human-domain", human_domain),
            (b"pasteboard-agent-domain", agent_domain),
            (b"pasteboard-domain-relation", classify_domain_relation(human_domain, agent_domain)),
        ):
            emit_diagnostic(b"PM26_DIAGNOSTIC " + name + b"=" + value)
    assert not canary_stdout and not canary_stderr, (
        "agent pasteboard probe exposed the exact human canary", result_status,
    )
    assert result is not None, "agent pasteboard probe result was indeterminate"


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
    path_exists=os.path.lexists,
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

    if bootstrapped:
        attempt("launchd-bootout", ["launchctl", "bootout", f"system/{LABEL}"])
    for name, path in reversed(owned_paths):
        attempt(f"remove-{name}", ["rm", "-rf", path])
    for name, path in reversed(owned_empty_directories):
        attempt(f"rmdir-{name}", ["rmdir", path])
    for record in reversed(owned_records):
        kind = "user" if record.startswith("/Users/") else "group"
        attempt(f"delete-{kind}", ["dscl", ".", "-delete", record])

    if bootstrapped:
        try:
            result = invoke(["launchctl", "list"], check=False)
            if result.returncode != 0:
                raise AssertionError("launchd cleanup inventory query failed")
            if LABEL in parse_launchctl_labels(result.stdout):
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
    owned_records, invoke=sudo,
):
    cleanup_errors = cleanup_owned_resources(
        bootstrapped, owned_paths, owned_empty_directories, owned_records, invoke
    )
    if lab_error is not None:
        if cleanup_errors:
            raise lab_error from OwnedCleanupError(cleanup_errors)
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


def require_agent_discovery(binary, profile, private, endpoint):
    result = sudo(
        [binary, "agent-discover", "--profile", profile, "--private", private,
         "--socket", endpoint],
        user=AGENT, check=False,
    )
    assert result.returncode == 0 and result.stdout.startswith(b"PASS delegated-discovery") \
        and result.stderr == b"", (
            "agent discovery failed after TUI lock", result.returncode,
            result.stdout[:1024], result.stderr[:1024],
        )


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
        session.close()
        raise


def tui_search(session, value):
    start = session.mark()
    session.send_key("/")
    session.wait_text("Search (engine-decrypted):", since=start)
    search_start = session.mark()
    session.send_text(value, enter=True)
    return session.wait_text("Search returned 1 active items", since=search_start)


def select_tui_password_for_copy(session):
    start = session.mark()
    session.send_key("c")
    session.wait_text("Fields (explicit selection; values hidden)", since=start)
    start = session.mark()
    session.send_text("j" * 14)
    session.wait_selected("auth[0].password", since=start)
    copy_start = session.mark()
    session.send_key("enter")
    return copy_start


def run_tui_core_lab(
    binary, profile, private, endpoint, agent_profile, agent_private, agent_endpoint,
    *, diagnostic=False,
):
    seed_tui_content(binary, profile, private, endpoint)
    first = start_macos_tui(
        binary, profile, private, endpoint, idle=30, reveal=1, copy=5,
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
        tui_search(first, "Password")
        copied_start = select_tui_password_for_copy(first)
        first.wait_text("Copied explicitly", since=copied_start)
        assert_human_pasteboard_canary(TUI_PASSWORD_RECORD, diagnostic=diagnostic)
        assert_agent_cannot_read_pasteboard(TUI_PASSWORD_RECORD, diagnostic=diagnostic)
        write_appkit_pasteboard(TUI_EXTERNAL_REPLACEMENT)
        expiry_start = first.mark()
        first.wait_text("Clipboard custody expired", since=expiry_start)
        assert read_appkit_pasteboard() == TUI_EXTERNAL_REPLACEMENT

        first.send_key("l")
        assert first.wait_exit(timeout=8) == 0
        assert b"\x1b[6n" not in bytes(first.output), (
            "TUI PTY exit must not require a terminal-emulator cursor response"
        )
    finally:
        first.close()
    assert TUI_PASSWORD_RECORD not in bytes(first.output)
    assert b"\x1b]52;" not in bytes(first.output)
    require_agent_discovery(binary, agent_profile, agent_private, agent_endpoint)

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
        second.close()
    assert PASSWORD not in bytes(second.output)
    assert TUI_PASSWORD_RECORD not in bytes(second.output)
    assert b"\x1b]52;" not in bytes(second.output)
    require_agent_discovery(binary, agent_profile, agent_private, agent_endpoint)


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
    if diagnostic:
        arguments.pop(0)
    assert len(arguments) == 4 and not any(
        value.startswith("--") for value in arguments
    ), "usage: macos_lab.py [--diagnostic] CUSTODY CLI PLIST SODIUM_CONFIG"
    return diagnostic, tuple(pathlib.Path(value).resolve() for value in arguments)


def main():
    assert sys.platform == "darwin" and os.geteuid() != 0
    assert os.environ.get("PM_MACOS_EPHEMERAL_CI") == "1"
    assert DIAGNOSTIC_ENV not in os.environ, (
        "ticket 26 diagnostic activation must be injected only into owned fixture processes"
    )
    assert_screen_observer_regression()
    diagnostic, paths = parse_lab_arguments(sys.argv[1:])
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
        bootstrapped, owned_paths, owned_empty_directories, owned_records
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
