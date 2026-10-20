"""Private GUI gates. No compositor/clipboard/contact is performed here.

A library enum is not proof of Hyprland's mandatory headless launch semantics.
No successful GUI receipt can currently be emitted by this method.
"""
import os
from pathlib import Path
import stat
from core import digest, require, GateError

PREREQUISITE = ('BLOCKED: installed Hyprland documentation does not establish mandatory '
                'headless backend selection, renderer/device isolation and no DRM/input/DBus fallback; '
                'a documented safe launch plus owned namespace/device-mask proof is required')
GUI_CASES = frozenset({'lab-tui-access', 'lab-tui-content', 'lab-tui-operations',
                      'publication-backup', 'publication-plaintext', 'publication-attachment'})
FORBIDDEN = frozenset({'WAYLAND_DISPLAY', 'DISPLAY', 'XDG_RUNTIME_DIR',
                      'HYPRLAND_INSTANCE_SIGNATURE', 'DBUS_SESSION_BUS_ADDRESS', 'XAUTHORITY'})

def endpoint_identity(runtime, endpoint, pid, expected_command_digest):
    """Read-only identity prerequisite, NOT GUI proof. Reject crossed paths before contact.

    Socket filesystem inode and kernel socket inode differ; bind via /proc/net/unix
    path -> kernel inode -> the specified process's fd, not by comparing those inodes.
    This does not connect any socket, including the negative foreign case.
    """
    runtime, endpoint = Path(runtime), Path(endpoint)
    require(runtime.is_absolute() and runtime.resolve(strict=True) == runtime, 'runtime symlink/path')
    require(runtime.stat().st_uid == os.getuid() and stat.S_IMODE(runtime.stat().st_mode) == 0o700,
            'private runtime owner/mode')
    require(endpoint.parent == runtime and endpoint.name.startswith('wayland-') and not endpoint.is_symlink(),
            'crossed/foreign endpoint')
    node = endpoint.lstat()
    require(stat.S_ISSOCK(node.st_mode) and node.st_uid == os.getuid(), 'socket owner/type')
    proc = Path('/proc') / str(pid)
    require(type(pid) is int and pid > 0 and proc.stat().st_uid == os.getuid(), 'process owner')
    command = (proc / 'cmdline').read_bytes()
    require(digest(command) == expected_command_digest, 'process command differs')
    start = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    candidates = [line.split()[6] for line in Path('/proc/net/unix').read_text().splitlines()[1:]
                  if len(line.split()) == 8 and line.split()[7] == str(endpoint)]
    require(len(candidates) == 1, 'socket path/kernel inode ambiguity')
    descriptors = {os.readlink(p) for p in (proc / 'fd').iterdir() if p.exists()}
    require('socket:[' + candidates[0] + ']' in descriptors, 'endpoint not owned by expected process')
    require(endpoint.lstat() == node and (proc / 'cmdline').read_bytes() == command, 'identity changed during inspection')
    return dict(pid=pid, uid=os.getuid(), command_digest=digest(command), start=start,
                endpoint=str(endpoint), device=node.st_dev, inode=node.st_ino, kernel_inode=candidates[0])

def require_private_gui():
    raise GateError(PREREQUISITE)

def blocked_case(name):
    return name in GUI_CASES
