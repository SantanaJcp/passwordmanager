#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""W4 ordinary-daemon concurrency through real UID/RPK/TUI connections."""

import os
import pathlib
import select
import sqlite3
import hashlib
import time
import shutil
import subprocess
import sys
import tempfile

os.environ["PM_TMUX_SERVER"] = f"pmw4-concurrency-{os.getpid()}"

from linux_lab import as_uid, create_vault, expect_unavailable, start_as, wait_for_sockets
from tui_content_lab import screen, send, start_tui, wait_text
from tui_access_lab import (
    AGENT_A, AGENT_B, AGENT_C, CUSTODIAN, HUMAN, LAB_PARENT, LAB_PREFIX,
    PROVIDER, authorization, close_tui, discover, cleanup_owned_root, stop_owned_tmux, provision,
)

DEVICE = "44444444444444444444444444444444"


def main():
    assert os.geteuid() == 0 and len(sys.argv) in (3, 4)
    source_binary, source_cli = (pathlib.Path(value).resolve() for value in sys.argv[1:3])
    root = pathlib.Path(tempfile.mkdtemp(prefix=LAB_PREFIX, dir=LAB_PARENT))
    daemon = None
    tui_started = False
    try:
        root.chmod(0o711)
        binary, cli = root / "pm-custody", root / "pm"
        shutil.copyfile(source_binary, binary); binary.chmod(0o755)
        shutil.copyfile(source_cli, cli); cli.chmod(0o755)
        directories = [("state", CUSTODIAN, 0o700), ("run", CUSTODIAN, 0o755),
                       ("human", HUMAN, 0o755), ("profiles", HUMAN, 0o755),
                       ("provider", PROVIDER, 0o755),
                       *[(f"agent-{uid}", uid, 0o755) for uid in (AGENT_A, AGENT_B, AGENT_C)]]
        for name, uid, mode_bits in directories:
            path = root / name
            path.mkdir(); os.chown(path, uid, uid); path.chmod(mode_bits)
        state, runtime = root / "state", root / "run"
        server_key, server_public = state / "server.key", state / "server.pub"
        human_key, human_public = root / "human/human.key", root / "human/human.pub"
        a_key, a_public = root / "agent-3/agent.key", root / "agent-3/agent.pub"
        b_key, b_public = root / "agent-4/agent.key", root / "agent-4/agent.pub"
        for uid, private, public in [(CUSTODIAN, server_key, server_public),
                (HUMAN, human_key, human_public), (AGENT_A, a_key, a_public),
                (AGENT_B, b_key, b_public)]:
            as_uid(uid, [binary, "keygen", "--private", private, "--public", public])
        bootstrap = state / "bootstrap"
        provision(binary, bootstrap, server_key, server_public, a_public, AGENT_A, human_public)
        agent_profile, human_profile = root / "profiles/agent.profile", root / "profiles/human.profile"
        for role, profile in (("agent", agent_profile), ("human", human_profile)):
            as_uid(HUMAN, [binary, "provision-profile", "--path", profile,
                          "--server-public", server_public, "--server-uid", str(CUSTODIAN),
                          "--role", role])
        vault = state / "vault.sqlite3"
        password = create_vault(cli, vault)
        daemon = start_as(CUSTODIAN, [binary, "serve-vault", "--bootstrap", bootstrap,
            "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
            "--vault", vault, "--device", DEVICE])
        wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
        authorization(binary, human_key, human_profile, runtime / "human.sock", password,
                      "setup", a_public.read_bytes(), b_public.read_bytes())
        # Installed fixture uses the versioned binary schema, independently of
        # the provisioning command. Existing daemon must consume it, not learn peers.
        daemon.terminate(); daemon.communicate(timeout=5); daemon = None
        with sqlite3.connect(vault) as db:
            vault_id = db.execute("select vault_id from vault_metadata").fetchone()[0]
        registry = pathlib.Path(str(vault) + ".agent-registry")
        registry.write_bytes(b"PMAR1" + vault_id + bytes.fromhex(DEVICE)
            + server_public.read_bytes() + (2).to_bytes(2, "big")
            + a_public.read_bytes() + AGENT_A.to_bytes(4, "big")
            + b_public.read_bytes() + AGENT_B.to_bytes(4, "big"))
        os.chown(registry, CUSTODIAN, CUSTODIAN); registry.chmod(0o400)
        daemon = start_as(CUSTODIAN, [binary, "serve-vault", "--bootstrap", bootstrap,
            "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
            "--vault", vault, "--device", DEVICE])
        wait_for_sockets(daemon, [runtime / "agent.sock", runtime / "human.sock"])
        baseline = discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock")
        if os.environ.get("CHEF_ROOT_NO_TUI")!="1":
            start_tui(root, binary, human_profile, human_key, runtime, password)
            tui_started = True
        else: print("NOT_RUN active-TUI owned-root-device-creation=EPERM",flush=True)
        second = discover(binary, AGENT_B, b_key, agent_profile, runtime / "agent.sock")
        assert second == baseline and daemon.poll() is None
        if tui_started: assert "Unlocked:" in screen(root)
        for source, uid, directory in ((b_key, AGENT_A, "agent-3"), (a_key, AGENT_B, "agent-4")):
            copied = root / directory / "cross.key"
            shutil.copyfile(source, copied); os.chown(copied, uid, uid); copied.chmod(0o400)
            denied = as_uid(uid, [binary, "agent-discover", "--profile", agent_profile,
                "--private", copied, "--socket", runtime / "agent.sock"], check=False)
            expect_unavailable(denied)
        assert discover(binary, AGENT_A, a_key, agent_profile, runtime / "agent.sock") == baseline
        if tui_started: send(root, "a"); wait_text(root, "Delegated authority"); close_tui(root)
        unknown_key=root/"agent-3/unknown.key";unknown_public=root/"agent-3/unknown.pub"
        as_uid(AGENT_A,[binary,"keygen","--private",unknown_key,"--public",unknown_public])
        discover(binary,AGENT_A,unknown_key,agent_profile,runtime/"agent.sock",allowed=False)
        role_denied=as_uid(AGENT_B,[binary,"probe","--profile",human_profile,"--private",b_key,"--socket",runtime/"human.sock"],check=False)
        expect_unavailable(role_denied)
        print("OBSERVED unknown-RPK known-UID=rejected native-role-separation=preserved",flush=True)
        print("OBSERVED A+B same-pid tui="+("open" if tui_started else "NOT_RUN")+" crossed-pairs=denied", flush=True)
        if "CHEF_RUNTIME_ROOT" in os.environ:
            owned_root=pathlib.Path(os.environ["CHEF_RUNTIME_ROOT"])
            assert (owned_root/"chef-owned-root.marker").read_text()=="synthetic private root filesystem\n"
            daemon.terminate();daemon.communicate(timeout=5);daemon=None
            for endpoint in (runtime/"agent.sock",runtime/"human.sock"):endpoint.unlink()
            os.chmod(owned_root/"tmp",0o755)
            os.chown(owned_root,AGENT_A,AGENT_A)
            unsafe=None
            try:
                unsafe=start_as(CUSTODIAN,[binary,"serve-vault","--bootstrap",bootstrap,
                    "--agent-socket",runtime/"agent.sock","--human-socket",runtime/"human.sock",
                    "--vault",vault,"--device",DEVICE])
                try:
                    out,err=unsafe.communicate(timeout=10)
                    assert unsafe.returncode==4 and out==b"" and err==b"CUSTODY_UNAVAILABLE\n",(unsafe.returncode,out,err)
                except subprocess.TimeoutExpired:
                    discover(binary,AGENT_B,b_key,agent_profile,runtime/"agent.sock")
                    raise AssertionError("agent-owned filesystem root admitted a real registered peer")
            finally:
                if unsafe is not None and unsafe.poll() is None:unsafe.terminate();unsafe.communicate(timeout=5)
                os.chown(owned_root,0,0)
                os.chmod(owned_root/"tmp",0o1777)
            print("OBSERVED agent-owned filesystem root=rejected",flush=True)
            daemon=start_as(CUSTODIAN,[binary,"serve-vault","--bootstrap",bootstrap,
                "--agent-socket",runtime/"agent.sock","--human-socket",runtime/"human.sock",
                "--vault",vault,"--device",DEVICE])
            wait_for_sockets(daemon,[runtime/"agent.sock",runtime/"human.sock"])
        held = start_as(AGENT_A, [sys.executable,"-c", "import socket,sys; s=[socket.socket(socket.AF_UNIX) for _ in range(4)]; [c.connect(sys.argv[1]) for c in s]; print('READY',flush=True); sys.stdin.buffer.read(1); [c.close() for c in s]", str(runtime/"agent.sock")],stdin=subprocess.PIPE)
        try:
            readable,_,_=select.select([held.stdout],[],[],10)
            assert readable and held.stdout.readline()==b"READY\n"
            assert discover(binary,AGENT_B,b_key,agent_profile,runtime/"agent.sock")==baseline
            print("OBSERVED native-four-A B=admitted independent-principal=1",flush=True)
        finally:
            out,err=held.communicate(b"x",timeout=5)
            assert held.returncode==0 and out==b"" and err==b""
        assert discover(binary,AGENT_B,b_key,agent_profile,runtime/"agent.sock")==baseline

        # Migration is explicit, verifies current authority, and never edits the
        # trusted bootstrap. Failed and repeated installs preserve bytes.
        daemon.terminate(); daemon.communicate(timeout=5); daemon = None
        bootstrap_before = bootstrap.read_bytes()
        expected = registry.read_bytes(); registry.unlink()
        migrate = [binary, "migrate-agent-registry", "--bootstrap", bootstrap,
                   "--vault", vault, "--device", DEVICE]
        bad = as_uid(CUSTODIAN, [*migrate, "--agent-public", b_public, "--agent-uid", str(HUMAN)], check=False)
        expect_unavailable(bad)
        assert not registry.exists() and bootstrap.read_bytes() == bootstrap_before
        as_uid(CUSTODIAN, [*migrate, "--agent-public", b_public, "--agent-uid", str(AGENT_B)])
        assert registry.read_bytes() == expected and bootstrap.read_bytes() == bootstrap_before
        duplicate = as_uid(CUSTODIAN, migrate, check=False)
        assert duplicate.returncode == 4 and duplicate.stderr == b"DESTINATION_EXISTS\n"
        assert registry.read_bytes() == expected
        print("OBSERVED migration explicit continuity=preserved ambiguous+overwrite=denied", flush=True)

        def launch():
            process = start_as(CUSTODIAN, [binary, "serve-vault", "--bootstrap", bootstrap,
                "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
                "--vault", vault, "--device", DEVICE])
            wait_for_sockets(process, [runtime / "agent.sock", runtime / "human.sock"])
            return process
        def install(value=expected, mode=0o400, uid=CUSTODIAN):
            registry.unlink(missing_ok=True); registry.write_bytes(value)
            os.chown(registry,uid,uid); registry.chmod(mode)
        c_key=root/"agent-6/unknown.key";c_public=root/"agent-6/unknown.pub"
        as_uid(AGENT_C,[binary,"keygen","--private",c_key,"--public",c_public])
        extra=expected[:81]+(3).to_bytes(2,"big")+expected[83:]+c_public.read_bytes()+AGENT_C.to_bytes(4,"big")
        install(extra);daemon=launch()
        discover(binary,AGENT_C,c_key,agent_profile,runtime/"agent.sock",allowed=False)
        assert discover(binary,AGENT_B,b_key,agent_profile,runtime/"agent.sock")==baseline
        daemon.terminate();daemon.communicate(timeout=5);daemon=None
        print("OBSERVED registered-native-pair without-human-grant=rejected",flush=True)
        # Every corruption is tested through ordinary startup or real admission.
        for label, value, mode, uid in (
                ("corrupt", b"broken", 0o400, CUSTODIAN),
                ("wrong-vault", expected[:5] + b"\xff"*16 + expected[21:], 0o400, CUSTODIAN),
                ("writable", expected, 0o600, CUSTODIAN),
                ("wrong-owner", expected, 0o400, AGENT_A)):
            install(value,mode,uid)
            rejected = as_uid(CUSTODIAN, [binary,"serve-vault","--bootstrap",bootstrap,
                "--agent-socket",runtime/"agent.sock","--human-socket",runtime/"human.sock",
                "--vault",vault,"--device",DEVICE],check=False)
            expect_unavailable(rejected)
            print("OBSERVED registry startup="+label+" rejected",flush=True)
        install()
        daemon=launch()
        assert discover(binary,AGENT_B,b_key,agent_profile,runtime/"agent.sock") == baseline
        # Equal-content replacement changes inode; matching hash is insufficient.
        before=registry.stat().st_ino
        replacement=state/"replacement"; replacement.write_bytes(expected)
        os.chown(replacement,CUSTODIAN,CUSTODIAN); replacement.chmod(0o400)
        replacement.replace(registry); assert registry.stat().st_ino != before
        discover(binary,AGENT_A,a_key,agent_profile,runtime/"agent.sock",allowed=False)
        daemon.terminate(); daemon.communicate(timeout=5); daemon=None
        install(); daemon=launch(); registry.unlink()
        discover(binary,AGENT_B,b_key,agent_profile,runtime/"agent.sock",allowed=False)
        daemon.terminate(); daemon.communicate(timeout=5); daemon=None
        # Missing at startup preserves only the human management lane, never
        # admits the legacy bootstrap agent as an implicit alternate path.
        daemon=launch()
        discover(binary,AGENT_A,a_key,agent_profile,runtime/"agent.sock",allowed=False)
        daemon.terminate(); daemon.communicate(timeout=5); daemon=None
        install(); daemon=launch(); registry.chmod(0o600)
        discover(binary,AGENT_A,a_key,agent_profile,runtime/"agent.sock",allowed=False)
        daemon.terminate(); daemon.communicate(timeout=5); daemon=None
        install(); daemon=launch()
        open_client = source_binary.parent/"examples/chef_runtime_open_channel"
        local_client=root/"agent-3/open-channel"; shutil.copyfile(open_client,local_client)
        os.chown(local_client,AGENT_A,AGENT_A);local_client.chmod(0o500)
        channel=start_as(AGENT_A,[local_client,agent_profile,a_key,runtime/"agent.sock"],stdin=subprocess.PIPE)
        try:
            ready,_,_=select.select([channel.stdout],[],[],10)
            assert ready and channel.stdout.readline()==b"READY\n"
            authorization(binary,human_key,human_profile,runtime/"human.sock",password,"resume-revoke-a")
            out,err=channel.communicate(b"x",timeout=15)
            assert channel.returncode==0 and out==b"PASS hot-revoke same-native-tls-channel=1\n" and err==b"",(channel.returncode,out,err)
            print(out.decode().strip(),flush=True)
        finally:
            if channel.poll() is None: channel.terminate(); channel.communicate(timeout=5)
        discover(binary,AGENT_A,a_key,agent_profile,runtime/"agent.sock",allowed=False)
        assert discover(binary,AGENT_B,b_key,agent_profile,runtime/"agent.sock") == baseline
        daemon.terminate(); daemon.communicate(timeout=5); daemon=None
        registry.unlink()
        revoked=as_uid(CUSTODIAN,migrate,check=False); expect_unavailable(revoked)
        assert not registry.exists() and bootstrap.read_bytes() == bootstrap_before
        print("OBSERVED registry replacement+removal+mode invalidated revocation=not-bypassed migration-revoked=denied",flush=True)
    finally:
        errors=[]
        if tui_started:
            try: stop_owned_tmux(root)
            except BaseException as error: errors.append(error)
        if daemon is not None and daemon.poll() is None:
            try:
                daemon.terminate(); out,err=daemon.communicate(timeout=5)
                assert daemon.returncode==-15 and out==b"" and err==b"",(daemon.returncode,out,err)
            except BaseException as error: errors.append(error)
        try: cleanup_owned_root(root)
        except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("registry cleanup failed",errors)
    print("PASS runtime-registry daemon=ordinary agents=A+B tui="+("open" if tui_started else "NOT_RUN")+" crossed-pairs=denied cleanup=verified")


if __name__ == "__main__":
    main()
