# SPDX-License-Identifier: AGPL-3.0-only
"""Extend the existing controlled-provider lab with an in-flight barrier."""
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import sqlite3
import sys
import time

from g7_canary_channels import Channels
from g7_fault_matrix import ProductRed, witness
from linux_lab import CUSTODIAN, HUMAN, AGENT, wait_for_sockets, wire_fields
from storage_fault_lab import pause_owned

SECRET = b"ticket07-secret-canary"
AUTHORITY = ("vault_metadata", "encrypted_objects", "authority_events", "outbox", "human_receipts", "agent_authorizations", "delegated_state", "credential_authorizations", "vault_items", "revision_parts", "audit_keys")


def query(vault, sql):
    database = sqlite3.connect(vault.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return database.execute(sql).fetchall()
    finally:
        database.close()


def calls(journal, attempt):
    value = json.loads(journal.read_bytes())
    assert set(value) == {attempt}, "unexpected controlled provider attempt"
    assert value[attempt]["mode"] == "ambiguous"
    return value[attempt]["calls"]


def inflight(f, target, *, live=False, failure="EIO"):
    channels = Channels(f, (SECRET, f["password"]))
    defects = []
    retained = []
    try:
        # Keep the existing provider protocol/counter. The only extension is a
        # fixture barrier after its one recorded send and before the response.
        for name, uid, mode in (("provider", 5, 0o755), ("agent-b", 4, 0o755)):
            folder = f["root"] / name
            folder.mkdir(mode=mode)
            os.chown(folder, uid, uid)
            channels.directories.add(folder)
        phome, bhome = f["root"] / "provider", f["root"] / "agent-b"
        private, public = bhome / "agent.key", bhome / "agent.pub"
        for path in (private, public):
            channels.register(path, "agent-resources")
        keygen = channels.spawn(4, [f["binary"], "keygen", "--private", private, "--public", public], "second-key")
        assert channels.result(keygen).returncode == 0, "second RPK setup"
        profile = f["profiles"] / "agent.profile"
        channels.register(profile, "agent-resources")
        provision = channels.spawn(0, [f["binary"], "provision-profile", "--path", profile, "--server-public", f["server_pub"], "--server-uid", str(CUSTODIAN), "--role", "agent"], "agent-profile")
        assert channels.result(provision).returncode == 0
        script = phome / "attempts_lab.py"
        for name in ("attempts_lab.py", "linux_lab.py"):
            path = phome / name
            shutil.copyfile(pathlib.Path(__file__).with_name(name), path)
            path.chmod(0o555)
            channels.assets[path] = hashlib.sha256(path.read_bytes()).digest()
        gate, journal, sock = phome / "barrier", phome / "journal.json", phome / "provider.sock"
        for path in (journal, phome / "journal.json.tmp", pathlib.Path(str(gate) + ".sent"), pathlib.Path(str(gate) + ".release")):
            channels.register(path, "logs")
        channels.sockets.add(sock)
        provider = channels.spawn(5, [sys.executable, script, "provider", sock, journal, str(phome / "resolve-"), gate], "provider", environment={"PYTHONDONTWRITEBYTECODE": "1"})
        wait_for_sockets(provider, [sock])
        serve = list(f["serve"])
        serve[1] = "serve-attempt-lab"
        serve += ["--provider-socket", sock, "--provider-uid", "5"]
        arm = f["state"] / "owned-sync.arm"
        if target in ("result-sync", "result-control"):
            arm.write_text("0 EIO 0")
            arm.chmod(0o444)
            channels.register(arm, "logs")
        environment = dict(f["environment"], PM28_SYNC_FAIL="0", PM28_SYNC_ARM=str(arm)) if target in ("result-sync", "result-control") else {}
        daemon = channels.spawn(CUSTODIAN, serve, "custodian", environment=environment)
        f["pid_path"].write_text(str(daemon.pid))
        f["pid_path"].chmod(0o444)
        wait_for_sockets(daemon, (f["agent_socket"], f["human_socket"]))
        setup = channels.spawn(HUMAN, [f["binary"], "human-authorization", "--profile", f["human_profile"], "--private", f["human_key"], "--socket", f["human_socket"], "--action", "setup"], "setup",
                               input=wire_fields([f["password"], f["agent_pub"].read_bytes(), public.read_bytes()]))
        assert channels.result(setup).returncode == 0, "controlled-provider setup failed"
        discovery = channels.spawn(AGENT, [f["binary"], "agent-discover", "--profile", profile, "--private", f["agent_key"], "--socket", f["agent_socket"]], "discovery")
        discovered = channels.result(discovery)
        assert discovered.returncode == 0
        item = re.search(rb"set=([0-9a-f]{32}):", discovered.stdout)
        assert item, "enabled credential control"
        start = channels.spawn(AGENT, [f["binary"], "agent-attempt", "--profile", profile, "--private", f["agent_key"], "--socket", f["agent_socket"], "--action", "start", "--item", item[1].decode("ascii"), "--issued-at", str(int(time.time() * 1_000_000)), "--nonce", "28" * 16, "--context", "ambiguous"], "start")
        created = channels.result(start)
        assert created.returncode == 0
        match = re.search(rb"id=([0-9a-f]{32}).*state=CREATED", created.stdout)
        assert match, "intent admission control"
        attempt = match[1].decode("ascii")
        deadline = time.monotonic() + 8
        sent = pathlib.Path(str(gate) + ".sent")
        while not sent.exists():
            assert provider.poll() is None and daemon.poll() is None and time.monotonic() < deadline, "provider in-flight barrier setup"
            time.sleep(0.002)
        assert sent.read_text() == attempt and calls(journal, attempt) == 1
        pause_owned(daemon)
        pause_owned(provider)
        before = witness(f, channels)
        running = query(f["vault"], "SELECT state,provider_sent FROM authentication_attempts")
        assert running == [("running", 1)], "durable intent before external effect control"
        channels.scan("inflight-active-before-loss", (daemon, provider))
        originals = {path: path.read_bytes() for path in (f["bootstrap"], f["server_key"], pathlib.Path(str(f["vault"]) + ".audit-custody"))}
        print(f"PM28_INFLIGHT_CONTROL target={target} intent=running provider-sent=1 provider-calls=1", flush=True)
        if target in ("result-sync", "result-control"):
            from g7_result_sync import result_sync
            return result_sync(f, channels, daemon, provider, gate, journal, attempt, before, arm, target == "result-sync", failure)
        paths = []
        if target in ("bootstrap", "audit"):
            paths = [f["bootstrap"] if target == "bootstrap" else pathlib.Path(str(f["vault"]) + ".audit-custody")]
        elif target == "vault":
            paths = [pathlib.Path(str(f["vault"]) + suffix) for suffix in ("", "-wal", "-shm") if pathlib.Path(str(f["vault"]) + suffix).exists()]
        else:
            assert target == "crash"
        for path in paths:
            was_required = path in channels.required
            saved = path.with_name("owned-retained-" + path.name)
            channels.register(saved, channels.files[path])
            path.rename(saved)
            channels.required.discard(path)
            channels.required.add(saved)
            retained.append((path, saved, was_required))
        channels.scan("inflight-active-after-loss", (daemon, provider))
        if live:
            # Check the original live process, before using the crash boundary.
            # If admitted, explicitly cancel the extra synthetic attempt while
            # the single provider worker is still held on the first call.
            daemon.send_signal(signal.SIGCONT)
            new = channels.spawn(AGENT, [f["binary"], "agent-attempt", "--profile", profile, "--private", f["agent_key"], "--socket", f["agent_socket"], "--action", "start", "--item", item[1].decode("ascii"), "--issued-at", str(int(time.time() * 1_000_000)), "--nonce", "29" * 16, "--context", "ambiguous"], "live-loss-start")
            response = channels.result(new)
            closed = response.returncode == 4 and response.stderr == b"CUSTODY_UNAVAILABLE\n" and response.stdout in (b"", b"DENIED code=1\n")
            accepted = re.search(rb"id=([0-9a-f]{32}).*state=CREATED", response.stdout) if response.returncode == 0 else None
            if accepted:
                cancellation = channels.spawn(AGENT, [f["binary"], "agent-attempt", "--profile", profile, "--private", f["agent_key"], "--socket", f["agent_socket"], "--action", "cancel", "--attempt", accepted[1].decode("ascii")], "live-loss-cancel")
                cancelled = channels.result(cancellation)
                assert cancelled.returncode == 0 and b"state=CANCELLED" in cancelled.stdout, "fixture could not cancel the additional admitted attempt"
            assert calls(journal, attempt) == 1, "extra login before controlled release"
            print(f"PM28_LIVE_LOSS target={target} admission-closed={int(closed)} accepted={int(accepted is not None)} rc={response.returncode} extra-attempt-cancelled={int(accepted is not None)} provider-calls=1", flush=True)
            if not closed:
                defects.append("live custody withdrawal accepted a new authentication")
            pause_owned(daemon)
            channels.scan("inflight-live-admission-observed", (daemon, provider))
        # Abort really exercises crash policy; WCOREDUMP must remain false.
        crash_signal = signal.SIGABRT if target == "crash" else signal.SIGKILL
        daemon.send_signal(crash_signal)
        if crash_signal == signal.SIGABRT:
            daemon.send_signal(signal.SIGCONT)
        waited, status = os.waitpid(daemon.pid, 0)
        assert waited == daemon.pid and os.WIFSIGNALED(status) and os.WTERMSIG(status) == crash_signal
        daemon.returncode = -crash_signal
        assert not os.WCOREDUMP(status), "product crash produced a core artifact"
        print(f"PM28_CRASH signal={crash_signal} core-dumped=0 collector-invoked=0", flush=True)
        channels.scan("inflight-historical-after-crash", (provider,))
        for path in (f["agent_socket"], f["human_socket"]):
            assert path.is_socket()
            path.unlink()
        if paths:
            lost = channels.spawn(CUSTODIAN, serve, "lost-custody")
            deadline = time.monotonic() + 8
            while lost.poll() is None and not (f["agent_socket"].exists() and f["human_socket"].exists()):
                assert time.monotonic() < deadline, "lost custody readiness observation"
                time.sleep(0.002)
            closed = lost.poll() is not None
            if closed:
                rejected = channels.result(lost)
                closed = rejected.returncode == 4 and rejected.stdout == b"" and rejected.stderr == b"CUSTODY_UNAVAILABLE\n"
            else:
                pause_owned(lost)
                probe = channels.spawn(AGENT, [f["binary"], "agent-attempt", "--profile", profile, "--private", f["agent_key"], "--socket", f["agent_socket"], "--action", "get", "--attempt", attempt], "lost-get")
                lost.send_signal(signal.SIGCONT)
                rejected = channels.result(probe)
                closed = rejected.returncode == 4 and rejected.stderr == b"CUSTODY_UNAVAILABLE\n"
                pause_owned(lost)
            replacement = any(path.exists() for path, _, _ in retained)
            print(f"PM28_INFLIGHT_LOSS target={target} closed={int(closed)} replacement={int(replacement)} provider-calls={calls(journal, attempt)}", flush=True)
            if not closed:
                defects.append("lost custody did not close admission/status")
            if replacement:
                defects.append("lost custody was replaced automatically")
            channels.scan("inflight-historical-rejected", (provider, lost) if lost.poll() is None else (provider,))
            if lost.poll() is None:
                lost.send_signal(signal.SIGCONT)
                lost.send_signal(signal.SIGTERM)
                assert lost.wait(timeout=8) == -signal.SIGTERM
            for path, saved, was_required in retained:
                if path.exists():
                    path.unlink()
                saved.rename(path)
                channels.required.remove(saved)
                if was_required:
                    channels.required.add(path)
            retained.clear()
            for path in (f["agent_socket"], f["human_socket"]):
                if path.exists():
                    assert path.is_socket()
                    path.unlink()
        assert all(path.read_bytes() == value for path, value in originals.items()), "original custody keys changed"
        pathlib.Path(str(gate) + ".release").write_bytes(b"release")
        provider.send_signal(signal.SIGCONT)
        restarted = channels.spawn(CUSTODIAN, serve, "restored-custody")
        wait_for_sockets(restarted, (f["agent_socket"], f["human_socket"]))
        deadline = time.monotonic() + 15
        number = 0
        while True:
            get = channels.spawn(AGENT, [f["binary"], "agent-attempt", "--profile", profile, "--private", f["agent_key"], "--socket", f["agent_socket"], "--action", "get", "--attempt", attempt], "restored-get-" + str(number))
            result = channels.result(get)
            assert result.returncode == 0 and result.stderr == b"", "same-ID status unavailable after exact restoration"
            state = re.search(rb"state=([A-Z_]+) reason=([^ ]*) result=(.*)", result.stdout)
            assert state and state[3] == b"", "intention without result exposed success/payload"
            if state[1] == b"INDETERMINATE":
                break
            assert (state[1], state[2]) == (b"RUNNING", b"INDETERMINATE") and time.monotonic() < deadline, "unexpected restored attempt state"
            number += 1
        pause_owned(restarted)
        pause_owned(provider)
        after = witness(f, channels)
        assert all(after[table] == before[table] for table in AUTHORITY), "authority/outbox/receipts changed across in-flight loss"
        assert calls(journal, attempt) == 1, "blind duplicate login after in-flight loss"
        channels.scan("inflight-historical-restored", (restarted, provider))
        print(f"PM28_INFLIGHT_DONE target={target} state=INDETERMINATE provider-calls=1 authority-exact=1 original-keys=1", flush=True)
        if defects:
            raise ProductRed("; ".join(defects))
        print(f"PASS inflight target={target} positive-control=1", flush=True)
    finally:
        channels.close()
