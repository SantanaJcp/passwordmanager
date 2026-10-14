#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Worker transport regression; synthetic installed adapter, real UID/RPK/SQLite.

Run under one outer Cargo flock and the subordinate user/mount/PID namespace.
The full passkey/token-exchange labs remain independent unchanged acceptance.
"""
import json
import inspect
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time

import chef_installed_fixture as installed
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "pm-web-auth/tests"))
import web_auth_lab as common
import token_exchange_lab as exchange


def adapter(endpoint, events, release):
    def exact(connection, size):
        value = b""
        while len(value) < size:
            block = connection.recv(size - len(value))
            assert block, "incomplete provider frame"
            value += block
        return value
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(endpoint); os.chmod(endpoint, 0o666); listener.listen()
    while True:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(20)
            request = exact(connection, int.from_bytes(exact(connection, 4), "big"))
            with open(events, "a") as out:
                out.write(json.dumps({"opcode": request[0], "attempt": request[1:17].hex()}) + "\n")
            if request[0] != 2:
                deadline = time.monotonic() + 20
                while not Path(release).exists():
                    assert time.monotonic() < deadline, "fixture release missing"
                    time.sleep(.01)
            # Unknown for reconciliation, late success for the first cancelled use.
            response = b"\x03\0\0\0\0" if request[0] == 2 or len(Path(events).read_text().splitlines()) > 1 else b"\0\0\0\0\x16late synthetic success"
            connection.sendall(len(response).to_bytes(4, "big") + response)


def wait_until(predicate, label):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.02)
    raise AssertionError(label)


def main():
    custody_source, cli_source = map(lambda p: Path(p).resolve(strict=True), sys.argv[1:])
    root = installed.initialize(custody_source)
    processes = []
    daemon = None
    try:
        custody, cli = root / "pm-custody", root / "pm"
        for source, destination in ((custody_source, custody), (cli_source, cli)):
            shutil.copy2(source, destination); destination.chmod(0o755)
        directories = {}
        for name, uid, mode in (("state",1,0o700),("run",1,0o755),("human",2,0o755),
                                ("agent",3,0o755),("agent-b",4,0o755),("provider",5,0o711),("profiles",0,0o755)):
            path = root / name; path.mkdir(); os.chown(path,uid,uid); path.chmod(mode); directories[name] = path
        state, runtime, human, agent, agent_b, provider, profiles = [directories[k] for k in ("state","run","human","agent","agent-b","provider","profiles")]
        keys = []
        for uid, home in ((1,state),(2,human),(3,agent),(4,agent_b)):
            private, public = home / "private", home / "public"
            common.run_uid(uid,[custody,"keygen","--private",private,"--public",public]); keys.append((private,public))
        (sk,sp),(hk,hp),(ak,ap),(_,bp) = keys
        bootstrap, vault = state / "bootstrap", state / "vault.sqlite3"
        common.run_uid(1,[custody,"provision-bootstrap","--path",bootstrap,"--server-private",sk,"--server-public",sp,"--agent-public",ap,"--agent-uid","3","--human-public",hp,"--human-uid","2"])
        for role in ("agent","human"):
            subprocess.run([custody,"provision-profile","--path",profiles/role,"--server-public",sp,"--server-uid","1","--role",role],check=True,capture_output=True)
        common.create_vault(cli,vault)
        command = [custody,"serve-vault","--bootstrap",bootstrap,"--agent-socket",runtime/"agent.sock","--human-socket",runtime/"human.sock","--vault",vault,"--device",exchange.DEVICE]
        def launch():
            cmd, preexec = installed.prepare(1,command,common.identity(1))
            process = subprocess.Popen(cmd,preexec_fn=preexec,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            processes.append(process)
            for path in (runtime/"agent.sock",runtime/"human.sock"): common.wait_path(process,path)
            return process
        def stop_daemon(process):
            installed.stop_and_unlink(process,[runtime/"agent.sock",runtime/"human.sock"],timeout=8)
            processes.remove(process)
        daemon = launch()
        common.human(custody,hk,profiles/"human",runtime/"human.sock","setup",ap.read_bytes(),bp.read_bytes())
        common.human(custody,hk,profiles/"human",runtime/"human.sock","add-keycloak-exchange",b"synthetic-boundary-subject-token",exchange.CLIENT_SECRET.encode())
        stop_daemon(daemon); daemon = None
        installed.migrate(custody,bootstrap,vault,exchange.DEVICE,(bp,4))
        endpoint, events, release = provider/"adapter.sock", provider/"events.jsonl", provider/"release"
        adapter_code = "import json, socket, time, sys, os\nfrom pathlib import Path\n" + inspect.getsource(adapter) + "\nadapter(*sys.argv[1:])\n"
        server = common.start_uid(5,[sys.executable,"-c",adapter_code,endpoint,events,release]); processes.append(server)
        common.wait_path(server,endpoint)
        installed.run(1,[custody,"provision-adapters","--bootstrap",bootstrap,"--vault",vault,"--device",exchange.DEVICE,"--integration","keycloak-token-exchange","--profile","keycloak-exchange-lab","--method","token_exchange","--endpoint",endpoint,"--adapter-uid","5"])
        daemon = launch()
        env = {"PM_PROFILE":str(profiles/"agent"),"PM_PRIVATE":str(ak),"PM_SOCKET":str(runtime/"agent.sock")}
        def rpc(args, check=True): return common.cli(3,cli,env,["--json",*args],check=check)
        rows = json.loads(rpc(["credentials","list"]).stdout)["result"]["credentials"]
        item = next(r["id"] for r in rows if r["destination"] == "keycloak-exchange-lab")
        _, started = exchange.start_attempt(cli,env,item,"a")
        assert started.returncode == 0
        attempt = json.loads(started.stdout)["result"]["attempt_id"]
        wait_until(events.exists,"provider emission missing")
        # Independent SQLite writer must be admitted while only response is held.
        connection = sqlite3.connect(vault,timeout=0)
        try:
            connection.execute("BEGIN IMMEDIATE"); connection.rollback()
        except sqlite3.OperationalError as error:
            raise AssertionError("response wait holds SQLite writer: " + str(error)) from error
        finally: connection.close()
        assert json.loads(rpc(["auth","status","--attempt",attempt]).stdout)["result"]["state"] == "RUNNING"
        assert json.loads(rpc(["credentials","list"]).stdout)["result"]["credentials"]
        cancelled = json.loads(rpc(["auth","cancel","--attempt",attempt]).stdout)["result"]
        assert cancelled["state"] == "CANCELLED" and cancelled["result"] is None
        release.touch(); os.chown(release,5,5)
        # Follow it with another request: observed emission proves the worker has
        # consumed the late response and attempted settlement of the cancelled use.
        _, second = exchange.start_attempt(cli,env,item,"b"); assert second.returncode == 0
        second_id = json.loads(second.stdout)["result"]["attempt_id"]
        wait_until(lambda: len(events.read_text().splitlines()) >= 2,"worker never returned from response wait")
        assert json.loads(rpc(["auth","status","--attempt",attempt]).stdout)["result"]["state"] == "CANCELLED"
        stop_daemon(daemon); daemon = None
        daemon = launch()
        assert json.loads(rpc(["auth","status","--attempt",attempt]).stdout)["result"]["state"] == "CANCELLED"
        wait_until(lambda: any(row["opcode"] == 2 and row["attempt"] == second_id for row in map(json.loads,events.read_text().splitlines())),"unknown result was not reconciled after restart")
        assert sum(row["opcode"] == 4 and row["attempt"] == second_id for row in map(json.loads,events.read_text().splitlines())) == 1
        assert sum(row["opcode"] == 4 and row["attempt"] == attempt for row in map(json.loads,events.read_text().splitlines())) == 1
        common.human(custody,hk,profiles/"human",runtime/"human.sock","suspend")
        before = events.read_bytes()
        _, denied = exchange.start_attempt(cli,env,item,"c")
        assert denied.returncode != 0 and b"ACCESS_SUSPENDED" in denied.stdout
        assert events.read_bytes() == before
        print("PASS provider-boundary SQLite-writer=available status+discover=live cancel=durable late-success=CANCELLED restart=no-second-login suspend=zero-calls",flush=True)
    finally:
        errors = []
        for process in reversed(processes):
            try:
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=8)
                assert process.returncode == -signal.SIGTERM and out == err == b"", (process.returncode,out,err)
            except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("owned boundary fixture cleanup",errors)


if __name__ == "__main__":
    if sys.argv[1] == "adapter": adapter(*sys.argv[2:])
    else: main()
