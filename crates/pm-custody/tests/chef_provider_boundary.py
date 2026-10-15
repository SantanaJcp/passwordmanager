#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Worker transport regression; synthetic installed adapter, real UID/RPK/SQLite.

Run under one outer Cargo flock and the subordinate user/mount/PID namespace.
The full passkey/token-exchange labs remain independent unchanged acceptance.
"""
import json
import inspect
import hashlib
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


def edit_adapter(endpoint, events, marker):
    listener=socket.socket(socket.AF_UNIX);listener.bind(endpoint);os.chmod(endpoint,0o666);listener.listen()
    after=0
    def exact(c,n):
        data=b""
        while len(data)<n:
            block=c.recv(n-len(data))
            if not block: return None
            data+=block
        return data
    while True:
        c,_=listener.accept()
        with c:
            c.settimeout(20);header=exact(c,4)
            if header is None:
                with open(events,"a") as out: out.write(json.dumps({"frame":False})+"\n")
                continue
            request=exact(c,int.from_bytes(header,"big"));assert request
            row={"frame":True,"opcode":request[0],"attempt":request[1:17].hex(),"revision":request[17:33].hex(),"after_edit":Path(marker).exists()}
            if request[0]!=2:
                fields=[];cursor=request[33:]
                while cursor:
                    n=int.from_bytes(cursor[:4],"big");fields.append(cursor[4:4+n]);cursor=cursor[4+n:]
                assert fields[:4]==[b"keycloak-token-exchange",b"token_exchange",b"keycloak-exchange-lab",b"keycloak-exchange-lab"]
                assert len(fields)==7
                row["requester_sha256"]=hashlib.sha256(fields[5]).hexdigest();row["subject_sha256"]=hashlib.sha256(fields[6]).hexdigest()
            if request[0]==2 and row["after_edit"]:after+=1
            with open(events,"a") as out:out.write(json.dumps(row)+"\n")
            # First post-edit query can have been in flight before the human
            # commit. Only a second fresh query may resolve this fixture.
            status=2 if request[0]==2 and after>=2 else 3
            response=bytes([status])+b"\0\0\0\0";c.sendall(len(response).to_bytes(4,"big")+response)


def wait_until(predicate, label):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.02)
    raise AssertionError(label)


def main():
    custody_source, cli_source = map(lambda p: Path(p).resolve(strict=True), sys.argv[1:3])
    case_mode=sys.argv[3] if len(sys.argv)>3 else "boundary"
    helper_source=Path(sys.argv[4]).resolve(strict=True) if case_mode.startswith("edit-") else None
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
        # Public migration must reject a genuine native-bound bootstrap RPK
        # that never received a human grant, not merely a stale TLS generation.
        rogue=root/"rogue";rogue.mkdir();os.chown(rogue,6,6);rogue.chmod(0o755)
        rogue_key,rogue_public=rogue/"private",rogue/"public"
        common.run_uid(6,[custody,"keygen","--private",rogue_key,"--public",rogue_public])
        rogue_bootstrap=state/"rogue-bootstrap"
        common.run_uid(1,[custody,"provision-bootstrap","--path",rogue_bootstrap,"--server-private",sk,"--server-public",sp,"--agent-public",rogue_public,"--agent-uid","6","--human-public",hp,"--human-uid","2"])
        before_bootstrap=rogue_bootstrap.read_bytes()
        rejected=installed.run(1,[custody,"migrate-agent-registry","--bootstrap",rogue_bootstrap,"--vault",vault,"--device",exchange.DEVICE],check=False)
        assert rejected.returncode==4 and rejected.stderr==b"CUSTODY_UNAVAILABLE\n",rejected
        assert rogue_bootstrap.read_bytes()==before_bootstrap and not Path(str(vault)+".agent-registry").exists()
        print("PASS corpus pinned-but-unenrolled RPK migration=denied native-principal=6",flush=True)
        installed.migrate(custody,bootstrap,vault,exchange.DEVICE,(bp,4))
        endpoint, events, release = provider/"adapter.sock", provider/"events.jsonl", provider/"release"
        adapter_function=edit_adapter if case_mode.startswith("edit-") else adapter
        adapter_code = "import json, socket, time, sys, os, hashlib\nfrom pathlib import Path\n" + inspect.getsource(adapter_function) + "\n"+adapter_function.__name__+"(*sys.argv[1:])\n"
        server = common.start_uid(5,[sys.executable,"-c",adapter_code,endpoint,events,release]); processes.append(server)
        common.wait_path(server,endpoint)
        installed.run(1,[custody,"provision-adapters","--bootstrap",bootstrap,"--vault",vault,"--device",exchange.DEVICE,"--integration","keycloak-token-exchange","--profile","keycloak-exchange-lab","--method","token_exchange","--endpoint",endpoint,"--adapter-uid","5"])
        daemon = launch()
        env = {"PM_PROFILE":str(profiles/"agent"),"PM_PRIVATE":str(ak),"PM_SOCKET":str(runtime/"agent.sock")}
        def rpc(args, check=True): return common.cli(3,cli,env,["--json",*args],check=check)
        rows = json.loads(rpc(["credentials","list"]).stdout)["result"]["credentials"]
        item = next(r["id"] for r in rows if r["destination"] == "keycloak-exchange-lab")
        if case_mode.startswith("edit-"):
            helper=root/"chef_human_enabled_edit";shutil.copy2(helper_source,helper);helper.chmod(0o755)
            def edit(action):
                result=common.run_uid(2,[helper,profiles/"human",hk,runtime/"human.sock",item,action],input=common.MASTER,check=False,timeout=20)
                assert result.returncode==0,(result.stdout,result.stderr)
                (root/("human-edit-"+action+"-receipt.txt")).write_bytes(result.stdout)
            def observations():
                return [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
            if case_mode=="edit-new":
                for action,nonce in (("organize","d"),("title","e"),("rotate","f")):
                    edit(action)
                    _, result=exchange.start_attempt(cli,env,item,nonce);assert result.returncode==0
                    aid=json.loads(result.stdout)["result"]["attempt_id"]
                    wait_until(lambda:any(r.get("opcode")==4 and r.get("attempt")==aid for r in observations()),"F1: enabled "+action+" edit blocked NEW ordinary adapter emission")
                    if action=="rotate":
                        sent=next(r for r in observations() if r.get("attempt")==aid and r.get("opcode")==4)
                        assert sent["subject_sha256"]==hashlib.sha256(b"synthetic-r2-new-subject").hexdigest()
                        assert sent["requester_sha256"]==hashlib.sha256(b"synthetic-r2-new-requester").hexdigest()
                print("PASS F1 ordinary enabled organize+title+material edits emit new authenticated revision; rotation=new synthetic material",flush=True)
            else:
                _, result=exchange.start_attempt(cli,env,item,"d");assert result.returncode==0
                aid=json.loads(result.stdout)["result"]["attempt_id"]
                wait_until(lambda:any(r.get("opcode")==2 for r in observations()),"initial unknown did not enter query recovery")
                edit("rotate")
                release.touch();os.chown(release,5,5)
                with sqlite3.connect(vault) as db:before=db.execute("SELECT count(*) FROM encrypted_audit_records").fetchone()[0]
                deadline=time.monotonic()+1.2;state=None
                while time.monotonic()<deadline:
                    observed=rpc(["auth","status","--attempt",aid]);state=json.loads(observed.stdout)["result"]["state"]
                    if state=="FAILED":break
                    time.sleep(.01)
                with sqlite3.connect(vault) as db:after=db.execute("SELECT count(*) FROM encrypted_audit_records").fetchone()[0]
                rows=observations();capture={"audit_before":before,"audit_after":after,"audit_delta":after-before,"connections":len(rows),"initial_calls":sum(r.get("opcode")==4 for r in rows),"post_edit_queries":sum(r.get("opcode")==2 and r.get("after_edit") for r in rows),"final_state":state}
                (root/"edit-reconcile-measurement.json").write_text(json.dumps(capture,indent=2)+"\n")
                print("MEASURED F2 "+json.dumps(capture),flush=True)
                assert state=="FAILED" and capture["post_edit_queries"]>=2,"F2: no legitimate opcode-2 result after enabled edit"
                assert capture["initial_calls"]==1 and capture["audit_delta"]<=8,capture
                assert all(r.get("opcode")!=2 or r["revision"]==next(v["revision"] for v in rows if v.get("opcode")==4) for r in rows)
                print("PASS F2 edited unknown recovered through pinned opcode2 with one original authentication and finite audit",flush=True)
            return
        _, started = exchange.start_attempt(cli,env,item,"a")
        assert started.returncode == 0
        attempt = json.loads(started.stdout)["result"]["attempt_id"]
        wait_until(events.exists,"provider emission missing")
        # Independent SQLite writer must be admitted while only response is held.
        def writer_released():
            connection=sqlite3.connect(vault,timeout=0)
            try:
                connection.execute("BEGIN IMMEDIATE");connection.rollback();return True
            except sqlite3.OperationalError as error:
                if getattr(error,"sqlite_errorcode",None)!=sqlite3.SQLITE_BUSY:raise
                return False
            finally:connection.close()
        wait_until(writer_released,"response wait holds SQLite writer")
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
