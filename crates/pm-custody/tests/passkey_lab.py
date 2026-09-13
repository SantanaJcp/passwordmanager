#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-13 real MV3 -> Native Messaging -> TLS/RPK -> custody lab."""

import base64, fcntl, hashlib, json, os, pathlib, pty, select, shutil, signal
import sqlite3, ssl, stat, subprocess, sys, tempfile, termios, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CUSTODIAN,HUMAN,BRIDGE,AGENT,ROGUE=1,2,3,4,5
DEVICE="13131313131313131313131313131313"
MASTER=b"synthetic ticket 13 e2e master"
ORIGIN="https://passkey.test:8443"
EXTENSION_ID="jeaiefhkopnahbmombchmbpjifdjjdai"
EXTENSION_ORIGIN=f"chrome-extension://{EXTENSION_ID}/"

def identity(uid, tty_fd=None):
    def change():
        if tty_fd is not None:
            os.setsid();fcntl.ioctl(tty_fd,termios.TIOCSCTTY,0)
        os.setgroups([]);os.setgid(uid);os.setuid(uid)
    return change

def run_uid(uid, command, *, input=None, check=True, env=None, timeout=30):
    merged=os.environ.copy();merged.update(env or {})
    return subprocess.run([str(x) for x in command],input=input,capture_output=True,check=check,
        preexec_fn=identity(uid),env=merged,timeout=timeout)

def start_uid(uid, command, *, env=None):
    merged=os.environ.copy();merged.update(env or {})
    return subprocess.Popen([str(x) for x in command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        preexec_fn=identity(uid),env=merged)

def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try: process.wait(timeout=8)
        except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)

def wait_path(process,path):
    deadline=time.monotonic()+12
    while time.monotonic()<deadline:
        if process.poll() is not None: raise AssertionError((process.returncode,process.stdout.read(),process.stderr.read()))
        if path.exists(): return
        time.sleep(.03)
    raise AssertionError(f"missing {path}")

def wire_fields(values):
    out=bytearray()
    for value in values: out.extend(len(value).to_bytes(4,"big"));out.extend(value)
    return bytes(out)

def create_vault(cli,path):
    p=subprocess.Popen([str(cli),"vault","create",str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,preexec_fn=identity(CUSTODIAN))
    assert p.stdout.readline()==b"Master password (read from stdin):\n"
    p.stdin.write(MASTER+b"\n");p.stdin.flush()
    assert p.stdout.readline()==b"Confirm master password:\n"
    p.stdin.write(MASTER+b"\n");p.stdin.flush()
    recovery=p.stdout.readline();assert recovery.startswith(b"Recovery code (store externally): PMR1-")
    assert p.stdout.readline()==b"Reintroduce recovery code to confirm the external copy:\n"
    p.stdin.write(recovery.split(b": ",1)[1]);p.stdin.close()
    assert p.wait(timeout=30)==0,(p.stdout.read(),p.stderr.read())

def human_authorization(binary,key,profile,sock,action,*public_keys):
    result=run_uid(HUMAN,[binary,"human-authorization","--profile",profile,"--private",key,
        "--socket",sock,"--action",action],input=wire_fields([MASTER,*public_keys]),check=False)
    assert result.returncode==0,(result.stdout,result.stderr)

def tty_action(uid,command,approval,password=MASTER,expected=0):
    needs_password=approval is not None
    master,slave=pty.openpty()
    process=subprocess.Popen([str(x) for x in command],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,preexec_fn=identity(uid,slave),pass_fds=(slave,))
    os.close(slave);seen=b"";deadline=time.monotonic()+15
    while approval is not None and time.monotonic()<deadline:
        ready,_,_=select.select([master],[],[],.1)
        if ready:
            try: seen+=os.read(master,4096)
            except OSError: break
            if b"to continue:" in seen:
                os.write(master,approval.encode()+b"\n");approval=None;seen=b""
        if process.poll() is not None: break
    if needs_password:
        while time.monotonic()<deadline:
            ready,_,_=select.select([master],[],[],.1)
            if ready:
                try: seen+=os.read(master,4096)
                except OSError: break
                if b"fresh reauthentication" in seen:
                    os.write(master,password+b"\n");break
            if process.poll() is not None: break
    out,err=process.communicate(timeout=15);os.close(master)
    assert process.returncode==expected,(process.returncode,out,err,seen)
    return out,err,seen

def native_call(binary,uid,argument,message):
    raw=json.dumps(message,separators=(",",":")).encode()
    framed=len(raw).to_bytes(4,sys.byteorder)+raw
    result=run_uid(uid,[binary,argument],input=framed,check=False)
    assert len(result.stdout)>=4,(result.returncode,result.stdout,result.stderr)
    size=int.from_bytes(result.stdout[:4],sys.byteorder)
    return result,json.loads(result.stdout[4:4+size])

class QuietServer(ThreadingHTTPServer):
    def handle_error(self,*_): pass

class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        body=b"<!doctype html><meta charset=utf-8><title>Ticket 13 synthetic RP</title><iframe src='/frame'></iframe>"
        self.send_response(200);self.send_header("Content-Type","text/html")
        self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*_): pass

class Cdp:
    def __init__(self,process,writer,reader): self.process=process;self.writer=writer;self.reader=reader;self.n=0;self.buffer=b""
    def command(self,method,params=None,session=None,timeout=15):
        self.n+=1;message={"id":self.n,"method":method,"params":params or {}}
        if session: message["sessionId"]=session
        os.write(self.writer,json.dumps(message,separators=(",",":")).encode()+b"\0")
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            while b"\0" in self.buffer:
                raw,self.buffer=self.buffer.split(b"\0",1)
                if raw:
                    value=json.loads(raw)
                    if value.get("id")==self.n:
                        assert "error" not in value,value
                        return value["result"]
            ready,_,_=select.select([self.reader],[],[],.2)
            if ready:
                chunk=os.read(self.reader,65536)
                if not chunk: break
                self.buffer+=chunk
            if self.process.poll() is not None: break
        raise AssertionError((method,self.process.poll(),self.process.stderr.read() if self.process.poll() is not None else b""))
    def evaluate(self,session,request,timeout=20):
        detail=json.dumps(request,separators=(",",":"))
        expression="new Promise((resolve)=>{const t=setTimeout(()=>resolve({ok:false,error:'NO_RESPONSE'}),5000);addEventListener('pm-passkey-response-v1',(e)=>{clearTimeout(t);resolve(e.detail)},{once:true});dispatchEvent(new CustomEvent('pm-passkey-request-v1',{detail:"+detail+"}))})"
        result=self.command("Runtime.evaluate",{"expression":expression,"awaitPromise":True,"returnByValue":True},session,timeout)
        assert "exceptionDetails" not in result,result
        return result["result"]["value"]

def start_browser(cft,extension,home,pin):
    read3,write3=os.pipe();read4,write4=os.pipe()
    def child():
        os.dup2(read3,3);os.dup2(write4,4);identity(BRIDGE)()
    args=[cft/"chrome","--headless=new","--remote-debugging-pipe","--disable-setuid-sandbox","--no-first-run","--no-default-browser-check",
      "--disable-background-networking",f"--user-data-dir={home/'profile'}",f"--disable-extensions-except={extension}",
      f"--load-extension={extension}","--host-resolver-rules=MAP passkey.test 127.0.0.1",
      f"--ignore-certificate-errors-spki-list={pin}",ORIGIN]
    env=os.environ.copy();env.update({"HOME":str(home),"XDG_CONFIG_HOME":str(home/".config"),"XDG_CACHE_HOME":str(home/".cache"),"TMPDIR":str(home/"tmp"),"DBUS_SESSION_BUS_ADDRESS":"disabled:"})
    log_path=home/"chrome.log";log=open(log_path,"wb")
    process=subprocess.Popen([str(x) for x in args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=log,
        preexec_fn=child,pass_fds=tuple(set((read3,write4,3,4))),env=env)
    os.close(read3);os.close(write4)
    cdp=Cdp(process,write3,read4);cdp.log_path=log_path;cdp.command("Browser.getVersion")
    deadline=time.monotonic()+12;target=None
    while time.monotonic()<deadline:
        targets=cdp.command("Target.getTargets")["targetInfos"]
        target=next((t for t in targets if t["type"]=="page" and t["url"].startswith(ORIGIN)),None)
        if target: break
        time.sleep(.1)
    assert target,targets
    attached=cdp.command("Target.attachToTarget",{"targetId":target["targetId"],"flatten":True})
    session=attached["sessionId"]
    cdp.command("Runtime.enable",session=session);time.sleep(1)
    return cdp,session

def cert(root):
    key,crt=root/"rp.key",root/"rp.crt"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","2","-subj","/CN=passkey.test",
      "-addext","subjectAltName=DNS:passkey.test","-keyout",key,"-out",crt],check=True,capture_output=True)
    pub=subprocess.run(["openssl","x509","-in",crt,"-pubkey","-noout"],check=True,capture_output=True).stdout
    der=subprocess.run(["openssl","pkey","-pubin","-outform","DER"],input=pub,check=True,capture_output=True).stdout
    return key,crt,base64.b64encode(hashlib.sha256(der).digest()).decode()

def request(op,rid,challenge,**extra):
    value={"op":op,"requestId":rid,"challenge":challenge,"userHandle":"","userName":"","displayName":"",
      "credentialIds":[],"uv":"required"};value.update(extra);return value

def main():
    custody_source,bridge_source,cli_source,cft,extension=map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:])
    root=pathlib.Path(tempfile.mkdtemp(prefix="pm-passkey-linux-lab-"));procs=[]
    try:
        root.chmod(0o711);custody,bridge,cli=[root/n for n in ("pm-custody","pm-passkey-bridge","pm")]
        for src,dst in [(custody_source,custody),(bridge_source,bridge),(cli_source,cli)]: shutil.copy2(src,dst);dst.chmod(0o755)
        local_cft=root/"cft";shutil.copytree(cft,local_cft,symlinks=True);cft=local_cft
        local_extension=root/"extension";shutil.copytree(extension,local_extension);extension=local_extension
        state,run,hh,ah,bh,rh,profiles=[root/n for n in ("state","run","human","bridge","agent","rogue","profiles")]
        for path,uid,mode in [(state,CUSTODIAN,0o700),(run,CUSTODIAN,0o755),(hh,HUMAN,0o755),(ah,BRIDGE,0o755),(bh,AGENT,0o755),(rh,ROGUE,0o755),(profiles,0,0o755)]:
            path.mkdir();os.chown(path,uid,uid);path.chmod(mode)
        sk,sp=state/"server.key",state/"server.pub";hk,hp=hh/"human.key",hh/"human.pub"
        ak,ap=ah/"bridge.key",ah/"bridge.pub";bk,bp=bh/"agent.key",bh/"agent.pub";rk,rp=rh/"rogue.key",rh/"rogue.pub"
        for uid,k,p in [(CUSTODIAN,sk,sp),(HUMAN,hk,hp),(BRIDGE,ak,ap),(AGENT,bk,bp),(ROGUE,rk,rp)]: run_uid(uid,[custody,"keygen","--private",k,"--public",p])
        boot=state/"bootstrap";run_uid(CUSTODIAN,[custody,"provision-bootstrap","--path",boot,"--server-private",sk,
          "--server-public",sp,"--agent-public",ap,"--agent-uid",str(BRIDGE),"--human-public",hp,"--human-uid",str(HUMAN)])
        aprof,hprof=profiles/"agent.profile",profiles/"human.profile"
        for role,out in [("agent",aprof),("human",hprof)]: subprocess.run([custody,"provision-profile","--path",out,"--server-public",sp,"--server-uid",str(CUSTODIAN),"--role",role],check=True,capture_output=True)
        vault=state/"vault.sqlite3";create_vault(cli,vault)
        daemon=start_uid(CUSTODIAN,[custody,"serve-vault","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE]);procs.append(daemon)
        wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
        human_authorization(custody,hk,hprof,run/"human.sock","setup",ap.read_bytes(),bp.read_bytes())

        # Private, exact bridge binding. The executable contains no passkey secret.
        config=pathlib.Path(str(bridge)+".conf")
        config.write_text("\n".join(["PMN1",f"profile={aprof}",f"private={ak}",f"socket={run/'agent.sock'}",
          f"extension_origin={EXTENSION_ORIGIN}",f"origin={ORIGIN}","rp_id=passkey.test",""]))
        os.chown(config,BRIDGE,BRIDGE);config.chmod(0o400)
        home=ah/"browser";home.mkdir();os.chown(home,BRIDGE,BRIDGE);home.chmod(0o700)
        for child in (home/"tmp",home/"profile"):
            child.mkdir();os.chown(child,BRIDGE,BRIDGE);child.chmod(0o700)
        manifest={"name":"org.passwordmanager.passkey","description":"Ticket 13 synthetic native host",
          "path":str(bridge),"type":"stdio","allowed_origins":[EXTENSION_ORIGIN]}
        for product in ("google-chrome-for-testing","google-chrome","chromium"):
            directory=home/".config"/product/"NativeMessagingHosts";directory.mkdir(parents=True,exist_ok=True)
            path=directory/"org.passwordmanager.passkey.json";path.write_text(json.dumps(manifest));os.chown(path,BRIDGE,BRIDGE)
        for base,dirs,files in os.walk(home/".config"):
            os.chown(base,BRIDGE,BRIDGE)
            for name in dirs+files: os.chown(os.path.join(base,name),BRIDGE,BRIDGE)
        # CFT's branded Linux lookup is exercised through a private mount
        # namespace. Nothing under the host's /etc is created or changed.
        fake_opt=root/"opt";native_dir=fake_opt/"chrome_for_testing"/"native-messaging-hosts"
        native_dir.mkdir(parents=True);(native_dir/"org.passwordmanager.passkey.json").write_text(json.dumps(manifest))
        subprocess.run(["mount","--bind",fake_opt,"/etc/opt"],check=True,capture_output=True)

        key,crt,pin=cert(root);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(crt,key)
        server=QuietServer(("127.0.0.1",8443),Page);server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        cdp,session=start_browser(cft,extension,home,pin);procs.append(cdp.process)
        browser_cmd=pathlib.Path(f"/proc/{cdp.process.pid}/cmdline").read_bytes()
        assert b"--remote-debugging-pipe" in browser_cmd and b"--remote-debugging-port" not in browser_cmd
        assert b"--no-sandbox" not in browser_cmd and cdp.process.pid>0
        assert home.stat().st_uid==BRIDGE and stat.S_IMODE(home.stat().st_mode)==0o700
        for resource in (f"/proc/{cdp.process.pid}/mem",f"/proc/{cdp.process.pid}/fd/3",f"/proc/{cdp.process.pid}/fd/4"):
            denied=run_uid(AGENT,["head","-c","1",resource],check=False);assert denied.returncode!=0 and denied.stdout==b""

        create=request("create","11"*16,"21"*32,userHandle="31"*16,userName="alice",displayName="Alice Synthetic")
        waiting=cdp.evaluate(session,create);assert waiting.get("state")=="waiting" and waiting.get("operation")=="create",(waiting,cdp.log_path.read_text(errors="replace"))
        # Durable browser request survives custody restart before a human sees it.
        stop(daemon);procs.remove(daemon)
        daemon=start_uid(CUSTODIAN,[custody,"serve-vault","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE]);procs.append(daemon)
        wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
        confirm=[custody,"human-passkey-confirm","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request","11"*16,"--verification","verified"]
        atomic_tables=("authority_events","outbox","human_receipts","encrypted_audit_records","vault_items","revision_parts")
        db=sqlite3.connect(vault);before_atomic=tuple(db.execute(f"select count(*) from {table}").fetchone()[0] for table in atomic_tables)
        db.execute("create trigger fail_ticket13_audit before insert on encrypted_audit_records begin select raise(abort,'ticket13 audit failure'); end");db.commit();db.close()
        tty_action(HUMAN,confirm,"APPROVE "+"11"*16,expected=4)
        stop(daemon);procs.remove(daemon)
        daemon=start_uid(CUSTODIAN,[custody,"serve-vault","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE]);procs.append(daemon)
        wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
        restart_discovery=run_uid(BRIDGE,[custody,"agent-discover","--profile",aprof,"--private",ak,"--socket",run/"agent.sock"],check=False)
        assert restart_discovery.returncode==0,(restart_discovery.stdout,restart_discovery.stderr)
        after_failure=cdp.evaluate(session,{"op":"response","requestId":"11"*16})
        diagnostic_db=sqlite3.connect(vault)
        diagnostic=diagnostic_db.execute("select state,length(response),expires_at_us from passkey_requests where request_id=?",(bytes.fromhex("11"*16),)).fetchall()
        after_atomic=tuple(diagnostic_db.execute(f"select count(*) from {table}").fetchone()[0] for table in atomic_tables);diagnostic_db.close()
        assert after_atomic==before_atomic,(before_atomic,after_atomic)
        assert after_failure.get("state")=="waiting",(after_failure,diagnostic,daemon.poll(),cdp.log_path.read_text(errors="replace"))
        db=sqlite3.connect(vault);db.execute("drop trigger fail_ticket13_audit");db.commit();db.close()
        tty_action(HUMAN,confirm,"APPROVE "+"11"*16)
        registration=cdp.evaluate(session,{"op":"response","requestId":"11"*16})
        assert registration["state"]=="registration" and registration["algorithm"]==-8 and registration["signCount"]==0
        assert registration["backupEligible"] is True and registration["backupState"] is False
        # Exact replay is public/idempotent; altered request never creates a second key.
        assert cdp.evaluate(session,create)==registration
        altered=dict(create);altered["challenge"]="22"*32
        assert cdp.evaluate(session,altered)["ok"] is False

        enable=[custody,"human-passkey-enable","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request","11"*16]
        tty_action(HUMAN,enable,"ENABLE "+"11"*16)
        discovered=run_uid(BRIDGE,[custody,"agent-discover","--profile",aprof,"--private",ak,"--socket",run/"agent.sock"])
        text=discovered.stdout.decode();row=next(v for v in text.split("set=",1)[1].split(",") if ":passkey:" in v);item=row.split(":",1)[0]

        get=request("get","41"*16,"51"*32,itemId=item,issuedAt=int(time.time()*1_000_000),nonce="61"*16,
          credentialIds=[registration["credentialId"]])
        waiting=cdp.evaluate(session,get);assert waiting["state"]=="waiting" and waiting["operation"]=="get"
        presence=[custody,"human-passkey-confirm","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request","41"*16,"--verification","presence"]
        tty_action(HUMAN,presence,None,expected=4)
        assert cdp.evaluate(session,{"op":"response","requestId":"41"*16})["state"]=="waiting"
        stop(daemon);procs.remove(daemon)
        daemon=start_uid(CUSTODIAN,[custody,"serve-vault","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE]);procs.append(daemon)
        wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
        verified=presence[:-1]+["verified"]
        tty_action(HUMAN,verified,"APPROVE "+"41"*16)
        assertion=cdp.evaluate(session,{"op":"response","requestId":"41"*16})
        assert assertion["state"]=="assertion" and len(assertion["signature"])==128

        # Native boundary rejects false host/extension/origin/document and unknown fields.
        valid={**create,"documentId":"doc-direct","origin":ORIGIN,"rpId":"passkey.test","topLevel":True,"frameId":0,"senderOrigin":ORIGIN}
        for argument,change in [("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",{}),(EXTENSION_ORIGIN,{"origin":"https://evil.invalid"}),
          (EXTENSION_ORIGIN,{"documentId":"../../false"}),(EXTENSION_ORIGIN,{"nativeHost":"false.host"})]:
            hostile=dict(valid);hostile.update(change);result,response=native_call(bridge,BRIDGE,argument,hostile)
            assert result.returncode in (0,4) and response=={"ok":False,"error":"NOT_ALLOWED"},(result,response)
        denied=run_uid(AGENT,["cat",config],check=False);assert denied.returncode!=0 and denied.stdout==b""
        denied_host,denied_message=native_call(bridge,AGENT,EXTENSION_ORIGIN,valid)
        assert denied_host.returncode==4 and denied_message=={"ok":False,"error":"NOT_ALLOWED"}
        denied=run_uid(ROGUE,[custody,"agent-discover","--profile",aprof,"--private",rk,"--socket",run/"agent.sock"],check=False)
        assert denied.returncode==4 and denied.stdout==b"" and denied.stderr==b"CUSTODY_UNAVAILABLE\n"

        # Revoke after the browser request but before human confirmation: never sign.
        # The packaged content script is absent in subframes (`all_frames=false`).
        frame_test=cdp.command("Runtime.evaluate",{"expression":"new Promise(resolve=>{let hit=false;const w=document.querySelector('iframe').contentWindow;w.addEventListener('pm-passkey-response-v1',()=>hit=true,{once:true});w.dispatchEvent(new w.CustomEvent('pm-passkey-request-v1',{detail:{op:'response',requestId:'41'.repeat(16)}}));setTimeout(()=>resolve(hit),300)})","awaitPromise":True,"returnByValue":True},session)
        assert frame_test["result"]["value"] is False,frame_test

        revoked=dict(get);revoked.update(requestId="71"*16,issuedAt=int(time.time()*1_000_000),nonce="72"*16,challenge="73"*32)
        assert cdp.evaluate(session,revoked)["state"]=="waiting"
        human_authorization(custody,hk,hprof,run/"human.sock","resume-revoke-a")
        revoked_confirm=verified.copy();revoked_confirm[revoked_confirm.index("41"*16)]="71"*16
        tty_action(HUMAN,revoked_confirm,"APPROVE "+"71"*16,expected=4)
        denied_response=cdp.evaluate(session,{"op":"response","requestId":"71"*16});assert denied_response["ok"] is False
        revoked_create=dict(create);revoked_create.update(requestId="74"*16,challenge="75"*32)
        assert cdp.evaluate(session,revoked_create)["ok"] is False
        cdp.command("Page.enable",session=session)
        cdp.command("Page.navigate",{"url":ORIGIN+"/new-document"},session);time.sleep(1)
        changed_document=cdp.evaluate(session,{"op":"response","requestId":"41"*16})
        assert changed_document=={"ok":False,"error":"DOCUMENT_CHANGED"},changed_document

        raw=vault.read_bytes()+b"".join(p.read_bytes() for p in state.iterdir() if p.is_file())
        for canary in (MASTER,bytes.fromhex("21"*32),b"Alice Synthetic",bytes.fromhex(registration["credentialId"])):
            assert canary not in raw
        chrome_log=cdp.log_path.read_bytes()
        assert MASTER not in chrome_log and bytes.fromhex("21"*32) not in chrome_log
        db=sqlite3.connect(vault)
        assert db.execute("select count(*) from passkey_requests where state='complete'").fetchone()[0]>=2
        assert db.execute("select count(*) from encrypted_audit_records").fetchone()[0]>=6
        assert db.execute("select count(*) from human_receipts").fetchone()[0]>=3
        db.close()
        print("PASS passkey-e2e browser=CFT-153.0.8010.36 mv3=real native-messaging=real bridge-uid=3 untrusted-agent-uid=4 agent-channel=tls1.3+rpk+alpn/pm-agent/1 human=tls1.3+rpk+alpn/pm-human/1")
        print("PASS passkey-custody key=independent+encrypted g6=exact registration=explicit-enable assertion=UP+UV audit=atomic restart=durable replay=idempotent")
        print("PASS passkey-adversarial origin+document+extension+host+unknown=denied iframe=no-content-script rogue-rpk=denied revoke-before-sign=denied secrets=absent")
        print("LIMIT cft=laboratory-instrument product-browser=ticket33-NOT_RUN passkey-login=ticket14-NOT_RUN cross-platform=NOT_RUN")
    finally:
        try: server.shutdown();server.server_close()
        except Exception: pass
        for process in reversed(procs): stop(process)
        shutil.rmtree(root,ignore_errors=True)

if __name__=="__main__": main()
