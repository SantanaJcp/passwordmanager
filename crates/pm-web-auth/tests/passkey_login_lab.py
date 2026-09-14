#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Real Keycloak WebAuthn registration -> same vault key assertion -> OIDC lab."""
import base64, fcntl, hashlib, json, os, pathlib, pty, select, shutil, signal
import socket, sqlite3, ssl, stat, struct, subprocess, sys, tempfile, termios, threading, time, urllib.parse, urllib.request

CUSTODIAN,HUMAN,BRIDGE,UNTRUSTED,DESTINATION=1,2,3,4,5
MASTER=b"synthetic ticket 14 master"
PASSWORD="synthetic-ticket14-initial-password"
DEVICE="14141414141414141414141414141414"
ALICE_ID="14141414-1414-4141-8141-141414141414"
EXTENSION_ID="jeaiefhkopnahbmombchmbpjifdjjdai"
EXTENSION_ORIGIN=f"chrome-extension://{EXTENSION_ID}/"

def identity(uid,tty=None):
 def change():
  if tty is not None: os.setsid();fcntl.ioctl(tty,termios.TIOCSCTTY,0)
  os.setgroups([]);os.setgid(uid);os.setuid(uid)
 return change

def run_uid(uid,cmd,*,input=None,check=True,env=None,timeout=40):
 merged=os.environ.copy();merged.update(env or {})
 return subprocess.run([str(x) for x in cmd],input=input,capture_output=True,check=check,preexec_fn=identity(uid),env=merged,timeout=timeout)

def start_uid(uid,cmd,*,env=None,cwd=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE):
 merged=os.environ.copy();merged.update(env or {})
 return subprocess.Popen([str(x) for x in cmd],preexec_fn=identity(uid),env=merged,cwd=cwd,stdout=stdout,stderr=stderr)

def stop(p):
 if p.poll() is None:
  p.send_signal(signal.SIGTERM)
  try:p.wait(8)
  except subprocess.TimeoutExpired:p.kill();p.wait(5)

def wait_path(p,path,timeout=15):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  if p.poll() is not None: raise AssertionError((p.returncode,p.stdout.read() if p.stdout else b"",p.stderr.read() if p.stderr else b""))
  if path.exists(): return
  time.sleep(.03)
 raise AssertionError(f"missing {path}")

def chown_tree(path,uid):
 for base,dirs,files in os.walk(path):
  os.chown(base,uid,uid)
  for name in dirs+files: os.chown(os.path.join(base,name),uid,uid)

def free_port():
 s=socket.socket();s.bind(("127.0.0.1",0));v=s.getsockname()[1];s.close();return v

def wire(values):
 out=bytearray()
 for value in values:out+=len(value).to_bytes(4,"big")+value
 return bytes(out)

def create_vault(cli,path):
 p=subprocess.Popen([str(cli),"vault","create",str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=identity(CUSTODIAN))
 assert p.stdout.readline()==b"Master password (read from stdin):\n";p.stdin.write(MASTER+b"\n");p.stdin.flush()
 assert p.stdout.readline()==b"Confirm master password:\n";p.stdin.write(MASTER+b"\n");p.stdin.flush()
 recovery=p.stdout.readline();assert recovery.startswith(b"Recovery code (store externally): PMR1-")
 assert p.stdout.readline()==b"Reintroduce recovery code to confirm the external copy:\n";p.stdin.write(recovery.split(b": ",1)[1]);p.stdin.close()
 assert p.wait(30)==0,(p.stdout.read(),p.stderr.read())

def human_auth(custody,key,profile,sock,action,*keys):
 r=run_uid(HUMAN,[custody,"human-authorization","--profile",profile,"--private",key,"--socket",sock,"--action",action],input=wire([MASTER,*keys]),check=False)
 assert r.returncode==0,(r.stdout,r.stderr)

def tty_confirm(uid,cmd,approval,password=MASTER,expected=0):
 master,slave=pty.openpty();p=subprocess.Popen([str(x) for x in cmd],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=identity(uid,slave),pass_fds=(slave,));os.close(slave)
 seen=b"";sent=False;pw=False;end=time.monotonic()+20
 while time.monotonic()<end and p.poll() is None:
  ready,_,_=select.select([master],[],[],.1)
  if not ready:continue
  try:seen+=os.read(master,4096)
  except OSError:break
  if not sent and b"to continue:" in seen:os.write(master,approval.encode()+b"\n");sent=True;seen=b""
  if sent and not pw and b"fresh reauthentication" in seen:os.write(master,password+b"\n");pw=True
 out,err=p.communicate(timeout=15);os.close(master)
 assert p.returncode==expected,(p.returncode,out,err,seen)
 return out,err

def tui_confirm(uid,custody,profile,key,sock,request_id,password=MASTER):
 tmux="/usr/bin/tmux";tmux_socket=key.parent/"ticket24-tmux.sock"
 env={"HOME":str(key.parent),"TERM":"xterm-256color"}
 def call(*args,check=True):
  return run_uid(uid,[tmux,"-S",tmux_socket,*args],check=check,env=env)
 def capture():return call("capture-pane","-p").stdout
 def wait_for(value,timeout=10):
  deadline=time.monotonic()+timeout
  while time.monotonic()<deadline:
   page=capture()
   if value in page:return page
   time.sleep(.05)
  raise AssertionError((value,capture()))
 def literal(value):call("send-keys","-l",value)
 call("kill-server",check=False)
 command=[custody,"tui","--profile",profile,"--private",key,"--socket",sock,
          "--idle-seconds","30","--reveal-seconds","1","--copy-seconds","2"]
 call("new-session","-d","-x","320","-y","30","--",*command)
 wait_for(b"Password required");literal(password.decode());call("send-keys","Enter")
 page=wait_for(b"Unlocked: selection never reveals secrets");assert password not in page
 literal("w");wait_for(b"Attempts (safe context only)")
 literal("j");wait_for(b"passkey-confirmation")
 literal("v");wait_for(b"type APPROVE")
 literal("APPROVE "+request_id);call("send-keys","Enter")
 wait_for(b"fresh reauthentication");literal(password.decode());call("send-keys","Enter")
 page=wait_for(b"Passkey confirmed with fresh UP+UV",20);assert password not in page
 call("send-keys","Escape");wait_for(b"Content view");literal("l")
 deadline=time.monotonic()+5
 while time.monotonic()<deadline and call("has-session",check=False).returncode==0:time.sleep(.05)
 assert call("has-session",check=False).returncode!=0

def native_call(bridge,message):
 raw=json.dumps(message,separators=(",",":")).encode();r=run_uid(BRIDGE,[bridge,EXTENSION_ORIGIN],input=len(raw).to_bytes(4,sys.byteorder)+raw,check=False)
 assert len(r.stdout)>=4,(r.returncode,r.stdout,r.stderr);n=int.from_bytes(r.stdout[:4],sys.byteorder)
 return json.loads(r.stdout[4:4+n])

def certificates(root):
 cakey,ca=root/"ca.key",root/"ca.pem"
 subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","2","-subj","/CN=PM Ticket14 CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout",cakey,"-out",ca],check=True,capture_output=True)
 key,csr,crt=root/"tls.key",root/"tls.csr",root/"tls.crt";ext=root/"tls.ext";ext.write_text("subjectAltName=DNS:auth.test,DNS:callback.test\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n")
 subprocess.run(["openssl","req","-newkey","rsa:2048","-nodes","-subj","/CN=auth.test","-keyout",key,"-out",csr],check=True,capture_output=True)
 subprocess.run(["openssl","x509","-req","-days","2","-in",csr,"-CA",ca,"-CAkey",cakey,"-CAcreateserial","-extfile",ext,"-out",crt],check=True,capture_output=True)
 der=root/"callback.der";pk=root/"callback.key.der";cader=root/"ca.der"
 subprocess.run(["openssl","x509","-in",crt,"-outform","DER","-out",der],check=True);subprocess.run(["openssl","x509","-in",ca,"-outform","DER","-out",cader],check=True)
 subprocess.run(["openssl","pkcs8","-topk8","-nocrypt","-in",key,"-outform","DER","-out",pk],check=True)
 return ca,cader,key,crt,der,pk

def realm(auth_port,callback_port):
 return {"realm":"pm","enabled":True,"sslRequired":"all","registrationAllowed":False,"eventsEnabled":True,"eventsListeners":["jboss-logging"],
  "webAuthnPolicyRpEntityName":"PM Ticket14","webAuthnPolicyRpId":"auth.test","webAuthnPolicySignatureAlgorithms":["Ed25519"],"webAuthnPolicyAttestationConveyancePreference":"none","webAuthnPolicyAuthenticatorAttachment":"not specified","webAuthnPolicyRequireResidentKey":"No","webAuthnPolicyUserVerificationRequirement":"required","webAuthnPolicyCreateTimeout":60,
  "clients":[{"clientId":"pm-passkey","enabled":True,"protocol":"openid-connect","publicClient":True,"standardFlowEnabled":True,"directAccessGrantsEnabled":False,"redirectUris":[f"https://callback.test:{callback_port}/callback"],"webOrigins":[],"protocolMappers":[{"name":"pm audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","consentRequired":False,"config":{"included.client.audience":"pm-passkey","access.token.claim":"true","id.token.claim":"false"}}]}],
  "users":[{"id":ALICE_ID,"username":"alice","email":"alice@example.invalid","firstName":"Alice","lastName":"Synthetic","enabled":True,"requiredActions":["webauthn-register"],"credentials":[{"type":"password","value":PASSWORD,"temporary":False}]}]}

def wait_keycloak(p,port,ca,log):
 ctx=ssl.create_default_context(cafile=str(ca));end=time.monotonic()+70
 while time.monotonic()<end:
  if p.poll() is not None:raise AssertionError(log.read_text(errors="replace"))
  try:
   raw=socket.create_connection(("127.0.0.1",port),timeout=2)
   with ctx.wrap_socket(raw,server_hostname="auth.test") as tls:
    tls.sendall(f"GET /realms/pm/.well-known/openid-configuration HTTP/1.1\r\nHost: auth.test:{port}\r\nConnection: close\r\n\r\n".encode());data=b""
    while True:
     piece=tls.recv(65536)
     if not piece:break
     data+=piece
    if b"200 OK" in data:return
  except Exception:time.sleep(.2)
 raise AssertionError(log.read_text(errors="replace"))

class Cdp:
 def __init__(self,p,w,r):self.p=p;self.w=w;self.r=r;self.n=0;self.buf=b""
 def command(self,method,params=None,session=None,timeout=20):
  self.n+=1;m={"id":self.n,"method":method,"params":params or {}};m.update({"sessionId":session} if session else {});os.write(self.w,json.dumps(m,separators=(",",":")).encode()+b"\0");end=time.monotonic()+timeout
  while time.monotonic()<end:
   while b"\0" in self.buf:
    raw,self.buf=self.buf.split(b"\0",1)
    if raw:
     v=json.loads(raw)
     if v.get("id")==self.n:assert "error" not in v,v;return v["result"]
   ready,_,_=select.select([self.r],[],[],.2)
   if ready:self.buf+=os.read(self.r,65536)
  raise AssertionError((method,self.p.poll()))
 def eval(self,s,expr):
  v=self.command("Runtime.evaluate",{"expression":expr,"awaitPromise":True,"returnByValue":True},s);assert "exceptionDetails" not in v,v;return v["result"].get("value")

def browser(cft,extension,home,url):
 r3,w3=os.pipe();r4,w4=os.pipe()
 def child():os.dup2(r3,3);os.dup2(w4,4);identity(BRIDGE)()
 args=[cft/"chrome","--headless=new","--remote-debugging-pipe","--disable-setuid-sandbox","--no-first-run","--no-default-browser-check","--disable-background-networking",f"--user-data-dir={home/'registration-profile'}",f"--disable-extensions-except={extension}",f"--load-extension={extension}","--host-resolver-rules=MAP auth.test 127.0.0.1, MAP callback.test 127.0.0.1","about:blank"]
 env={"HOME":str(home),"XDG_CONFIG_HOME":str(home/".config"),"XDG_CACHE_HOME":str(home/".cache"),"TMPDIR":str(home/"tmp"),"DBUS_SESSION_BUS_ADDRESS":"disabled:"}
 merged=os.environ.copy();merged.update(env)
 p=subprocess.Popen([str(x) for x in args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=open(home/"registration-chrome.log","wb"),preexec_fn=child,pass_fds=tuple(set((r3,w4,3,4))),env=merged)
 os.close(r3);os.close(w4);cdp=Cdp(p,w3,r4);cdp.command("Browser.getVersion");end=time.monotonic()+15
 # Do not navigate the first tab before Chromium has loaded the unpacked MV3
 # package.  Product code follows the same about:blank -> createTarget order.
 while time.monotonic()<end:
  ts=cdp.command("Target.getTargets")["targetInfos"]
  if any(x["type"] in ("service_worker","background_page") and x["url"].startswith("chrome-extension://") for x in ts):break
  time.sleep(.1)
 else:raise AssertionError(("extension-not-loaded",ts,(home/"registration-chrome.log").read_text(errors="replace")))
 target=cdp.command("Target.createTarget",{"url":url})["targetId"]
 s=cdp.command("Target.attachToTarget",{"targetId":target,"flatten":True})["sessionId"];cdp.command("Runtime.enable",session=s);cdp.command("Page.enable",session=s);return p,cdp,s

def wait_eval(cdp,s,expr,predicate,timeout=20):
 end=time.monotonic()+timeout;last=None
 while time.monotonic()<end:
  try:last=cdp.eval(s,expr)
  except Exception:last=None
  if predicate(last):return last
  time.sleep(.05)
 raise AssertionError(last)

def curl_json(url,port,ca,method="GET",data=None,token=None,form=False):
 cmd=["curl","--silent","--show-error","--fail","--cacert",str(ca),"--resolve",f"auth.test:{port}:127.0.0.1","-X",method]
 if token:cmd += ["-H","Authorization: Bearer "+token]
 if data is not None:
  if form:cmd += ["-H","Content-Type: application/x-www-form-urlencoded","--data",urllib.parse.urlencode(data)]
  else:cmd += ["-H","Content-Type: application/json","--data",json.dumps(data)]
 raw=subprocess.run(cmd+[url],check=True,capture_output=True).stdout
 return json.loads(raw or b"null")

def configure_flow(port,ca):
 base=f"https://auth.test:{port}";token=curl_json(base+"/realms/master/protocol/openid-connect/token",port,ca,"POST",{"grant_type":"password","client_id":"admin-cli","username":"admin","password":"synthetic-admin-ticket14"},form=True)["access_token"]
 admin=base+"/admin/realms/pm";flow={"alias":"pm-passkey-browser","description":"Ticket14 username then own passkey","providerId":"basic-flow","topLevel":True,"builtIn":False}
 curl_json(admin+"/authentication/flows",port,ca,"POST",flow,token)
 for provider in ("auth-username-form","webauthn-authenticator"):
  curl_json(admin+"/authentication/flows/pm-passkey-browser/executions/execution",port,ca,"POST",{"provider":provider},token)
 executions=curl_json(admin+"/authentication/flows/pm-passkey-browser/executions",port,ca,token=token)
 for execution in executions:
  execution["requirement"]="REQUIRED";curl_json(admin+"/authentication/flows/pm-passkey-browser/executions",port,ca,"PUT",execution,token)
 curl_json(admin,port,ca,"PUT",{"browserFlow":"pm-passkey-browser"},token)

def ext_hash(path):
 h=hashlib.sha256()
 for name in ("config.js","content.js","main.js","manifest.json","service.js"):
  h.update(name.encode()+b"\0"+ (path/name).read_bytes()+b"\0")
 return h.hexdigest()

def cli(uid,binary,env,args,check=True):
 r=run_uid(uid,[binary,*args],env=env,check=False,timeout=45)
 if check:assert r.returncode==0,(r.stdout,r.stderr)
 return r

def attempt_status(uid,binary,env,attempt,terminal=False,timeout=35,allowed_intermediates=None):
 end=time.monotonic()+timeout;value=None
 while time.monotonic()<end:
  result=cli(uid,binary,env,["--json","auth","status","--attempt",attempt],check=False)
  if result.returncode!=0:return None,result
  value=json.loads(result.stdout)["result"]
  assert value["attempt_id"]==attempt,(attempt,value)
  if (terminal and value["state"] in ("SUCCEEDED","FAILED","INDETERMINATE")) or (not terminal and value["state"]=="WAITING_FOR_HUMAN"):return value,result
  if allowed_intermediates is not None:
   observed=(value["state"],value.get("reason") or "")
   if observed not in allowed_intermediates:raise AssertionError((attempt,value))
  time.sleep(.05)
 raise AssertionError((attempt,value))

def latest_waiting_request(vault):
 db=sqlite3.connect(vault);row=db.execute("select hex(request_id) from passkey_requests where operation='get' and state='waiting' order by created_at_us desc limit 1").fetchone();db.close()
 return row[0].lower() if row else None

def main():
 custody_src,cli_src,web_src,bridge_src,kc_src,cft_src,extension_src,java_src=map(lambda x:pathlib.Path(x).resolve(),sys.argv[1:])
 root=pathlib.Path(tempfile.mkdtemp(prefix="pm-passkey-login-lab-"));procs=[]
 try:
  root.chmod(0o711);custody,cli_bin,web,bridge=[root/x for x in ("pm-custody","pm","pm-web-auth","pm-passkey-bridge")]
  for src,dst in ((custody_src,custody),(cli_src,cli_bin),(web_src,web),(bridge_src,bridge)):shutil.copy2(src,dst);dst.chmod(0o755)
  cft=root/"cft";shutil.copytree(cft_src,cft,symlinks=True);extension=root/"extension";shutil.copytree(extension_src,extension)
  auth_port,callback_port=free_port(),free_port();origin=f"https://auth.test:{auth_port}"
  # Registration browser package is the same fixed extension, configured for this exact RP.
  for name in ("config.js","manifest.json"):
   path=extension/name;text=path.read_text().replace("https://passkey.test:8443",origin).replace('rpId: "passkey.test"','rpId: "auth.test"');path.write_text(text)
  state,run,hh,bh,uh,dh,profiles=[root/x for x in ("state","run","human","bridge","untrusted","destination","profiles")]
  for path,uid,mode in ((state,CUSTODIAN,0o700),(run,CUSTODIAN,0o755),(hh,HUMAN,0o755),(bh,BRIDGE,0o755),(uh,UNTRUSTED,0o755),(dh,DESTINATION,0o700),(profiles,0,0o755)):
   path.mkdir();os.chown(path,uid,uid);path.chmod(mode)
  certs=root/"certs";certs.mkdir();ca,cader,tlskey,tlscrt,callbackder,callbackkey=certificates(certs)
  kc=dh/"keycloak";java=dh/"java";shutil.copytree(kc_src,kc,symlinks=True);shutil.copytree(java_src,java,symlinks=True);chown_tree(kc,DESTINATION);chown_tree(java,DESTINATION)
  imports=kc/"data/import";imports.mkdir(parents=True,exist_ok=True);(imports/"pm.json").write_text(json.dumps(realm(auth_port,callback_port)));chown_tree(kc/"data",DESTINATION)
  for p in (tlskey,tlscrt):os.chown(p,DESTINATION,DESTINATION);p.chmod(0o400)
  klog=dh/"keycloak.log";klog.touch();os.chown(klog,DESTINATION,DESTINATION);kf=open(klog,"wb")
  kp=start_uid(DESTINATION,[kc/"bin/kc.sh","start","--https-port",str(auth_port),"--http-enabled=false","--https-certificate-file",tlscrt,"--https-certificate-key-file",tlskey,"--hostname",origin,"--import-realm","--db=dev-file"],cwd=kc,env={"JAVA_HOME":str(java),"PATH":str(java/"bin")+":/usr/bin:/bin","KC_BOOTSTRAP_ADMIN_USERNAME":"admin","KC_BOOTSTRAP_ADMIN_PASSWORD":"synthetic-admin-ticket14"},stdout=kf,stderr=subprocess.STDOUT);procs.append(kp);wait_keycloak(kp,auth_port,ca,klog)
  sk,sp=state/"server.key",state/"server.pub";hk,hp=hh/"human.key",hh/"human.pub";ak,ap=bh/"bridge.key",bh/"bridge.pub";uk,up=uh/"untrusted.key",uh/"untrusted.pub"
  for uid,k,p in ((CUSTODIAN,sk,sp),(HUMAN,hk,hp),(BRIDGE,ak,ap),(UNTRUSTED,uk,up)):run_uid(uid,[custody,"keygen","--private",k,"--public",p])
  boot=state/"bootstrap";run_uid(CUSTODIAN,[custody,"provision-bootstrap","--path",boot,"--server-private",sk,"--server-public",sp,"--agent-public",ap,"--agent-uid",str(BRIDGE),"--human-public",hp,"--human-uid",str(HUMAN)])
  aprof,hprof=profiles/"agent.profile",profiles/"human.profile"
  for role,out in (("agent",aprof),("human",hprof)):subprocess.run([custody,"provision-profile","--path",out,"--server-public",sp,"--server-uid",str(CUSTODIAN),"--role",role],check=True,capture_output=True)
  vault=state/"vault.sqlite3";create_vault(cli_bin,vault)
  daemon=start_uid(CUSTODIAN,[custody,"serve-vault","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE]);procs.append(daemon);wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
  time.sleep(1)
  human_auth(custody,hk,hprof,run/"human.sock","setup",ap.read_bytes(),up.read_bytes())
  conf=pathlib.Path(str(bridge)+".conf");conf.write_text("\n".join(["PMN1",f"profile={aprof}",f"private={ak}",f"socket={run/'agent.sock'}",f"extension_origin={EXTENSION_ORIGIN}",f"origin={origin}","rp_id=auth.test",""]));os.chown(conf,BRIDGE,BRIDGE);conf.chmod(0o400)
  home=bh/"browser";home.mkdir();os.chown(home,BRIDGE,BRIDGE);home.chmod(0o700)
  for x in (home/"tmp",home/"registration-profile",home/".pki/nssdb"):x.mkdir(parents=True,exist_ok=True);chown_tree(home,BRIDGE)
  run_uid(BRIDGE,["certutil","-N","--empty-password","-d",f"sql:{home/'.pki/nssdb'}"],env={"HOME":str(home)});run_uid(BRIDGE,["certutil","-A","-d",f"sql:{home/'.pki/nssdb'}","-n","pm-ticket14-ca","-t","C,,","-i",ca],env={"HOME":str(home)})
  host={"name":"org.passwordmanager.passkey","description":"Ticket14 bridge","path":str(bridge),"type":"stdio","allowed_origins":[EXTENSION_ORIGIN]}
  fake=root/"opt/chrome_for_testing/native-messaging-hosts";fake.mkdir(parents=True);(fake/"org.passwordmanager.passkey.json").write_text(json.dumps(host));subprocess.run(["mount","--bind",root/"opt","/etc/opt"],check=True,capture_output=True)
  authorize=f"{origin}/realms/pm/protocol/openid-connect/auth?response_type=code&client_id=pm-passkey&redirect_uri={urllib.parse.quote(f'https://callback.test:{callback_port}/callback',safe='')}&scope=openid&state=registration&nonce=registration&code_challenge={'A'*43}&code_challenge_method=S256"
  bp,cdp,session=browser(cft,extension,home,authorize);procs.append(bp)
  wait_eval(cdp,session,"!!document.querySelector('#username')",lambda x:x is True)
  script=f"(()=>{{document.querySelector('#username').value='alice';document.querySelector('#password').value={json.dumps(PASSWORD)};document.querySelector('#kc-form-login').requestSubmit(document.querySelector('#kc-login'));return true}})()";assert cdp.eval(session,script) is True
  wait_eval(cdp,session,"!!document.querySelector('#registerWebAuthn')",lambda x:x is True)
  # Chromium may cloak extension-installed MAIN-world functions as native in
  # Function#toString.  The adapter publishes a non-configurable completion
  # marker only after both WebAuthn operations were replaced successfully.
  installed=wait_eval(cdp,session,"globalThis.__PM_PASSKEY_ADAPTER_INSTALLED__===true",lambda x:x is True)
  assert installed,(cdp.eval(session,"location.href"),cdp.eval(session,"typeof PM_PASSKEY_PROFILE"),(home/"registration-chrome.log").read_text(errors="replace"))
  no_platform=cdp.eval(session,"navigator.credentials.get({password:true}).then(()=> 'unexpected',e=>e.name)")
  assert no_platform=="NotSupportedError",no_platform
  time.sleep(1)
  assert cdp.eval(session,"document.querySelector('#registerWebAuthn').click();true") is True
  rid=wait_eval(cdp,session,"document.documentElement.dataset.pmPasskeyCalled||''",lambda x:isinstance(x,str) and len(x)==32)
  waiting_rid=wait_eval(cdp,session,"document.documentElement.dataset.pmPasskeyRequest||''",lambda x:isinstance(x,str) and len(x)==32);assert waiting_rid==rid
  confirm=[custody,"human-passkey-confirm","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request",rid,"--verification","verified"]
  tty_confirm(HUMAN,confirm,"APPROVE "+rid)
  time.sleep(.3);cdp.command("Page.handleJavaScriptDialog",{"accept":True,"promptText":"Passwordmanager passkey"},session)
  end=time.monotonic()+20;callback_url=None
  while time.monotonic()<end:
   targets=cdp.command("Target.getTargets")["targetInfos"]
   callback_url=next((x["url"] for x in targets if x["type"]=="page" and x["url"].startswith(f"https://callback.test:{callback_port}/callback")),None)
   if callback_url:break
   time.sleep(.05)
  if not callback_url:
   raise AssertionError((targets,klog.read_text(errors="replace"), (home/"registration-chrome.log").read_text(errors="replace")))
  reg=native_call(bridge,{"op":"response","requestId":rid,"documentId":"ticket14-registration","origin":origin,"rpId":"auth.test","topLevel":True,"frameId":0,"senderOrigin":origin})
  assert reg["state"]=="registration" and reg["attestation"]=="none" and len(reg["attestationObject"])>200,reg
  tty_confirm(HUMAN,[custody,"human-passkey-enable","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request",rid],"ENABLE "+rid)
  discovered=run_uid(BRIDGE,[custody,"agent-discover","--profile",aprof,"--private",ak,"--socket",run/"agent.sock"]);row=next(x for x in discovered.stdout.decode().split("set=",1)[1].split(",") if ":passkey:" in x);item=row.split(":",1)[0]
  stop(bp);procs.remove(bp);configure_flow(auth_port,ca)
  stop(daemon);procs.remove(daemon)
  for src,dst in ((cader,bh/"ca.der"),(callbackder,bh/"callback.der"),(callbackkey,bh/"callback.key.der")):shutil.copy2(src,dst);os.chown(dst,BRIDGE,BRIDGE);dst.chmod(0o400)
  profile=bh/"keycloak-passkey.profile";profile.write_text("\n".join(["version=1","profile_id=keycloak-passkey-lab",f"issuer={origin}/realms/pm",f"authorization_endpoint={origin}/realms/pm/protocol/openid-connect/auth",f"token_endpoint={origin}/realms/pm/protocol/openid-connect/token",f"jwks_uri={origin}/realms/pm/protocol/openid-connect/certs","client_id=pm-passkey",f"redirect_uri=https://callback.test:{callback_port}/callback",f"expected_subject={ALICE_ID}","expected_username=alice","audience=pm-passkey","scopes=openid","browser_version=153.0.8010.36",f"browser_sha256={hashlib.sha256((cft/'chrome').read_bytes()).hexdigest()}",f"browser_path={cft/'chrome'}",f"browser_home={home}",f"ca_der={bh/'ca.der'}",f"callback_cert={bh/'callback.der'}",f"callback_key={bh/'callback.key.der'}","method=webauthn",f"extension_path={extension}",f"extension_sha256={ext_hash(extension)}",""]));os.chown(profile,BRIDGE,BRIDGE);profile.chmod(0o400)
  sockdir=bh/"provider";sockdir.mkdir();os.chown(sockdir,BRIDGE,BRIDGE);sockdir.chmod(0o711);psock=sockdir/"web.sock";plog=bh/"provider.log";plog.touch();os.chown(plog,BRIDGE,BRIDGE)
  provider=start_uid(BRIDGE,[web,"serve","--profile",profile,"--socket",psock,"--custodian-uid",str(CUSTODIAN)],stdout=open(plog,"wb"),stderr=subprocess.STDOUT);procs.append(provider);wait_path(provider,psock)
  daemon=start_uid(CUSTODIAN,[custody,"serve-attempt-lab","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE,"--provider-socket",psock,"--provider-uid",str(BRIDGE)]);procs.append(daemon);wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
  env={"PM_PROFILE":str(aprof),"PM_PRIVATE":str(ak),"PM_SOCKET":str(run/"agent.sock")};args=["--json","auth","start","--credential-id",item,"--integration-id","keycloak-webauthn","--integration-version","1","--method","webauthn","--destination",origin,"--context","keycloak-passkey-lab","--issued-at",str(int(time.time()*1_000_000)),"--nonce","14"*16]
  outer=json.loads(cli(BRIDGE,cli_bin,env,args).stdout)["result"];attempt=outer["attempt_id"]
  waiting,_=attempt_status(BRIDGE,cli_bin,env,attempt)
  assert waiting["state"]=="WAITING_FOR_HUMAN",(waiting,plog.read_text(errors="replace"),klog.read_text(errors="replace"))
  end=time.monotonic()+20;request_id=None
  while time.monotonic()<end:
   request_id=latest_waiting_request(vault)
   if request_id:break
   # Reconciliation advances the trusted browser while custody remains paused.
   observed=json.loads(cli(BRIDGE,cli_bin,env,["--json","auth","status","--attempt",attempt]).stdout)["result"]
   assert observed["state"] in ("RUNNING","WAITING_FOR_HUMAN"),(observed,plog.read_text(errors="replace"))
   time.sleep(.05)
  assert request_id,(plog.read_text(errors="replace"),klog.read_text(errors="replace"))
  tty_confirm(HUMAN,[custody,"human-passkey-confirm","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request",request_id,"--verification","presence"],"APPROVE "+request_id,expected=4)
  tui_confirm(HUMAN,custody,hprof,hk,run/"human.sock",request_id)
  finished,_=attempt_status(BRIDGE,cli_bin,env,attempt,terminal=True)
  assert finished["state"]=="SUCCEEDED",(finished,plog.read_text(errors="replace"),klog.read_text(errors="replace"));tokens=finished["result"]
  assert tokens["kind"]=="oidc_tokens" and tokens["subject"]==ALICE_ID and tokens["issuer"]==origin+"/realms/pm" and tokens["audience"]=="pm-passkey"
  assert PASSWORD.encode() not in json.dumps(finished).encode()+plog.read_bytes();assert MASTER not in plog.read_bytes()

  # Restart loses the in-memory browser session and therefore closes the
  # durable outer attempt as an integrity failure; it never substitutes an OS
  # authenticator or resurrects the challenge.
  restart_args=args.copy();restart_args[restart_args.index("--nonce")+1]="16"*16;restart_args[restart_args.index("--issued-at")+1]=str(int(time.time()*1_000_000))
  restarted=json.loads(cli(BRIDGE,cli_bin,env,restart_args).stdout)["result"]["attempt_id"]
  attempt_status(BRIDGE,cli_bin,env,restarted)
  end=time.monotonic()+20
  while time.monotonic()<end and latest_waiting_request(vault)==request_id:
   cli(BRIDGE,cli_bin,env,["--json","auth","status","--attempt",restarted]);time.sleep(.05)
  restart_request=latest_waiting_request(vault);assert restart_request and restart_request!=request_id
  stop(provider);procs.remove(provider);psock.unlink()
  provider=start_uid(BRIDGE,[web,"serve","--profile",profile,"--socket",psock,"--custodian-uid",str(CUSTODIAN)],stdout=open(plog,"ab"),stderr=subprocess.STDOUT);procs.append(provider);wait_path(provider,psock)
  restart_terminal,_=attempt_status(BRIDGE,cli_bin,env,restarted,terminal=True)
  assert restart_terminal["state"]=="FAILED" and restart_terminal["reason"]=="INTEGRITY_FAILURE",restart_terminal

  # The persisted expiry is authoritative even while the real Keycloak page
  # and extension remain alive.
  expired_args=args.copy();expired_args[expired_args.index("--nonce")+1]="17"*16;expired_args[expired_args.index("--issued-at")+1]=str(int(time.time()*1_000_000))
  expired=json.loads(cli(BRIDGE,cli_bin,env,expired_args).stdout)["result"]["attempt_id"];attempt_status(BRIDGE,cli_bin,env,expired)
  end=time.monotonic()+20;expired_request=None
  while time.monotonic()<end:
   candidate=latest_waiting_request(vault)
   if candidate not in (request_id,restart_request):expired_request=candidate;break
   cli(BRIDGE,cli_bin,env,["--json","auth","status","--attempt",expired]);time.sleep(.05)
  assert expired_request
  db=sqlite3.connect(vault);db.execute("update passkey_requests set created_at_us=-2,expires_at_us=-1 where request_id=?",(bytes.fromhex(expired_request),));db.commit();db.close()
  tty_confirm(HUMAN,[custody,"human-passkey-confirm","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request",expired_request,"--verification","verified"],"APPROVE "+expired_request,expected=4)
  expired_observed,_=attempt_status(BRIDGE,cli_bin,env,expired,allowed_intermediates={("RUNNING","PASSKEY_HUMAN_CONFIRMATION")})
  assert expired_observed["state"]=="WAITING_FOR_HUMAN" and expired_observed["result"] is None,expired_observed
  cancelled=json.loads(cli(BRIDGE,cli_bin,env,["--json","auth","cancel","--attempt",expired]).stdout)["result"]
  assert cancelled["state"]=="CANCELLED" and cancelled["result"] is None,cancelled

  # The installed account is checked before any browser launch or assertion.
  stop(daemon);procs.remove(daemon);stop(provider);procs.remove(provider);psock.unlink()
  wrong_profile=bh/"wrong-account.profile";wrong_profile.write_text(profile.read_text().replace("expected_username=alice","expected_username=bob"));os.chown(wrong_profile,BRIDGE,BRIDGE);wrong_profile.chmod(0o400)
  provider=start_uid(BRIDGE,[web,"serve","--profile",wrong_profile,"--socket",psock,"--custodian-uid",str(CUSTODIAN)],stdout=open(plog,"ab"),stderr=subprocess.STDOUT);procs.append(provider);wait_path(provider,psock)
  daemon=start_uid(CUSTODIAN,[custody,"serve-attempt-lab","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE,"--provider-socket",psock,"--provider-uid",str(BRIDGE)]);procs.append(daemon);wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
  account_args=args.copy();account_args[account_args.index("--nonce")+1]="18"*16;account_args[account_args.index("--issued-at")+1]=str(int(time.time()*1_000_000))
  account_attempt=json.loads(cli(BRIDGE,cli_bin,env,account_args).stdout)["result"]["attempt_id"]
  account_terminal,_=attempt_status(BRIDGE,cli_bin,env,account_attempt,terminal=True)
  assert account_terminal["state"]=="FAILED" and account_terminal["reason"]=="UNSUPPORTED_INTEGRATION",account_terminal

  bad=args.copy();bad[bad.index("--destination")+1]="https://evil.invalid";bad[bad.index("--nonce")+1]="15"*16;rejected=cli(BRIDGE,cli_bin,env,bad,check=False);assert rejected.returncode!=0 and b"CREDENTIAL_UNAVAILABLE" in rejected.stdout

  # Revocation between WebAuthn challenge creation and the TTY ceremony leaves
  # no signed response and makes the outer attempt inaccessible to that peer.
  stop(daemon);procs.remove(daemon);stop(provider);procs.remove(provider);psock.unlink()
  provider=start_uid(BRIDGE,[web,"serve","--profile",profile,"--socket",psock,"--custodian-uid",str(CUSTODIAN)],stdout=open(plog,"ab"),stderr=subprocess.STDOUT);procs.append(provider);wait_path(provider,psock)
  daemon=start_uid(CUSTODIAN,[custody,"serve-attempt-lab","--bootstrap",boot,"--agent-socket",run/"agent.sock","--human-socket",run/"human.sock","--vault",vault,"--device",DEVICE,"--provider-socket",psock,"--provider-uid",str(BRIDGE)]);procs.append(daemon);wait_path(daemon,run/"agent.sock");wait_path(daemon,run/"human.sock")
  revoked_args=args.copy();revoked_args[revoked_args.index("--nonce")+1]="19"*16;revoked_args[revoked_args.index("--issued-at")+1]=str(int(time.time()*1_000_000))
  revoked_attempt=json.loads(cli(BRIDGE,cli_bin,env,revoked_args).stdout)["result"]["attempt_id"];attempt_status(BRIDGE,cli_bin,env,revoked_attempt)
  end=time.monotonic()+20;revoked_request=None
  while time.monotonic()<end:
   candidate=latest_waiting_request(vault)
   if candidate not in (request_id,restart_request,expired_request):revoked_request=candidate;break
   cli(BRIDGE,cli_bin,env,["--json","auth","status","--attempt",revoked_attempt]);time.sleep(.05)
  assert revoked_request;human_auth(custody,hk,hprof,run/"human.sock","resume-revoke-a")
  tty_confirm(HUMAN,[custody,"human-passkey-confirm","--profile",hprof,"--private",hk,"--socket",run/"human.sock","--request",revoked_request,"--verification","verified"],"APPROVE "+revoked_request,expected=4)
  db=sqlite3.connect(vault);row=db.execute("select state,response is not null from passkey_requests where request_id=?",(bytes.fromhex(revoked_request),)).fetchone();db.close();assert row==("waiting",1)
  revoked_status=cli(BRIDGE,cli_bin,env,["--json","auth","status","--attempt",revoked_attempt],check=False);assert revoked_status.returncode!=0 and b"AGENT_REVOKED" in revoked_status.stdout
  denied=run_uid(UNTRUSTED,["cat",conf],check=False);assert denied.returncode!=0 and denied.stdout==b""
  print("PASS passkey-login keycloak=26.7.3 registration=real assertion=same-vault-key oidc=code+PKCE-S256 result=oidc_tokens")
  print("PASS passkey-login-human outer=WAITING_FOR_HUMAN UP=TUI-keyboard UV=fresh-second-human-channel presence-only=denied extension=MV3-native real")
  print("PASS passkey-login-binding challenge+credential+account+origin=bound passwordless-flow=username+webauthn wrong-origin+account=denied secrets=absent")
  print("PASS passkey-login-negative challenge-expired=denied provider-restart=integrity-failure revoke-before-UPUV=denied os-authenticator=unused")
  print("LIMIT cft=laboratory-instrument product-browser=ticket33-NOT_RUN six-native-targets=NOT_RUN")
 finally:
  for p in reversed(procs):stop(p)
  shutil.rmtree(root,ignore_errors=True)
if __name__=="__main__":main()
