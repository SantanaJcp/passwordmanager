#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Opaque GitHub bearer profile through real custody, TLS and process seams."""

import json, os, pathlib, shutil, socket, ssl, subprocess, sys, tempfile, time
import web_auth_lab as common

CUSTODIAN, HUMAN, AGENT_A, AGENT_B, PROVIDER, DESTINATION = 1, 2, 3, 4, 5, 6
DEVICE = "15151515151515151515151515151515"
MASTER = common.MASTER
TOKEN = b"github_pat_ticket15_synthetic_canary_not_real"


def certificates(root):
    ca_key, ca_pem = root / "ca.key", root / "ca.pem"
    common.openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                   "-subj", "/CN=PM Ticket15 Lab CA", "-addext", "basicConstraints=critical,CA:TRUE",
                   "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", ca_key, "-out", ca_pem)
    key, csr, crt, ext = root / "github.key", root / "github.csr", root / "github.crt", root / "github.ext"
    ext.write_text("subjectAltName=DNS:api.github.com\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n")
    common.openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=api.github.com", "-keyout", key, "-out", csr)
    common.openssl("x509", "-req", "-days", "2", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
                   "-CAcreateserial", "-extfile", ext, "-out", crt)
    der = root / "ca.der"
    common.openssl("x509", "-in", ca_pem, "-outform", "DER", "-out", der)
    return der, key, crt


def destination_server(port, key, cert, capture):
    code = r'''import json,pathlib,socket,ssl,sys,urllib.parse
port=int(sys.argv[1]);key,cert,capture,token=sys.argv[2:];cap=pathlib.Path(capture)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(cert,key)
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',port));s.listen();pathlib.Path(capture+'.ready').write_text('1')
while True:
 c,_=s.accept()
 try:
  with ctx.wrap_socket(c,server_side=True) as t:
   data=b''
   while b'\r\n\r\n' not in data and len(data)<65536:data+=t.recv(4096)
   with cap.open('ab') as f:f.write(data+b'\n--REQUEST--\n')
   head=data.split(b'\r\n\r\n',1)[0];line=head.split(b'\r\n',1)[0].decode();path=line.split(' ')[1]
   page=int(urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)['page'][0])
   body=b'';extra=b''
   if page==1:
    body=json.dumps([{'id':9007199254740993,'number':7,'title':'Synthetic assigned issue','state':'open','html_url':'https://github.com/acme/repo/issues/7','body':'private upstream body','user':{'login':'private'}}]).encode()
    extra=b'Link: <https://api.github.com/issues?filter=assigned&state=open&sort=created&direction=desc&page=2&per_page=30>; rel="next"\r\n'
    status=b'200 OK'
   elif page==2: status=b'302 Found';extra=b'Location: https://evil.invalid/collect\r\n'
   elif page==3: status=b'200 OK';extra=('X-Reflect: '+token+'\r\n').encode();body=b'[]'
   elif page==4: status=b'401 Unauthorized'
   elif page==5: status=b'403 Forbidden'
   elif page==6: status=b'403 Forbidden';extra=b'X-GitHub-SSO: required; url=https://github.com/orgs/acme/sso\r\n'
   elif page==7: status=b'403 Forbidden';extra=b'Retry-After: 60\r\n'
   elif page==8: status=b'403 Forbidden';extra=b'Retry-After: forever\r\n'
   else: status=b'500 Internal Server Error'
   response=b'HTTP/1.1 '+status+b'\r\n'+extra+b'Content-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
   t.sendall(response)
   try:t.unwrap()
   except (OSError,ssl.SSLError):pass
 except (OSError,ssl.SSLError,KeyError,ValueError): pass
'''
    return common.start_uid(DESTINATION, [sys.executable, "-c", code, str(port), key, cert, capture, TOKEN.decode()])


def daemon(custody, bootstrap, runtime, vault, provider_socket):
    return common.start_uid(CUSTODIAN, [custody, "serve-attempt-lab", "--bootstrap", bootstrap,
        "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
        "--vault", vault, "--device", DEVICE, "--provider-socket", provider_socket,
        "--provider-uid", str(PROVIDER)])


def start(cli, env, item, page, nonce):
    args = ["--json", "auth", "start", "--credential-id", item,
        "--integration-id", "github-rest-bearer", "--integration-version", "1", "--method", "bearer",
        "--destination", "github-assigned-issues/1", "--request-profile", "github-assigned-issues/1",
        "--filter", "assigned", "--state", "open", "--sort", "created", "--direction", "desc",
        "--page", str(page), "--per-page", "30", "--issued-at", str(int(time.time()*1_000_000)),
        "--nonce", f"{nonce:02x}" * 16]
    return args, common.cli(AGENT_A, cli, env, args, check=False)


def terminal(cli, env, attempt):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = common.cli(AGENT_A, cli, env, ["--json", "auth", "status", "--attempt", attempt], check=False)
        if result.returncode == 0:
            value = json.loads(result.stdout)["result"]
            if value["state"] in ("SUCCEEDED", "FAILED", "INDETERMINATE", "CANCELLED"):
                return value, result.stdout
        time.sleep(.05)
    raise AssertionError("attempt did not finish")


def main():
    custody, cli, adapter = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:])
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-github-bearer-linux-lab-")); processes = []
    try:
        root.chmod(0o711); port = common.free_port(); certroot = root / "certs"; certroot.mkdir()
        ca_der, key, cert = certificates(certroot)
        state, runtime, human, agent, agent_b, provider, destination, profiles = [root / n for n in
            ("state", "run", "human", "agent", "agent-b", "provider", "destination", "profiles")]
        for path, uid, mode in ((state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),(human,HUMAN,0o755),
            (agent,AGENT_A,0o755),(agent_b,AGENT_B,0o755),(provider,PROVIDER,0o700),
            (destination,DESTINATION,0o700),(profiles,0,0o755)):
            path.mkdir(); os.chown(path,uid,uid); path.chmod(mode)
        for path in (key,cert): os.chown(path,DESTINATION,DESTINATION); path.chmod(0o400)
        installed_ca = provider / "ca.der"; shutil.copy2(ca_der,installed_ca); os.chown(installed_ca,PROVIDER,PROVIDER); installed_ca.chmod(0o400)
        profile = provider / "github.profile"
        profile.write_text("\n".join(("version=1","profile_id=github-assigned-issues/1","integration_id=github-rest-bearer",
            "origin=https://api.github.com",f"connect_port={port}",f"ca_der={installed_ca}","")))
        os.chown(profile,PROVIDER,PROVIDER); profile.chmod(0o400)
        socket_dir=root/"provider-socket";socket_dir.mkdir();os.chown(socket_dir,PROVIDER,PROVIDER);socket_dir.chmod(0o711)
        provider_socket=socket_dir/"github.sock";provider_log=provider/"provider.log";provider_log.touch();os.chown(provider_log,PROVIDER,PROVIDER)
        capture=destination/"requests";server=destination_server(port,key,cert,capture);processes.append(server);common.wait_path(server,pathlib.Path(str(capture)+".ready"))
        local_adapter=root/"pm-web-auth";shutil.copy2(adapter,local_adapter);local_adapter.chmod(0o755)
        web=common.start_uid(PROVIDER,[local_adapter,"serve","--profile",profile,"--socket",provider_socket,"--custodian-uid",str(CUSTODIAN)],stdout=open(provider_log,"wb"),stderr=subprocess.STDOUT)
        processes.append(web);common.wait_path(web,provider_socket)
        local_custody,local_cli=root/"pm-custody",root/"pm";shutil.copy2(custody,local_custody);shutil.copy2(cli,local_cli);local_custody.chmod(0o755);local_cli.chmod(0o755)
        server_key,server_pub=state/"server.key",state/"server.pub";human_key,human_pub=human/"human.key",human/"human.pub";agent_key,agent_pub=agent/"a.key",agent/"a.pub";b_key,b_pub=agent_b/"b.key",agent_b/"b.pub"
        for uid,private,public in ((CUSTODIAN,server_key,server_pub),(HUMAN,human_key,human_pub),(AGENT_A,agent_key,agent_pub),(AGENT_B,b_key,b_pub)):
            common.run_uid(uid,[local_custody,"keygen","--private",private,"--public",public])
        bootstrap=state/"bootstrap";common.run_uid(CUSTODIAN,[local_custody,"provision-bootstrap","--path",bootstrap,"--server-private",server_key,"--server-public",server_pub,"--agent-public",agent_pub,"--agent-uid",str(AGENT_A),"--human-public",human_pub,"--human-uid",str(HUMAN)])
        agent_profile,human_profile=profiles/"agent.profile",profiles/"human.profile"
        for role,out in (("agent",agent_profile),("human",human_profile)):
            subprocess.run([local_custody,"provision-profile","--path",out,"--server-public",server_pub,"--server-uid",str(CUSTODIAN),"--role",role],check=True,capture_output=True)
        vault=state/"vault.sqlite3";common.create_vault(local_cli,vault)
        d=daemon(local_custody,bootstrap,runtime,vault,provider_socket);processes.append(d);common.wait_path(d,runtime/"agent.sock");common.wait_path(d,runtime/"human.sock")
        common.human(local_custody,human_key,human_profile,runtime/"human.sock","setup",agent_pub.read_bytes(),b_pub.read_bytes())
        installed=common.run_uid(HUMAN,[local_custody,"human-github-lab-setup","--profile",human_profile,"--private",human_key,"--socket",runtime/"human.sock"],input=common.wire_fields([MASTER,TOKEN]),check=False)
        assert installed.returncode==0,(installed.stdout,installed.stderr)
        env={"PM_PROFILE":str(agent_profile),"PM_PRIVATE":str(agent_key),"PM_SOCKET":str(runtime/"agent.sock")}
        rows=json.loads(common.cli(AGENT_A,local_cli,env,["--json","credentials","list"]).stdout)["result"]["credentials"]
        row=next(value for value in rows if value["destination"]=="github-assigned-issues/1");item=row["id"]
        assert "github-rest-bearer" in row["integrations"]
        outputs=[]
        expected={1:("SUCCEEDED",None),2:("FAILED","INTEGRITY_FAILURE"),3:("FAILED","INTEGRITY_FAILURE"),4:("FAILED","AUTH_REJECTED"),5:("FAILED","AUTH_REJECTED"),6:("WAITING_FOR_HUMAN",None),7:("FAILED","RATE_LIMITED"),8:("FAILED","INTEGRITY_FAILURE"),9:("INDETERMINATE",None)}
        for page,(state_name,reason) in expected.items():
            args,started=start(local_cli,env,item,page,page);assert started.returncode==0,(page,started.stdout,started.stderr);value=json.loads(started.stdout)["result"]
            if state_name=="WAITING_FOR_HUMAN":
                deadline=time.monotonic()+20
                while time.monotonic()<deadline:
                    status=common.cli(AGENT_A,local_cli,env,["--json","auth","status","--attempt",value["attempt_id"]]);final=json.loads(status.stdout)["result"]
                    if final["state"]==state_name:break
                    time.sleep(.05)
                assert final["state"]==state_name,final
                cancelled=common.cli(AGENT_A,local_cli,env,["--json","auth","cancel","--attempt",value["attempt_id"]]);outputs.append(cancelled.stdout)
            else: final,status_out=terminal(local_cli,env,value["attempt_id"]);outputs.append(status_out)
            assert final["state"]==state_name and (reason is None or final["reason"]==reason),(page,final)
            if page==1:
                public=final["result"];assert set(public)=={"kind","provider","request_profile_id","status","items","page","next_page"}
                assert public["next_page"]==2 and set(public["items"][0])=={"id","number","title","state","html_url"}
                replay=common.cli(AGENT_A,local_cli,env,args);assert json.loads(replay.stdout)["result"]["attempt_id"]==value["attempt_id"];outputs.append(replay.stdout)
            else: assert final.get("result") is None
        bad=start(local_cli,env,item,1,20)[0]+["--url","https://evil.invalid"]
        rejected=common.cli(AGENT_A,local_cli,env,bad,check=False);assert rejected.returncode!=0;outputs.append(rejected.stdout+rejected.stderr)
        requests=capture.read_bytes();first=requests.split(b"\r\n\r\n",1)[0]
        assert first.startswith(b"GET /issues?filter=assigned&state=open&sort=created&direction=desc&page=1&per_page=30 HTTP/1.1\r\n")
        for required in (b"Host: api.github.com",b"Accept: application/vnd.github+json",b"X-GitHub-Api-Version: 2026-03-10",b"Authorization: Bearer "+TOKEN): assert required in first
        combined=b"".join(outputs)+provider_log.read_bytes()+installed.stdout+installed.stderr
        assert TOKEN not in combined and b"private upstream body" not in combined
        for candidate in state.rglob("*"):
            if candidate.is_file(): assert TOKEN not in candidate.read_bytes()
        print("PASS github-bearer profile=github-assigned-issues/1 origin+path+method+headers+query=fixed tls=1.3 uids=separate")
        print("PASS github-bearer-adversarial redirect+reflection+401+403+sso+quota+invalid-retry+5xx=closed public=reduced")
        print("PASS github-bearer-custody token=opaque idempotency=stable authority=real cancel=terminal real-github=ticket33")
    finally:
        for process in reversed(processes): common.stop(process)
        shutil.rmtree(root,ignore_errors=True)


if __name__ == "__main__": main()
