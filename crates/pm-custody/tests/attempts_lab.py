#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-08 public TLS/RPK attempt lab with a separate UID provider."""
import json, os, pathlib, re, shutil, socket, sqlite3, stat, struct, subprocess, sys, tempfile, time
from linux_lab import as_uid, create_vault, expect_unavailable, start_as, stop, wait_for_sockets, wire_fields

CUSTODIAN,HUMAN,AGENT_A,AGENT_B,PROVIDER=1,2,3,4,5
DEVICE="88888888888888888888888888888888"

def frame(v): return struct.pack(">I",len(v))+v
def recv_exact(c,n):
    out=b""
    while len(out)<n:
        p=c.recv(n-len(out))
        if not p: raise EOFError
        out+=p
    return out
def recv_frame(c): return recv_exact(c,struct.unpack(">I",recv_exact(c,4))[0])
def field(v): return struct.pack(">I",len(v))+v
def fields(v):
    out=[]; p=0
    while p<len(v): n=struct.unpack(">I",v[p:p+4])[0];p+=4;out.append(v[p:p+n]);p+=n
    return out

def provider(sock,journal,resolve):
    pathlib.Path(sock).unlink(missing_ok=True); s=socket.socket(socket.AF_UNIX);s.bind(sock);os.chmod(sock,0o666);s.listen()
    data={}
    if pathlib.Path(journal).exists(): data=json.loads(pathlib.Path(journal).read_text())
    while True:
        c,_=s.accept()
        try:
            req=recv_frame(c); op=req[0]; aid=req[1:17].hex(); revision=req[17:33].hex()
            if op==1:
                destination,context,username,password=fields(req[33:])
                assert destination==b"https://ticket07.invalid/login" and username==b"ticket07-user" and password==b"ticket07-secret-canary"
                mode=context.decode(); row=data.setdefault(aid,{"calls":0,"mode":mode,"revision":revision});row["calls"]+=1
                tmp=journal+".tmp";pathlib.Path(tmp).write_text(json.dumps(data,sort_keys=True));os.replace(tmp,journal)
                if mode in ("ambiguous","response-loss"): c.close();continue
                if mode=="challenge": response=b"\x01"+field(b"provider-challenge-ref")
                elif mode=="reject": response=b"\x02"+field(b"rejected")
                else: response=b"\x00"+field(b"provider-authenticated")
            elif op==2:
                row=data[aid]
                if row["mode"]=="ambiguous": response=b"\x03"+field(b"unknown")
                elif row["mode"]=="challenge" and pathlib.Path(resolve+aid).exists(): response=b"\x00"+field(b"provider-resolved")
                elif row["mode"]=="challenge": response=b"\x01"+field(b"provider-challenge-ref")
                else: response=b"\x00"+field(b"provider-authenticated")
            else: raise AssertionError(op)
            c.sendall(frame(response))
        except (EOFError,BrokenPipeError): pass
        finally: c.close()

def provision(binary,path,server_key,server_pub,agent_pub,agent_uid,human_pub):
    as_uid(CUSTODIAN,[binary,"provision-bootstrap","--path",path,"--server-private",server_key,"--server-public",server_pub,"--agent-public",agent_pub,"--agent-uid",str(agent_uid),"--human-public",human_pub,"--human-uid",str(HUMAN)])

def start(binary,boot,runtime,vault,provider_sock):
    for p in (runtime/"agent.sock",runtime/"human.sock"): p.unlink(missing_ok=True)
    d=start_as(CUSTODIAN,[binary,"serve-attempt-lab","--bootstrap",boot,"--agent-socket",runtime/"agent.sock","--human-socket",runtime/"human.sock","--vault",vault,"--device",DEVICE,"--provider-socket",provider_sock,"--provider-uid",str(PROVIDER)])
    wait_for_sockets(d,[runtime/"agent.sock",runtime/"human.sock"]);return d

def human(binary,key,profile,sock,password,action,*rpks,ok=True):
    r=as_uid(HUMAN,[binary,"human-authorization","--profile",profile,"--private",key,"--socket",sock,"--action",action],input=wire_fields([password,*rpks]),check=False)
    if ok: assert r.returncode==0,r
    else: expect_unavailable(r)
    return r

def agent(binary,uid,key,profile,sock,action,**kw):
    cmd=[binary,"agent-attempt","--profile",profile,"--private",key,"--socket",sock,"--action",action]
    for k,v in kw.items(): cmd += ["--"+k.replace("_","-"),str(v)]
    return as_uid(uid,cmd,check=False)

def parse(r,state=None):
    assert r.returncode==0 and r.stderr==b"",r
    text=r.stdout.decode();m=re.search(r"id=([0-9a-f]{32}).*state=([A-Z_]+)",text);assert m,text
    if state: assert m.group(2)==state,text
    return m.group(1)

def denied(r,code):
    assert r.returncode != 0 and r.stdout == f"DENIED code={code}\n".encode(), r

def main():
    binary,cli=map(lambda x:pathlib.Path(x).resolve(),sys.argv[1:]);root=pathlib.Path(tempfile.mkdtemp(prefix="pm-attempts-linux-lab-"))
    try:
        root.chmod(0o711); b=root/"pm-custody";pcli=root/"pm";shutil.copyfile(binary,b);shutil.copyfile(cli,pcli);b.chmod(0o755);pcli.chmod(0o755)
        state,runtime,hhome,ahome,bhome,phome,profiles=[root/n for n in ("state","run","human","agent-a","agent-b","provider","profiles")]
        for path,uid,mode in [(state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),(hhome,HUMAN,0o755),(ahome,AGENT_A,0o755),(bhome,AGENT_B,0o755),(phome,PROVIDER,0o755),(profiles,0,0o755)]:path.mkdir();os.chown(path,uid,uid);path.chmod(mode)
        sk,sp=state/"server.key",state/"server.pub";hk,hp=hhome/"human.key",hhome/"human.pub";ak,ap=ahome/"a.key",ahome/"a.pub";bk,bp=bhome/"b.key",bhome/"b.pub"
        for uid,k,p in [(CUSTODIAN,sk,sp),(HUMAN,hk,hp),(AGENT_A,ak,ap),(AGENT_B,bk,bp)]:as_uid(uid,[b,"keygen","--private",k,"--public",p])
        boota,bootb=state/"boot-a",state/"boot-b";provision(b,boota,sk,sp,ap,AGENT_A,hp);provision(b,bootb,sk,sp,bp,AGENT_B,hp)
        aprof,hprof=profiles/"agent.profile",profiles/"human.profile"
        for role,profile in [("agent",aprof),("human",hprof)]:subprocess.run([b,"provision-profile","--path",profile,"--server-public",sp,"--server-uid",str(CUSTODIAN),"--role",role],check=True)
        vault=state/"vault.sqlite3";password=create_vault(pcli,vault);psock=phome/"provider.sock";journal=phome/"journal.json";resolve=str(phome/"resolve-")
        provider_script=phome/"provider.py";helper_script=phome/"linux_lab.py";shutil.copyfile(__file__,provider_script);shutil.copyfile(pathlib.Path(__file__).with_name("linux_lab.py"),helper_script);os.chown(provider_script,PROVIDER,PROVIDER);os.chown(helper_script,PROVIDER,PROVIDER);provider_script.chmod(0o500);helper_script.chmod(0o400)
        provider_proc=start_as(PROVIDER,[sys.executable,provider_script,"provider",psock,journal,resolve]);wait_for_sockets(provider_proc,[psock])
        daemon=start(b,boota,runtime,vault,psock);human(b,hk,hprof,runtime/"human.sock",password,"setup",ap.read_bytes(),bp.read_bytes())
        discovery=as_uid(AGENT_A,[b,"agent-discover","--profile",aprof,"--private",ak,"--socket",runtime/"agent.sock"]).stdout.decode();item=re.search(r"set=([0-9a-f]{32}):",discovery).group(1)
        now=int(time.time()*1_000_000)
        success=agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="01"*16,context="success");sid=parse(success,"CREATED")
        time.sleep(.05);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=sid),"SUCCEEDED")
        assert parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="01"*16,context="success"),"SUCCEEDED")==sid
        conflict=agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="01"*16,context="reject");denied(conflict,3)
        challenge=parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="02"*16,context="challenge"),"CREATED");time.sleep(.05);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=challenge),"WAITING_FOR_HUMAN")
        as_uid(PROVIDER,["touch",resolve+challenge]);time.sleep(.15);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=challenge),"SUCCEEDED")
        cancelled=parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="03"*16,context="challenge"),"CREATED");time.sleep(.05);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","cancel",attempt=cancelled),"CANCELLED")
        ambiguous=parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="04"*16,context="ambiguous"),"CREATED");time.sleep(.05);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=ambiguous),"INDETERMINATE")
        lost=parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="07"*16,context="response-loss"),"CREATED");time.sleep(.2);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=lost),"SUCCEEDED")
        rejected=parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="08"*16,context="reject"),"CREATED");time.sleep(.05);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=rejected),"FAILED")
        stop(daemon);daemon=start(b,boota,runtime,vault,psock);parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=ambiguous),"INDETERMINATE")
        data=json.loads(journal.read_text());assert data[ambiguous]["calls"]==1 and data[lost]["calls"]==1
        db=sqlite3.connect(vault);before=db.execute("select count(*) from authentication_attempts").fetchone()[0];db.execute("create trigger fail_ticket08_audit before insert on encrypted_audit_records begin select raise(abort,'ticket08 audit fault'); end");db.commit();db.close()
        atomic=agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="06"*16,context="success");denied(atomic,1)
        db=sqlite3.connect(vault);assert db.execute("select count(*) from authentication_attempts").fetchone()[0]==before;db.execute("drop trigger fail_ticket08_audit");db.commit();db.close()
        stop(daemon);daemon=start(b,bootb,runtime,vault,psock);foreign=agent(b,AGENT_B,bk,aprof,runtime/"agent.sock","get",attempt=sid);denied(foreign,2)
        stop(daemon);daemon=start(b,boota,runtime,vault,psock);human(b,hk,hprof,runtime/"human.sock",password,"suspend");parse(agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=sid),"SUCCEEDED");blocked=agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","start",item=item,issued_at=now,nonce="05"*16,context="success");denied(blocked,4)
        human(b,hk,hprof,runtime/"human.sock",password,"resume-revoke-a");revoked=agent(b,AGENT_A,ak,aprof,runtime/"agent.sock","get",attempt=sid);denied(revoked,5)
        stop(daemon);db=sqlite3.connect(vault);assert db.execute("select count(*) from authentication_attempts").fetchone()[0]==6;assert db.execute("select count(*) from authentication_attempts where state='indeterminate'").fetchone()==(1,);db.close()
        for path in state.iterdir():
            if path.is_file(): assert b"ticket07-secret-canary" not in path.read_bytes()
        print("PASS attempts-e2e tls=rpk+alpn/pm-agent/1 provider=separate-uid idempotency=stable ownership=hidden challenge=trusted cancel=terminal")
        print("PASS attempts-crash provider-calls=1 ambiguous=INDETERMINATE restart=no-blind-retry K_ATT=device-only audit=atomic")
        stop(provider_proc)
    finally: shutil.rmtree(root,ignore_errors=True)

if __name__=="__main__":
    if len(sys.argv)>1 and sys.argv[1]=="provider": provider(*sys.argv[2:])
    else: main()
