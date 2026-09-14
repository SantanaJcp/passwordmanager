#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-12 disposable-userns OpenSSH/russh/custody end-to-end lab."""
import base64, json, os, pathlib, re, shutil, socket, struct, subprocess, sys, tempfile, time
sys.path.insert(0,str(pathlib.Path(__file__).parents[2]/"pm-custody"/"tests"))
from linux_lab import as_uid, create_vault, start_as, stop, wait_for_sockets, wire_fields

CUSTODIAN,HUMAN,AGENT_A,AGENT_B,SSH_CLIENT,ACCOUNT,SSHD=1,2,3,4,5,6,7
MALICIOUS_CODE=r"""import os,pathlib,socket,struct,sys
p=pathlib.Path(sys.argv[1]);p.unlink(missing_ok=True);s=socket.socket(socket.AF_UNIX);s.bind(str(p));os.chmod(p,0o666);s.listen(4)
def rx(c,n):
 o=b''
 while len(o)<n:
  x=c.recv(n-len(o))
  if not x:raise EOFError
  o+=x
 return o
while True:
 c,_=s.accept()
 try:n=struct.unpack('>I',rx(c,4))[0];q=rx(c,n);break
 except EOFError:c.close()
assert q[0]==4
f=lambda v:struct.pack('>I',len(v))+v
payload=f(b'S'*32)+b'\x32'+f(b'mallory')+f(b'ssh-connection')+f(b'publickey')+b'\x01'+f(b'ssh-ed25519')+f(b'wrong-public-key-blob')
for v in (b'\x05'+f(b''),b'\x06'+f(payload)):c.sendall(struct.pack('>I',len(v))+v)
try:rx(c,4)
except (EOFError,ConnectionResetError):pass
c.close();s.close()
"""
DEVICE="12121212121212121212121212121212"

def run(cmd,**kw): return subprocess.run([str(x) for x in cmd],check=True,**kw)
def terminate(process):
 if process.poll() is None: process.terminate()
 try: process.communicate(timeout=5)
 except subprocess.TimeoutExpired:
  process.kill();process.communicate(timeout=5)
 assert process.returncode in (-15,0,1),process.returncode

def frame(v): return struct.pack(">I",len(v))+v
def field(v): return struct.pack(">I",len(v))+v
def recv_exact(c,n):
 out=b""
 while len(out)<n:
  part=c.recv(n-len(out))
  if not part: raise EOFError
  out+=part
 return out
def recv_frame(c): return recv_exact(c,struct.unpack(">I",recv_exact(c,4))[0])

def mount_private_nss(root):
 run(["mount","--make-rprivate","/"])
 run(["mount","-t","tmpfs","tmpfs","/run"]);(pathlib.Path('/run')/'sshd').mkdir(mode=0o755)
 run(["mount","-t","tmpfs","tmpfs","/home"])
 empty=root/'empty.sshd';empty.mkdir(mode=0o755);run(["mount","--bind",empty,"/usr/share/empty.sshd"])
 etc=root/'etc';etc.mkdir()
 password_hash=subprocess.check_output(["openssl","passwd","-6","-salt","ticket12salt","ssh-password-canary-T12"],text=True).strip()
 docs={
  'passwd':f"root:x:0:0:root:/root:/bin/sh\npmssh:x:{ACCOUNT}:{ACCOUNT}:Synthetic SSH:/home/pmssh:/bin/sh\nsshd:x:{SSHD}:{SSHD}:sshd privsep:/run/sshd:/usr/bin/nologin\n",
  'group':f"root:x:0:\npmssh:x:{ACCOUNT}:\nsshd:x:{SSHD}:\n",
  'shadow':f"root:!:20000:0:99999:7:::\npmssh:{password_hash}:20000:0:99999:7:::\nsshd:!:20000:0:99999:7:::\n",
  'gshadow':"root:!::\npmssh:!::\nsshd:!::\n",
 }
 for name,text in docs.items():
  p=etc/name;p.write_text(text);p.chmod(0o600 if 'shadow' in name else 0o644);run(["mount","--bind",p,pathlib.Path('/etc')/name])

def copy_bin(src,dst): shutil.copyfile(src,dst);dst.chmod(0o755)
def provision(custody,path,server_key,server_pub,agent_pub,human_pub,agent_uid=AGENT_A):
 as_uid(CUSTODIAN,[custody,"provision-bootstrap","--path",path,"--server-private",server_key,"--server-public",server_pub,"--agent-public",agent_pub,"--agent-uid",str(agent_uid),"--human-public",human_pub,"--human-uid",str(HUMAN)])
def daemon_start(custody,boot,runtime,vault,provider):
 for p in (runtime/'agent.sock',runtime/'human.sock'):p.unlink(missing_ok=True)
 p=start_as(CUSTODIAN,[custody,"serve-attempt-lab","--bootstrap",boot,"--agent-socket",runtime/'agent.sock',"--human-socket",runtime/'human.sock',"--vault",vault,"--device",DEVICE,"--provider-socket",provider,"--provider-uid",str(SSH_CLIENT)])
 wait_for_sockets(p,[runtime/'agent.sock',runtime/'human.sock']);return p
def ssh_client_start(binary,profile,runtime):
 for p in (runtime/'provider.sock',runtime/'consumer.sock'):p.unlink(missing_ok=True)
 p=start_as(SSH_CLIENT,[binary,"serve","--profile",profile,"--profile-owner",str(SSH_CLIENT),"--provider-socket",runtime/'provider.sock',"--provider-uid",str(CUSTODIAN),"--consumer-socket",runtime/'consumer.sock'])
 wait_for_sockets(p,[runtime/'provider.sock',runtime/'consumer.sock']);return p
def interface(binary,uid,env,args):
 def identity():os.setgroups([]);os.setgid(uid);os.setuid(uid)
 merged=os.environ.copy();merged.update(env)
 return subprocess.run([str(binary),*args],capture_output=True,env=merged,preexec_fn=identity,timeout=15)
def rpc(cli,uid,env,args,ok=True):
 r=interface(cli,uid,env,["--json",*args]);data=json.loads(r.stdout)
 if ok: assert r.returncode==0 and 'result' in data,(r,data)
 else: assert r.returncode!=0 and 'error' in data,(r,data)
 return data
def start_attempt(cli,uid,env,item,integration,method,nonce):
 now=int(time.time()*1_000_000)
 return rpc(cli,uid,env,["auth","start","--credential-id",item,"--integration-id",integration,"--integration-version","1","--method",method,"--destination","ssh-lab","--context","ssh-lab","--issued-at",str(now),"--nonce",nonce])['result']
def poll(cli,uid,env,attempt,want):
 end=time.time()+8
 while time.time()<end:
  result=rpc(cli,uid,env,["auth","status","--attempt",attempt])['result']
  if result['state'] in want:return result
  time.sleep(.05)
 raise AssertionError((attempt,result,want))
def profile(path,port,host_hash,consumer=AGENT_A,user='pmssh'):
 path.write_text(f"version=1\nprofile_id=ssh-lab\nintegrations=ssh-server,linux-system-ssh\nmethods=publickey,password\nhost=127.0.0.1\nport={port}\nusername={user}\nhost_key_sha256={host_hash}\nconsumer_uid={consumer}\nserver_version=OpenSSH_10.5p1\n")
 os.chown(path,SSH_CLIENT,SSH_CLIENT);path.chmod(0o400)
def host_hash(pub):
 parts=pub.read_text().split();raw=base64.b64decode(parts[1]);import hashlib;return hashlib.sha256(raw).hexdigest()
def make_sshd(root,port,challenge=False,user_source=None,host_source=None):
 root.mkdir()
 sshhome=pathlib.Path('/home/pmssh');sshhome.mkdir(parents=True,exist_ok=True);os.chown(sshhome,ACCOUNT,ACCOUNT);sshhome.chmod(0o755)
 dot=sshhome/'.ssh';dot.mkdir();os.chown(dot,ACCOUNT,ACCOUNT);dot.chmod(0o700)
 host=root/'host';user=root/'user'
 if host_source:
  shutil.copyfile(host_source,host);shutil.copyfile(str(host_source)+'.pub',str(host)+'.pub');host.chmod(0o600)
 else:run(['ssh-keygen','-q','-t','ed25519','-N','','-f',host])
 if user_source:
  shutil.copyfile(user_source,user);shutil.copyfile(str(user_source)+'.pub',str(user)+'.pub');user.chmod(0o600)
 else:run(['ssh-keygen','-q','-t','ed25519','-N','','-f',user])
 auth=dot/'authorized_keys';auth.write_bytes((root/'user.pub').read_bytes());os.chown(auth,ACCOUNT,ACCOUNT);auth.chmod(0o600)
 config=root/'sshd_config';methods='AuthenticationMethods publickey,password\n' if challenge else ''
 config.write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\nPidFile {root/'sshd.pid'}\nAuthorizedKeysFile .ssh/authorized_keys\nPasswordAuthentication yes\nPubkeyAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nAllowUsers pmssh\nStrictModes yes\nDisableForwarding yes\nPermitTTY no\nX11Forwarding no\nAllowAgentForwarding no\nLogLevel VERBOSE\n{methods}")
 run(['/usr/bin/sshd','-t','-f',config]);proc=subprocess.Popen(['/usr/bin/sshd','-D','-e','-f',config],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 time.sleep(.12);assert proc.poll() is None,proc.stderr.read();return proc,user,host_hash(root/'host.pub')
def free_port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p

def malicious_provider(sock):
 sock.unlink(missing_ok=True);s=socket.socket(socket.AF_UNIX);s.bind(sock);os.chmod(sock,0o666);s.listen(1);c,_=s.accept();request=recv_frame(c);assert request[0]==4
 c.sendall(frame(b'\x05'+field(b'')));c.sendall(frame(b'\x06'+field(b'not-an-rfc4252-payload')))
 try:recv_frame(c)
 except EOFError:pass
 c.close();s.close()

def human_auth(custody,key,profile_path,sock,password,action,*extra):
 for _ in range(3):
  r=as_uid(HUMAN,[custody,'human-authorization','--profile',profile_path,'--private',key,'--socket',sock,'--action',action],input=wire_fields([password,*extra]),check=False)
  if r.returncode==0:return
  time.sleep(.08)
 assert False,(r.stdout,r.stderr)
def main():
 custody,cli,sshbin=map(lambda x:pathlib.Path(x).resolve(),sys.argv[1:]);root=pathlib.Path(tempfile.mkdtemp(prefix='pm-ssh-linux-lab-'))
 procs=[]
 try:
  root.chmod(0o711)
  b=root/'pm-custody';pcli=root/'pm';pssh=root/'pm-ssh-client';copy_bin(custody,b);copy_bin(cli,pcli);copy_bin(sshbin,pssh)
  mount_private_nss(root)
  state,runtime,hhome,ahome,bhome,chome,profiles=[root/n for n in ('state','run','human','agent-a','agent-b','ssh-client','profiles')]
  for path,uid,mode in [(state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),(hhome,HUMAN,0o755),(ahome,AGENT_A,0o755),(bhome,AGENT_B,0o755),(chome,SSH_CLIENT,0o711),(profiles,0,0o755)]:path.mkdir();os.chown(path,uid,uid);path.chmod(mode)
  sk,sp=state/'server.key',state/'server.pub';hk,hp=hhome/'human.key',hhome/'human.pub';ak,ap=ahome/'a.key',ahome/'a.pub';bk,bp=bhome/'b.key',bhome/'b.pub'
  for uid,k,pub in [(CUSTODIAN,sk,sp),(HUMAN,hk,hp),(AGENT_A,ak,ap),(AGENT_B,bk,bp)]:as_uid(uid,[b,'keygen','--private',k,'--public',pub])
  boota,bootb=state/'boot-a',state/'boot-b';provision(b,boota,sk,sp,ap,hp);provision(b,bootb,sk,sp,bp,hp,AGENT_B)
  aprof,hprof=profiles/'agent.profile',profiles/'human.profile'
  for role,path in [('agent',aprof),('human',hprof)]:run([b,'provision-profile','--path',path,'--server-public',sp,'--server-uid',str(CUSTODIAN),'--role',role])
  vault=state/'vault.sqlite3';master=create_vault(pcli,vault)
  port=free_port();openssh=root/'openssh';sshd,user_key,hh=make_sshd(openssh,port);procs.append(sshd)
  sshprof=chome/'ssh.profile';profile(sshprof,port,hh)
  sshclient=ssh_client_start(pssh,sshprof,chome);procs.append(sshclient)
  daemon=daemon_start(b,boota,runtime,vault,chome/'provider.sock');procs.append(daemon)
  human_auth(b,hk,hprof,runtime/'human.sock',master,'setup',ap.read_bytes(),bp.read_bytes())
  for _ in range(3):
   setup=as_uid(HUMAN,[b,'human-ssh-lab-setup','--profile',hprof,'--private',hk,'--socket',runtime/'human.sock'],input=wire_fields([master,user_key.read_bytes(),pathlib.Path(str(user_key)+'.pub').read_bytes(),b'ssh-password-canary-T12']),check=False)
   if setup.returncode==0:break
   time.sleep(.08)
  assert setup.returncode==0,(setup.stdout,setup.stderr);m=re.search(rb'key=([0-9a-f]{32}) password=([0-9a-f]{32})',setup.stdout);assert m,setup.stdout
  key_item,password_item=(x.decode() for x in m.groups())
  env={'PM_PROFILE':str(aprof),'PM_PRIVATE':str(ak),'PM_SOCKET':str(runtime/'agent.sock')}
  discovered=rpc(pcli,AGENT_A,env,['credentials','list'])['result'];by_id={x['id']:x for x in discovered['credentials']}
  assert {'ssh-server','linux-system-ssh'}<=set(by_id[key_item]['integrations']);caps=rpc(pcli,AGENT_A,env,['capabilities'])['result'];assert {'ssh-server','linux-system-ssh'}<={x['id'] for x in caps['integrations']}
  key_start=start_attempt(pcli,AGENT_A,env,key_item,'ssh-server','publickey','11'*16);key_done=poll(pcli,AGENT_A,env,key_start['attempt_id'],{'SUCCEEDED'});key_ref=key_done['result']['consumer_ref']
  pass_start=start_attempt(pcli,AGENT_A,env,password_item,'linux-system-ssh','password','12'*16);pass_done=poll(pcli,AGENT_A,env,pass_start['attempt_id'],{'SUCCEEDED'});pass_ref=pass_done['result']['consumer_ref']
  for reference in (key_ref,pass_ref):
   r=as_uid(AGENT_A,[pssh,'consume','--socket',chome/'consumer.sock',reference],check=False);assert r.returncode==0 and b'authenticated-channel-opened-and-closed' in r.stdout,(r.stdout,r.stderr)
  wrong=as_uid(AGENT_A,[pssh,'consume','--socket',chome/'consumer.sock','A'*43],check=False);assert wrong.returncode!=0 and b'ssh-password-canary' not in wrong.stderr
  wrong_uid=as_uid(AGENT_B,[pssh,'consume','--socket',chome/'consumer.sock',key_ref],check=False);assert wrong_uid.returncode!=0
  # Pinned host mismatch: no READY means custody releases/signs no credential.
  terminate(sshclient);procs.remove(sshclient);profile(sshprof,port,'0'*64);sshclient=ssh_client_start(pssh,sshprof,chome);procs.append(sshclient)
  bad_host=start_attempt(pcli,AGENT_A,env,password_item,'linux-system-ssh','password','13'*16);assert poll(pcli,AGENT_A,env,bad_host['attempt_id'],{'FAILED'})['reason']=='AUTH_REJECTED'
  # Installed-account mismatch is rejected before opening a transport or asking custody.
  terminate(sshclient);procs.remove(sshclient);profile(sshprof,port,hh,user='mallory');sshclient=ssh_client_start(pssh,sshprof,chome);procs.append(sshclient)
  bad_user=start_attempt(pcli,AGENT_A,env,key_item,'ssh-server','publickey','14'*16);assert poll(pcli,AGENT_A,env,bad_user['attempt_id'],{'FAILED'})['reason']=='AUTH_REJECTED'
  # A malicious trusted-side signer request is not an arbitrary signing oracle.
  terminate(sshclient);procs.remove(sshclient)
  fake=start_as(SSH_CLIENT,[sys.executable,'-c',MALICIOUS_CODE,chome/'provider.sock']);wait_for_sockets(fake,[chome/'provider.sock']);procs.append(fake)
  bad_sign=start_attempt(pcli,AGENT_A,env,key_item,'ssh-server','publickey','15'*16);assert poll(pcli,AGENT_A,env,bad_sign['attempt_id'],{'FAILED'})['reason']=='INTEGRITY_FAILURE';terminate(fake);procs.remove(fake)
  # Real partial success becomes a bounded challenge and can be terminally cancelled.
  terminate(sshd);procs.remove(sshd);shutil.rmtree(pathlib.Path('/home/pmssh/.ssh'));pathlib.Path('/home/pmssh').rmdir()
  challenge_dir=root/'challenge';sshd,_,hh2=make_sshd(challenge_dir,port,True,user_key,openssh/'host');assert hh2==hh;procs.append(sshd)
  profile(sshprof,port,hh);sshclient=ssh_client_start(pssh,sshprof,chome);procs.append(sshclient)
  challenge=start_attempt(pcli,AGENT_A,env,key_item,'ssh-server','publickey','16'*16);waiting=poll(pcli,AGENT_A,env,challenge['attempt_id'],{'WAITING_FOR_HUMAN'});assert waiting['reason']=='additional_factor_required'
  cancelled=rpc(pcli,AGENT_A,env,['auth','cancel','--attempt',challenge['attempt_id']])['result'];assert cancelled['state']=='CANCELLED',cancelled;time.sleep(.15);after=rpc(pcli,AGENT_A,env,['auth','status','--attempt',challenge['attempt_id']])['result'];assert after['state']=='CANCELLED',after
  # Same identifier is hidden when a different enrolled TLS identity owns the request.
  terminate(daemon);procs.remove(daemon);daemon=daemon_start(b,bootb,runtime,vault,chome/'provider.sock');procs.append(daemon)
  envb={'PM_PROFILE':str(aprof),'PM_PRIVATE':str(bk),'PM_SOCKET':str(runtime/'agent.sock')};foreign=rpc(pcli,AGENT_B,envb,['auth','status','--attempt',key_start['attempt_id']],False);assert foreign['error']['code']=='NOT_FOUND',foreign
  # Prior revocation blocks start before a provider connection/secret release.
  terminate(daemon);procs.remove(daemon);daemon=daemon_start(b,boota,runtime,vault,chome/'provider.sock');procs.append(daemon)
  human_auth(b,hk,hprof,runtime/'human.sock',master,'resume-revoke-a')
  before=os.stat(chome/'provider.sock').st_atime_ns;revoked=rpc(pcli,AGENT_A,env,['auth','start','--credential-id',password_item,'--integration-id','linux-system-ssh','--integration-version','1','--method','password','--destination','ssh-lab','--context','ssh-lab','--issued-at',str(int(time.time()*1_000_000)),'--nonce','17'*16],False);assert revoked['error']['code']=='AGENT_REVOKED';assert os.stat(chome/'provider.sock').st_atime_ns==before
  outputs=setup.stdout+setup.stderr
  assert b'ssh-password-canary-T12' not in outputs and b'BEGIN OPENSSH PRIVATE KEY' not in outputs
  for value in os.environ.values():assert 'ssh-password-canary-T12' not in value
  print('PASS ssh-e2e russh=0.63.3 openssh=10.5p1 auth=publickey+password AuthResult=Success post-auth-channel=opened-and-closed')
  print('PASS ssh-boundaries hostkey=reject-before-secret username=installed signing=rfc4252-only consumer=uid-bound ownership=hidden revoke=pre-provider challenge=cancelled')
 finally:
  for proc in reversed(procs):terminate(proc)
  shutil.rmtree(root,ignore_errors=True)

if __name__=='__main__':
 if len(sys.argv)>1 and sys.argv[1]=='malicious':malicious_provider(pathlib.Path(sys.argv[2]))
 else:main()
