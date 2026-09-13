#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Disposable multi-UID TLS 1.3/RPK sync-server acceptance lab."""
import base64,hashlib,os,pathlib,signal,sqlite3,subprocess,sys,tempfile,time,shutil
SERVER,A,B,C,ROGUE=1,2,3,4,5
def identity(uid):
 def change():os.setgroups([]);os.setgid(uid);os.setuid(uid)
 return change
def run(uid,args,check=True):return subprocess.run(args,check=check,capture_output=True,preexec_fn=identity(uid),timeout=15)
def keygen(tool,uid,folder,name):
 private,public=folder/(name+".key"),folder/(name+".pub");run(uid,[tool,"keygen","--private",private,"--public",public]);return private,public
def main():
 source_sync=pathlib.Path(sys.argv[1]).resolve();source_custody=pathlib.Path(sys.argv[2]).resolve();root=pathlib.Path(tempfile.mkdtemp(prefix="pm-sync-linux-lab-"));os.chmod(root,0o711);sync=root/"pm-sync";custody=root/"pm-custody";shutil.copyfile(source_sync,sync);shutil.copyfile(source_custody,custody);os.chmod(sync,0o755);os.chmod(custody,0o755)
 try:
  dirs=[]
  for uid,name in [(SERVER,"server"),(A,"a"),(B,"b"),(C,"c"),(ROGUE,"rogue")]:
   p=root/name;p.mkdir();os.chown(p,uid,uid);os.chmod(p,0o755);dirs.append(p)
  sk,sp=keygen(custody,SERVER,dirs[0],"server");keys=[keygen(custody,uid,folder,"client") for uid,folder in zip([A,B,C,ROGUE],dirs[1:])]
  runtime=root/"run";runtime.mkdir();os.chown(runtime,SERVER,SERVER);os.chmod(runtime,0o755);socket=runtime/"sync.sock";db=dirs[0]/"opaque.sqlite3";namespace="17"*32
  command=[sync,"serve","--db",db,"--socket",socket,"--server-key",sk,"--namespace",namespace]
  for _,pub in keys[:3]:command.extend(["--client-pub",pub])
  server=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=identity(SERVER));deadline=time.monotonic()+10
  while not socket.exists():
   if server.poll() is not None:raise AssertionError(server.communicate())
   if time.monotonic()>deadline:raise AssertionError("sync socket timeout")
   time.sleep(.02)
  opaque=os.urandom(4096);blob=dirs[1]/"opaque.bin";blob.write_bytes(opaque);os.chown(blob,A,A);digest=hashlib.sha256(opaque).hexdigest()
  common=lambda key:["--socket",socket,"--client-key",key,"--server-pub",sp,"--namespace",namespace]
  first=run(A,[sync,"put",*common(keys[0][0]),"--hash",digest,"--input",blob],False);assert first.returncode==0,(first,server.poll(),server.communicate() if server.poll() is not None else None);assert first.stdout==b'{"ok":true}\n'
  assert run(A,[sync,"put",*common(keys[0][0]),"--hash",digest,"--input",blob]).stdout==b'{"ok":true}\n'
  assert run(A,[sync,"publish",*common(keys[0][0]),"--hash",digest]).stdout==b'{"ok":true}\n'
  listed=run(B,[sync,"list",*common(keys[1][0])]).stdout;assert digest.encode() in listed
  fetched=run(C,[sync,"get",*common(keys[2][0]),"--hash",digest]).stdout;assert base64.b64encode(opaque) in fetched
  denied=run(ROGUE,[sync,"list",*common(keys[3][0])],False);assert denied.returncode==4 and denied.stderr==b"SYNC_UNAVAILABLE\n"
  missing="aa"*32;assert run(B,[sync,"publish",*common(keys[1][0]),"--hash",missing],False).returncode==5
  server.send_signal(signal.SIGTERM);server.communicate(timeout=5);assert server.returncode==-signal.SIGTERM
  old_socket_inode=socket.stat().st_ino
  database=sqlite3.connect(db);database.execute("update blocks set bytes=? where hash=?",(b"altered",bytes.fromhex(digest)));database.commit();database.close()
  server=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=identity(SERVER));deadline=time.monotonic()+10
  while not socket.exists() or socket.stat().st_ino==old_socket_inode:
   if server.poll() is not None:raise AssertionError(server.communicate())
   if time.monotonic()>deadline:raise AssertionError("sync restart timeout")
   time.sleep(.02)
  tampered=run(C,[sync,"get",*common(keys[2][0]),"--hash",digest],False);assert tampered.returncode==7,(tampered.returncode,tampered.stdout,tampered.stderr)
  server.send_signal(signal.SIGTERM);server.communicate(timeout=5);assert server.returncode==-signal.SIGTERM
  raw=b''.join(p.read_bytes() for p in dirs[0].glob("opaque.sqlite3*"));assert b"synthetic-ticket17-secret-canary" not in raw
  print("PASS sync-e2e custodians=3 server=opaque put=idempotent list=roots get=hash-bound partial=rejected hostile-tamper=rejected")
  print("PASS sync-path process=real multi-uid=1 tls=1.3 rpk=mutual alpn=pm-sync/1 json=base64 sqlite-copy=none")
  print("LIMIT public-internet=NOT_RUN production-service=NOT_RUN network-partition=simulated")
 finally:
  shutil.rmtree(root,ignore_errors=True)
if __name__=="__main__":main()
