#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""D2: actual adapter WAITING, local outage, honest unknown and no new login."""
import json,os,pathlib,sqlite3,sys,time
import chef_runtime_adapter as adapter


def exercise(c):
    case=os.environ['CHEF_RECONCILIATION_CASE'];common=adapter.common
    if case=='ssh-socket':return exercise_ssh(c)
    outage=case.removeprefix('indeterminate-')
    page=9 if case.startswith('indeterminate-') else 6
    initial='indeterminate' if page==9 else 'waiting_for_human'
    marker=f'page={page}&per_page='.encode()
    processes=c['processes'];d=c['d'];web=c['web'];config=c['config'];registry=c['registry']
    runtime=c['runtime'];capture=c['capture'];cli=c['local_cli'];env=c['env'];item=c['item']
    _,started=adapter.start(cli,env,item,page,80);assert started.returncode==0
    attempt=json.loads(started.stdout)['result']['attempt_id']
    def state():
        with sqlite3.connect(f"file:{c['vault']}?mode=ro",uri=True) as db:
            return db.execute('select state,terminal_at_us from authentication_attempts where attempt_id=?',(bytes.fromhex(attempt),)).fetchone()
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        if state()[0]==initial:break
        time.sleep(.01)
    else:raise AssertionError('real adapter never reached WAITING')
    assert capture.read_bytes().count(marker)==1
    print(f'OBSERVED D2 case={case} initial={initial} real-adapter=1 login-calls=1',flush=True)
    original_config=config.read_bytes();original_registry=registry.read_bytes()
    if outage=='socket':
        common.stop(web);processes.remove(web);c['provider_socket'].unlink()
    elif outage=='config-remove':config.unlink()
    elif outage=='config-replace':
        replacement=config.with_suffix('.replacement');replacement.write_bytes(original_config)
        os.chown(replacement,adapter.CUSTODIAN,adapter.CUSTODIAN);replacement.chmod(0o400);replacement.replace(config)
    elif outage=='registry-remove':registry.unlink()
    elif outage=='bootstrap-mode':c['bootstrap'].chmod(0o600)
    elif outage=='audit-mode':pathlib.Path(str(c['vault'])+'.audit-custody').chmod(0o600)
    else:raise AssertionError(case)
    # Read-only store observation also works when native custody admission now
    # correctly denies public get. No authority/write shims are used.
    time.sleep(1)
    observed,terminal=state()
    assert capture.read_bytes().count(marker)==1
    print(f'OBSERVED D2 case={case} after-outage={observed} terminal={terminal is not None} login-calls=1',flush=True)
    assert observed in ('waiting_for_human','indeterminate','running') and terminal is None,('local outage invented terminal outcome',case,observed,terminal is not None)
    if outage=='socket':
        with open(c['provider_log'],'ab') as output:
            web=common.start_uid(adapter.PROVIDER,[c['local_adapter'],'serve','--profile',c['profile'],'--socket',c['provider_socket'],'--custodian-uid',str(adapter.CUSTODIAN)],stdout=output,stderr=adapter.subprocess.STDOUT)
        processes.append(web);common.wait_path(web,c['provider_socket'])
    for path,value in ((config,original_config),(registry,original_registry)):
        if not path.exists():path.write_bytes(value);os.chown(path,adapter.CUSTODIAN,adapter.CUSTODIAN);path.chmod(0o400)
    c['bootstrap'].chmod(0o400);pathlib.Path(str(c['vault'])+'.audit-custody').chmod(0o400)
    # Restoring installed trust requires the documented restart, never reload.
    common.stop(d);processes.remove(d)
    out,diagnostic=d.communicate(timeout=5)
    category=b'CUSTODY_UNAVAILABLE' if outage in ('registry-remove','bootstrap-mode','audit-mode') else b'ADAPTER_UNAVAILABLE'
    expected=b'PM_PROVIDER_LOCAL_FAILURE category='+category+b' reconciliation=true'
    assert diagnostic.count(expected)==1,(out,diagnostic)
    assert adapter.TOKEN not in diagnostic
    print(f'OBSERVED D2 case={case} diagnostic=fixed-local-code deduplicated=1',flush=True)
    for endpoint in (runtime/'agent.sock',runtime/'human.sock'):endpoint.unlink()
    d=adapter.daemon(c['local_custody'],c['bootstrap'],runtime,c['vault'],c['provider_socket']);processes.append(d)
    common.wait_path(d,runtime/'agent.sock');common.wait_path(d,runtime/'human.sock')
    time.sleep(.4)
    assert state()[0] in ('waiting_for_human','indeterminate','running') and state()[1] is None
    assert capture.read_bytes().count(marker)==1
    public=common.cli(adapter.AGENT_A,cli,env,['--json','auth','status','--attempt',attempt]);assert public.returncode==0
    other=dict(env,PM_PRIVATE=str(c['b_key']))
    denied=common.cli(adapter.AGENT_B,cli,other,['--json','auth','status','--attempt',attempt],check=False)
    assert denied.returncode!=0 and b'NOT_FOUND' in denied.stdout+denied.stderr,(denied.stdout,denied.stderr)
    cancelled=common.cli(adapter.AGENT_A,cli,env,['--json','auth','cancel','--attempt',attempt]);assert cancelled.returncode==0
    result=json.loads(cancelled.stdout)['result']
    assert result['state'] in ('CANCELLED','INDETERMINATE'),result['state']
    assert capture.read_bytes().count(marker)==1
    assert adapter.TOKEN not in public.stdout+public.stderr+denied.stdout+denied.stderr+cancelled.stdout+cancelled.stderr
    print(f'PASS D2 case={case} restored=reconcile-only ownership=preserved cancel={result["state"]} login-calls=1',flush=True)


def exercise_ssh(c):
    """Reach the SSH reconciliation branch with a native protocol double.

    Human authority/custody/attempt engine and native UIDs remain real; no
    actual external SSH login or SSH-provider acceptance is claimed here.
    """
    common=adapter.common;processes=c['processes'];d=c['d'];runtime=c['runtime']
    key=c['human']/'synthetic-ssh-key'
    common.run_uid(adapter.HUMAN,['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',key])
    enrolled=common.run_uid(adapter.HUMAN,[c['local_custody'],'human-ssh-lab-setup','--profile',c['human_profile'],'--private',c['human_key'],'--socket',runtime/'human.sock'],input=common.wire_fields([adapter.MASTER,key.read_bytes(),pathlib.Path(str(key)+'.pub').read_bytes(),b'CHEF_SYNTHETIC_SSH_PASSWORD']))
    assert enrolled.returncode==0
    sock=c['socket_dir']/'ssh.sock';counter=c['provider']/'ssh.calls'
    code=r"""import os,pathlib,socket,struct,sys
sock,counter=sys.argv[1:];s=socket.socket(socket.AF_UNIX);s.bind(sock);os.chmod(sock,0o666);s.listen()
def rx(c,n):
 out=b''
 while len(out)<n:
  v=c.recv(n-len(out))
  if not v:raise EOFError
  out+=v
 return out
def frame(c):return rx(c,int.from_bytes(rx(c,4),'big'))
def send(c,b):c.sendall(len(b).to_bytes(4,'big')+b)
while True:
 c,_=s.accept()
 try:
  assert struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]==1
  assert frame(c)[0]==4
  send(c,b'\x05'+(0).to_bytes(4,'big'))
  secret=frame(c);assert secret[0]==5
  with pathlib.Path(counter).open('ab') as f:f.write(b'LOGIN\n')
  send(c,b'\x01'+len(b'additional_factor_required').to_bytes(4,'big')+b'additional_factor_required')
 finally:c.close()
"""
    def provider():
        p=common.start_uid(adapter.PROVIDER,[sys.executable,'-c',code,sock,counter]);processes.append(p);common.wait_path(p,sock);return p
    native=provider()
    common.stop(d);processes.remove(d)
    for endpoint in (runtime/'agent.sock',runtime/'human.sock'):endpoint.unlink()
    endpoint=str(sock).removeprefix(os.environ.get('CHEF_RUNTIME_ROOT',''))
    raw=c['config'].read_bytes()
    fields=[b'ssh-server',b'ssh-lab',b'password',endpoint.encode()]
    field=lambda v:len(v).to_bytes(4,'big')+v
    route=field(fields[0])+(1).to_bytes(4,'big')+b''.join(field(v) for v in fields[1:])+adapter.PROVIDER.to_bytes(4,'big')
    c['config'].unlink();c['config'].write_bytes(raw[:81]+(2).to_bytes(2,'big')+raw[83:]+route)
    os.chown(c['config'],adapter.CUSTODIAN,adapter.CUSTODIAN);c['config'].chmod(0o400)
    d=adapter.daemon(c['local_custody'],c['bootstrap'],runtime,c['vault'],c['provider_socket']);processes.append(d)
    common.wait_path(d,runtime/'agent.sock');common.wait_path(d,runtime/'human.sock')
    rows=json.loads(common.cli(adapter.AGENT_A,c['local_cli'],c['env'],['--json','credentials','list']).stdout)['result']['credentials']
    item=next(row['id'] for row in rows if row['destination']=='ssh-lab' and row['type']=='password')
    started=common.cli(adapter.AGENT_A,c['local_cli'],c['env'],['--json','auth','start','--credential-id',item,'--integration-id','ssh-server','--integration-version','1','--method','password','--destination','ssh-lab','--context','ssh-lab','--issued-at',str(time.time_ns()//1000),'--nonce','81'*16])
    attempt=json.loads(started.stdout)['result']['attempt_id']
    def state():
        with sqlite3.connect(f"file:{c['vault']}?mode=ro",uri=True) as db:return db.execute('select state,terminal_at_us from authentication_attempts where attempt_id=?',(bytes.fromhex(attempt),)).fetchone()
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        if state()[0]=='waiting_for_human':break
        time.sleep(.01)
    else:raise AssertionError('SSH double did not pause real attempt')
    assert counter.read_bytes()==b'LOGIN\n'
    common.stop(native);processes.remove(native);sock.unlink();time.sleep(1)
    observed,terminal=state()
    print(f'OBSERVED D2 case=ssh-socket after-outage={observed} terminal={terminal is not None} native-double-calls=1',flush=True)
    assert observed in ('waiting_for_human','indeterminate','running') and terminal is None,('SSH outage invented terminal outcome',observed)
    native=provider();time.sleep(.4)
    assert counter.read_bytes()==b'LOGIN\n'
    cancelled=common.cli(adapter.AGENT_A,c['local_cli'],c['env'],['--json','auth','cancel','--attempt',attempt])
    assert json.loads(cancelled.stdout)['result']['state']=='CANCELLED'
    print('PASS D2 case=ssh-socket restore=reconcile-without-connect cancel=CANCELLED native-double-calls=1 real-ssh=NOT_RUN',flush=True)


def main():
    assert os.environ.get('CHEF_RECONCILIATION_CASE')
    adapter.main()


if __name__=='__main__':main()
