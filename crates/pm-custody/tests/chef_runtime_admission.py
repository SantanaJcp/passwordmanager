#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""D1: ordinary daemon, authenticated four-per-RPK, distinct/shared UID cases."""
import os,pathlib,select,shutil,sqlite3,subprocess,sys,tempfile
from linux_lab import as_uid,create_vault,expect_unavailable,start_as,wait_for_sockets
from tui_access_lab import AGENT_A,AGENT_B,AGENT_C,CUSTODIAN,HUMAN,PROVIDER,LAB_PARENT,LAB_PREFIX,authorization,cleanup_owned_root,discover,provision
DEVICE='44444444444444444444444444444444'


def main():
    assert os.geteuid()==0
    source,cli_source=map(pathlib.Path,sys.argv[1:3])
    client=source.parent/'examples/chef_runtime_open_channel'
    for shared in ((True,) if os.environ.get("CHEF_FAIRNESS_ONLY_SHARED")=="1" else (False,True)):
        root=pathlib.Path(tempfile.mkdtemp(prefix=LAB_PREFIX,dir=LAB_PARENT));daemon=None;held=[]
        try:
            root.chmod(0o711)
            binary,cli=root/'pm-custody',root/'pm'
            for src,dst in ((source,binary),(cli_source,cli)):shutil.copyfile(src,dst);dst.chmod(0o755)
            for name,uid,mode in [('state',CUSTODIAN,0o700),('run',CUSTODIAN,0o755),('human',HUMAN,0o755),('profiles',HUMAN,0o755),('provider',PROVIDER,0o755),*[(f'agent-{uid}',uid,0o755) for uid in (AGENT_A,AGENT_B,AGENT_C)]]:
                p=root/name;p.mkdir();os.chown(p,uid,uid);p.chmod(mode)
            state,runtime=root/'state',root/'run'
            sk,sp=state/'server.key',state/'server.pub';hk,hp=root/'human/h.key',root/'human/h.pub'
            ak,ap=root/'agent-3/a.key',root/'agent-3/a.pub';bk,bp=root/'agent-4/b.key',root/'agent-4/b.pub'
            for uid,key,pub in ((CUSTODIAN,sk,sp),(HUMAN,hk,hp),(AGENT_A,ak,ap),(AGENT_B,bk,bp)):
                as_uid(uid,[binary,'keygen','--private',key,'--public',pub])
            bootstrap=state/'bootstrap';provision(binary,bootstrap,sk,sp,ap,AGENT_A,hp)
            aprofile,hprofile=root/'profiles/a.profile',root/'profiles/h.profile'
            for role,out in (('agent',aprofile),('human',hprofile)):
                as_uid(HUMAN,[binary,'provision-profile','--path',out,'--server-public',sp,'--server-uid',str(CUSTODIAN),'--role',role])
            vault=state/'vault.sqlite3';password=create_vault(cli,vault)
            def launch():
                for p in (runtime/'agent.sock',runtime/'human.sock'):p.unlink(missing_ok=True)
                process=start_as(CUSTODIAN,[binary,'serve-vault','--bootstrap',bootstrap,'--agent-socket',runtime/'agent.sock','--human-socket',runtime/'human.sock','--vault',vault,'--device',DEVICE])
                wait_for_sockets(process,[runtime/'agent.sock',runtime/'human.sock']);return process
            daemon=launch();authorization(binary,hk,hprofile,runtime/'human.sock',password,'setup',ap.read_bytes(),bp.read_bytes())
            daemon.terminate();daemon.communicate(timeout=5);daemon=None
            with sqlite3.connect(vault) as db:vid=db.execute('select vault_id from vault_metadata').fetchone()[0]
            uid_b=AGENT_A if shared else AGENT_B
            key_b=bk
            if shared:
                key_b=root/'agent-3/b.key';shutil.copyfile(bk,key_b);os.chown(key_b,AGENT_A,AGENT_A);key_b.chmod(0o400)
            registry=pathlib.Path(str(vault)+'.agent-registry')
            registry.write_bytes(b'PMAR1'+vid+bytes.fromhex(DEVICE)+sp.read_bytes()+(2).to_bytes(2,'big')+ap.read_bytes()+AGENT_A.to_bytes(4,'big')+bp.read_bytes()+uid_b.to_bytes(4,'big'))
            os.chown(registry,CUSTODIAN,CUSTODIAN);registry.chmod(0o400)
            daemon=launch()
            baseline=discover(binary,AGENT_A,ak,aprofile,runtime/'agent.sock')
            assert discover(binary,uid_b,key_b,aprofile,runtime/'agent.sock')==baseline
            local_client=root/'agent-3/hold';shutil.copyfile(client,local_client);local_client.chmod(0o555)
            def hold(uid,key):
                p=start_as(uid,[local_client,aprofile,key,runtime/'agent.sock'],stdin=subprocess.PIPE)
                held.append(p)
                ready,_,_=select.select([p.stdout],[],[],10)
                assert ready and p.stdout.readline()==b'READY\n',('authenticated hold failed',p.poll())
                return p
            for _ in range(4):hold(AGENT_A,ak)
            discover(binary,AGENT_A,ak,aprofile,runtime/'agent.sock',allowed=False)
            # Exact reported regression: B must work while all four A channels
            # remain authenticated and live. Sharing native UID is not identity.
            assert discover(binary,uid_b,key_b,aprofile,runtime/'agent.sock')==baseline
            for _ in range(4):hold(uid_b,key_b)
            discover(binary,uid_b,key_b,aprofile,runtime/'agent.sock',allowed=False)
            print(f'OBSERVED D1 shared-uid={int(shared)} A=4 B=4 fifth-each=denied authenticated-rpk=real',flush=True)
            # Release these authenticated application channels, then exercise
            # completed TLS with no application magic. The RPK budget must
            # already apply; waiting for magic would let one shared UID key take
            # the other key's native slots.
            for p in held:
                p.terminate();p.communicate(timeout=5)
            held=[]
            for _ in range(4):
                p=start_as(AGENT_A,[local_client,aprofile,ak,runtime/'agent.sock','tls-only'],stdin=subprocess.PIPE);held.append(p)
                ready,_,_=select.select([p.stdout],[],[],10);assert ready and p.stdout.readline()==b'READY\n'
            discover(binary,AGENT_A,ak,aprofile,runtime/'agent.sock',allowed=False)
            if shared:
                rejected=as_uid(AGENT_A,[local_client,aprofile,ak,runtime/'agent.sock','tls-quota-denied'])
                assert rejected.stdout==b'PASS tls-quota-denied no-application-magic=1\n' and rejected.stderr==b''
                print('OBSERVED D1 shared-uid=1 fifth-A-no-magic=closed-before-application-read',flush=True)
            assert discover(binary,uid_b,key_b,aprofile,runtime/'agent.sock')==baseline
            for p in held:p.terminate();p.communicate(timeout=5)
            held=[]
            for _ in range(4):hold(AGENT_A,ak)
            for _ in range(4):hold(uid_b,key_b)
            print(f'OBSERVED D1 shared-uid={int(shared)} tls-without-magic=A4 fifthA-denied B-admitted',flush=True)
            first=held.pop(0);first.terminate();out,err=first.communicate(timeout=5);assert first.returncode==-15 and out==err==b''
            assert discover(binary,AGENT_A,ak,aprofile,runtime/'agent.sock')==baseline
            # Revocation across the live A channels returns AGENT_REVOKED on
            # each same TLS channel and drops the authenticated/native permits.
            authorization(binary,hk,hprofile,runtime/'human.sock',password,'resume-revoke-a')
            for p in held[:3]:
                out,err=p.communicate(b'x',timeout=15)
                assert p.returncode==0 and b'PASS hot-revoke' in out and err==b'',(out,err)
            held=held[3:]
            # B remains live: remove one B channel to free its own slot.
            p=held.pop();p.terminate();p.communicate(timeout=5)
            assert discover(binary,uid_b,key_b,aprofile,runtime/'agent.sock')==baseline
            print(f'OBSERVED D1 shared-uid={int(shared)} disconnect+hot-revoke=permits-released B=independent',flush=True)
            # Stop the service with B's authenticated channels still open;
            # restart must reconstruct empty finite budgets, not retain permits.
            daemon.terminate();daemon.communicate(timeout=5);daemon=None
            for p in held:p.terminate();p.communicate(timeout=5)
            held=[];daemon=launch()
            assert discover(binary,uid_b,key_b,aprofile,runtime/'agent.sock')==baseline
            for _ in range(4):hold(uid_b,key_b)
            discover(binary,uid_b,key_b,aprofile,runtime/'agent.sock',allowed=False)
            print(f'OBSERVED D1 shared-uid={int(shared)} stop-with-open-channels+restart B-budget=4-no-stale-permits',flush=True)
        finally:
            errors=[]
            for p in held:
                if p.poll() is None:
                    try:p.terminate();p.communicate(timeout=5)
                    except BaseException as e:errors.append(e)
            if daemon is not None and daemon.poll() is None:
                try:daemon.terminate();out,err=daemon.communicate(timeout=5);assert out==err==b''
                except BaseException as e:errors.append(e)
            try:cleanup_owned_root(root)
            except BaseException as e:errors.append(e)
            if errors:raise BaseExceptionGroup('D1 cleanup failed',errors)
        print(f'PASS D1 shared-uid={int(shared)} cleanup=verified',flush=True)
