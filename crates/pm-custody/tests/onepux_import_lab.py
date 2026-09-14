#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-20 1PUX v3 import through the real human TLS/RPK/ALPN service."""
import hashlib, json, os, pathlib, shutil, sqlite3, subprocess, sys, tempfile, time, zipfile
from linux_lab import as_uid, create_vault, expect_unavailable, start_as, stop, wait_for_sockets, wire_fields
CUSTODIAN, HUMAN, AGENT = 1, 2, 3
DEVICE = "20202020202020202020202020202020"

def start(binary, bootstrap, runtime, vault):
    for socket in (runtime/"agent.sock", runtime/"human.sock"): socket.unlink(missing_ok=True)
    daemon=start_as(CUSTODIAN,[binary,"serve-vault","--bootstrap",bootstrap,"--agent-socket",runtime/"agent.sock","--human-socket",runtime/"human.sock","--vault",vault,"--device",DEVICE])
    wait_for_sockets(daemon,[runtime/"agent.sock",runtime/"human.sock"]); return daemon

def run_import(binary,key,profile,socket,password,source,ok=True,response_loss=False):
    command=[binary,"human-1pux-import","--profile",profile,"--private",key,"--socket",socket,"--source",source,"--confirm"]
    if response_loss: command.append("--simulate-response-loss")
    result=as_uid(HUMAN,command,input=wire_fields([password]),check=False)
    if not ok: expect_unavailable(result); return b""
    assert result.returncode == 0 and result.stderr == b"", result
    assert result.stdout.startswith(b"PASS 1pux-import version=3 "), result.stdout
    assert b"tls-rpk=1 alpn=pm-human/1 signed=1 receipt-replay=1" in result.stdout
    assert b"streamed-attachments=1 source-fd=scm-rights private-source=0400 auto-enable=0" in result.stdout
    return result.stdout

def archive(path, account, document, content, traversal=False):
    data={"accounts":[{"attrs":{"uuid":account},"vaults":[{"attrs":{"uuid":"vault-public"},"items":[
      {"uuid":f"login-{account}","state":"archived","favIndex":1,"categoryUuid":"001","details":{"loginFields":[{"designation":"username","value":"synthetic-user"},{"designation":"password","value":f"synthetic-ticket20-{account}-secret"}],"notesPlain":"synthetic public note","passwordHistory":[{"value":"synthetic-prior","time":1}]},"overview":{"title":f"Login {account}","url":"https://ticket20.invalid","tags":["imported"]}},
      {"uuid":f"item-{document}","categoryUuid":"004","details":{"documentAttributes":{"fileName":"large.bin","documentId":document,"decryptedSize":len(content)}},"overview":{"title":"Large file"}}
    ]}]}]}
    with zipfile.ZipFile(path,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=6) as out:
        out.writestr("export.attributes",json.dumps({"version":3,"description":"synthetic"},separators=(",",":")))
        out.writestr("export.data",json.dumps(data,separators=(",",":"),ensure_ascii=False))
        out.writestr(f"files/{document}___ignored-name.bin",content)
        if traversal: out.writestr("../ticket20-outside-canary",b"escape")
    os.chown(path,HUMAN,HUMAN); path.chmod(0o400)

def pseudo_random(length):
    state=0x201A1BC3D4E5F607; out=bytearray(length)
    for i in range(length):
        state ^= (state << 13) & 0xffffffffffffffff; state ^= state >> 7; state ^= (state << 17) & 0xffffffffffffffff
        out[i]=state & 0xff
    return bytes(out)

def counts(vault):
    db=sqlite3.connect(vault)
    values=tuple(db.execute(f"select count(*) from {table}").fetchone()[0] for table in ("vault_items","revision_parts","attachment_streams","attachment_stream_chunks","authority_events","outbox","human_receipts","encrypted_audit_records","import_reports"))
    db.close(); return values

def assert_only_human_unlock_changed(before, after):
    assert after[:7] == before[:7], (before, after)
    assert after[7] == before[7] + 1, (before, after)
    assert after[8:] == before[8:], (before, after)

def main():
    assert pathlib.Path('/proc/self/uid_map').exists() and len(sys.argv)==3
    source_binary, source_cli=map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:])
    root=pathlib.Path(tempfile.mkdtemp(prefix='pm-1pux-import-linux-lab-'))
    try:
        root.chmod(0o711); binary,cli=root/'pm-custody',root/'pm'
        shutil.copyfile(source_binary,binary); binary.chmod(0o755); shutil.copyfile(source_cli,cli); cli.chmod(0o755)
        state,runtime,human_home,agent_home,profiles,fixtures=[root/n for n in ('state','run','human','agent','profiles','fixtures')]
        for path,uid,mode in [(state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),(human_home,HUMAN,0o755),(agent_home,AGENT,0o755),(profiles,0,0o755),(fixtures,HUMAN,0o700)]: path.mkdir(); os.chown(path,uid,uid); path.chmod(mode)
        server_key,server_pub=state/'server.key',state/'server.pub'; human_key,human_pub=human_home/'human.key',human_home/'human.pub'; agent_key,agent_pub=agent_home/'agent.key',agent_home/'agent.pub'
        for uid,private,public in [(CUSTODIAN,server_key,server_pub),(HUMAN,human_key,human_pub),(AGENT,agent_key,agent_pub)]: as_uid(uid,[binary,'keygen','--private',private,'--public',public])
        bootstrap=state/'bootstrap'; as_uid(CUSTODIAN,[binary,'provision-bootstrap','--path',bootstrap,'--server-private',server_key,'--server-public',server_pub,'--agent-public',agent_pub,'--agent-uid',str(AGENT),'--human-public',human_pub,'--human-uid',str(HUMAN)])
        human_profile=profiles/'human.profile'; subprocess.run([binary,'provision-profile','--path',human_profile,'--server-public',server_pub,'--server-uid',str(CUSTODIAN),'--role','human'],check=True,capture_output=True)
        vault=state/'vault.sqlite3'; password=create_vault(cli,vault)
        content=pseudo_random(20*1024*1024+17)
        valid=fixtures/'valid.1pux'; archive(valid,'account-public','document-public',content)
        original=hashlib.sha256(valid.read_bytes()).digest()
        daemon=start(binary,bootstrap,runtime,vault)
        output=run_import(binary,human_key,human_profile,runtime/'human.sock',password,valid,response_loss=True)
        assert b'total=2 new=2' in output and valid.stat().st_size > 18*1024*1024
        db=sqlite3.connect(vault)
        assert db.execute("select count(*) from attachment_streams").fetchone()==(1,)
        assert db.execute("select count(*) from attachment_stream_chunks").fetchone()[0] == 21
        assert db.execute("select count(*) from attachment_parts").fetchone()==(0,)
        assert db.execute("select count(*) from credential_authorizations").fetchone()==(0,)
        assert db.execute("select source from import_reports").fetchone()==('1pux',)
        db.close()
        crash=fixtures/'crash.1pux'; archive(crash,'account-crash','document-crash',content)
        before=counts(vault); wal=pathlib.Path(str(vault)+'-wal'); initial_wal=wal.stat().st_size if wal.exists() else 0
        command=[binary,"human-1pux-import","--profile",human_profile,"--private",human_key,"--socket",runtime/'human.sock',"--source",crash,"--confirm"]
        client=start_as(HUMAN,command,stdin=subprocess.PIPE); client.stdin.write(wire_fields([password])); client.stdin.close(); client.stdin=None
        deadline=time.monotonic()+30; saw_descriptor=False; saw_staging=False
        while time.monotonic()<deadline:
            if client.poll() is not None: raise AssertionError(('import completed before crash seam',client.communicate()))
            try:
                saw_descriptor |= any(os.readlink(fd)==str(crash) for fd in pathlib.Path(f'/proc/{daemon.pid}/fd').iterdir())
            except (FileNotFoundError,PermissionError): pass
            saw_staging |= wal.exists() and wal.stat().st_size > initial_wal + 1024*1024
            if saw_descriptor and saw_staging: break
            time.sleep(0.01)
        assert saw_descriptor and saw_staging
        stop(daemon); stdout,stderr=client.communicate(timeout=5); assert client.returncode != 0 and stdout==b'' and stderr==b'CUSTODY_UNAVAILABLE\n',(client.returncode,stdout,stderr)
        assert_only_human_unlock_changed(before, counts(vault))
        daemon=start(binary,bootstrap,runtime,vault)
        assert b'total=2 new=2' in run_import(binary,human_key,human_profile,runtime/'human.sock',password,crash)
        hostile=fixtures/'traversal.1pux'; archive(hostile,'account-hostile','document-hostile',b'hostile',traversal=True)
        before=counts(vault); run_import(binary,human_key,human_profile,runtime/'human.sock',password,hostile,ok=False); assert_only_human_unlock_changed(before, counts(vault))
        assert not (root/'ticket20-outside-canary').exists()
        linked=fixtures/'linked.1pux'; linked.symlink_to(valid); os.lchown(linked,HUMAN,HUMAN); run_import(binary,human_key,human_profile,runtime/'human.sock',password,linked,ok=False)
        atomic=fixtures/'atomic.1pux'; archive(atomic,'account-atomic','document-atomic',pseudo_random(1024*1024+3))
        before=counts(vault)
        db=sqlite3.connect(vault); db.execute(f"create trigger fail_ticket20_public_audit before insert on encrypted_audit_records when (select count(*) from encrypted_audit_records) > {before[7]} begin select raise(abort,'ticket20 audit'); end"); db.commit(); db.close()
        run_import(binary,human_key,human_profile,runtime/'human.sock',password,atomic,ok=False); assert_only_human_unlock_changed(before, counts(vault))
        db=sqlite3.connect(vault); db.execute('drop trigger fail_ticket20_public_audit'); db.commit(); db.close()
        assert b'total=2 new=2' in run_import(binary,human_key,human_profile,runtime/'human.sock',password,atomic)
        stop(daemon); daemon=start(binary,bootstrap,runtime,vault)
        duplicate=run_import(binary,human_key,human_profile,runtime/'human.sock',password,valid); assert b'new=0' in duplicate and b'skipped_exact=2' in duplicate
        stop(daemon)
        assert hashlib.sha256(valid.read_bytes()).digest()==original
        for path in state.iterdir():
            if path.is_file():
                data=path.read_bytes()
                for canary in (b'synthetic-ticket20-account-public-secret',b'synthetic-ticket20-account-atomic-secret',content[:32]): assert canary not in data
        print('PASS 1pux-import-e2e tls-rpk=1 multi-uid=1 archive-over-frame=1 attachment-streamed=21chunks source-fd=scm-rights private-source=0400 source-unchanged=1 process-crash=staging-rollback traversal=no-effect symlink=rejected audit-failure=atomic response-loss=recovered restart=durable exact-duplicate=explicit-skip plaintext-canaries=absent auto-enable=0')
    finally: shutil.rmtree(root,ignore_errors=True)
if __name__=='__main__': main()
