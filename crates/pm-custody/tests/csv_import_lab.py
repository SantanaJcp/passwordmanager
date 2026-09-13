#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-19 CSV import through the real human TLS/RPK/ALPN service."""
import hashlib, os, pathlib, shutil, sqlite3, stat, subprocess, sys, tempfile
from linux_lab import as_uid, create_vault, expect_unavailable, start_as, stop, wait_for_sockets, wire_fields
CUSTODIAN, HUMAN, AGENT = 1, 2, 3
DEVICE = "19191919191919191919191919191919"

def start(binary, bootstrap, runtime, vault):
    for socket in (runtime/"agent.sock", runtime/"human.sock"): socket.unlink(missing_ok=True)
    daemon=start_as(CUSTODIAN,[binary,"serve-vault","--bootstrap",bootstrap,"--agent-socket",runtime/"agent.sock","--human-socket",runtime/"human.sock","--vault",vault,"--device",DEVICE])
    wait_for_sockets(daemon,[runtime/"agent.sock",runtime/"human.sock"]); return daemon

def run_import(binary,key,profile,socket,password,source,format,ok=True,response_loss=False):
    command=[binary,"human-csv-import","--profile",profile,"--private",key,"--socket",socket,"--source",source,"--format",format,"--confirm"]
    if response_loss: command.append("--simulate-response-loss")
    result=as_uid(HUMAN,command,input=wire_fields([password]),check=False)
    if not ok: expect_unavailable(result); return b""
    assert result.returncode == 0 and result.stderr == b"", result
    assert result.stdout.startswith(f"PASS csv-import format={format} ".encode()), result.stdout
    assert b"tls-rpk=1 alpn=pm-human/1 signed=1 receipt-replay=1" in result.stdout
    return result.stdout

def main():
    assert pathlib.Path('/proc/self/uid_map').exists() and len(sys.argv)==3
    source_binary, source_cli=map(lambda p:pathlib.Path(p).resolve(),sys.argv[1:])
    root=pathlib.Path(tempfile.mkdtemp(prefix='pm-csv-import-linux-lab-'))
    try:
        root.chmod(0o711); binary,cli=root/'pm-custody',root/'pm'
        shutil.copyfile(source_binary,binary); binary.chmod(0o755); shutil.copyfile(source_cli,cli); cli.chmod(0o755)
        state,runtime,human_home,agent_home,profiles=[root/n for n in ('state','run','human','agent','profiles')]
        for path,uid,mode in [(state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),(human_home,HUMAN,0o755),(agent_home,AGENT,0o755),(profiles,0,0o755)]: path.mkdir(); os.chown(path,uid,uid); path.chmod(mode)
        server_key,server_pub=state/'server.key',state/'server.pub'; human_key,human_pub=human_home/'human.key',human_home/'human.pub'; agent_key,agent_pub=agent_home/'agent.key',agent_home/'agent.pub'
        for uid,private,public in [(CUSTODIAN,server_key,server_pub),(HUMAN,human_key,human_pub),(AGENT,agent_key,agent_pub)]: as_uid(uid,[binary,'keygen','--private',private,'--public',public])
        bootstrap=state/'bootstrap'
        as_uid(CUSTODIAN,[binary,'provision-bootstrap','--path',bootstrap,'--server-private',server_key,'--server-public',server_pub,'--agent-public',agent_pub,'--agent-uid',str(AGENT),'--human-public',human_pub,'--human-uid',str(HUMAN)])
        human_profile=profiles/'human.profile'
        subprocess.run([binary,'provision-profile','--path',human_profile,'--server-public',server_pub,'--server-uid',str(CUSTODIAN),'--role','human'],check=True,capture_output=True)
        vault=state/'vault.sqlite3'; password=create_vault(cli,vault)
        chrome=human_home/'chrome.csv'; apple=human_home/'apple.csv'; mapped=human_home/'mapped.csv'; malformed=human_home/'malformed.csv'; atomic=human_home/'atomic.csv'
        chrome.write_text('name,url,username,password,note,Future Column\r\n"Cuenta, 🔐",https://chrome.invalid,u,synthetic-chrome-canary,"line 1\nline 2",opaque\r\n',encoding='utf-8')
        apple.write_text('Title,URL,Username,Password,Notes,OTPAuth,Unknown\nApple 🍎,https://apple.invalid,a,synthetic-apple-canary,note,otpauth://totp/Issuer:acct?secret=JBSWY3DPEHPK3PXP,keep\n',encoding='utf-8')
        rows=['name,url,username,password,note\n']+[f'row-{i},https://page.invalid/{i},u{i},synthetic-page-{i},n\n' for i in range(70)]
        mapped.write_text('title;user;site;secret;opaque\nMapeable;ñ;https://mapped.invalid;synthetic-mapped-canary;未知\n',encoding='utf-8')
        malformed.write_bytes(b'name,url,username,password\nBad,https://bad.invalid,u,"unterminated')
        atomic.write_text('name,url,username,password,note\nAtomic,https://atomic.invalid,u,synthetic-atomic-canary,n\n',encoding='utf-8')
        for path in (chrome,apple,mapped,malformed,atomic): os.chown(path,HUMAN,HUMAN); path.chmod(0o400)
        hashes={p:hashlib.sha256(p.read_bytes()).digest() for p in (chrome,apple,mapped)}
        daemon=start(binary,bootstrap,runtime,vault)
        assert b'total=1 new=1' in run_import(binary,human_key,human_profile,runtime/'human.sock',password,chrome,'chrome')
        assert b'total=1 new=1' in run_import(binary,human_key,human_profile,runtime/'human.sock',password,apple,'apple')
        assert b'total=1 new=1' in run_import(binary,human_key,human_profile,runtime/'human.sock',password,mapped,'mappable',response_loss=True)
        source_link=human_home/'source-link.csv'; source_link.symlink_to(chrome); os.lchown(source_link,HUMAN,HUMAN)
        run_import(binary,human_key,human_profile,runtime/'human.sock',password,source_link,'chrome',ok=False)
        database=sqlite3.connect(vault); before=tuple(database.execute(f'select count(*) from {t}').fetchone()[0] for t in ('vault_items','authority_events','outbox','human_receipts','encrypted_audit_records','import_reports'))
        database.execute("create trigger fail_ticket19_public_audit before insert on encrypted_audit_records begin select raise(abort,'ticket19 audit'); end"); database.commit(); database.close()
        run_import(binary,human_key,human_profile,runtime/'human.sock',password,atomic,'chrome',ok=False)
        database=sqlite3.connect(vault); after=tuple(database.execute(f'select count(*) from {t}').fetchone()[0] for t in ('vault_items','authority_events','outbox','human_receipts','encrypted_audit_records','import_reports')); assert before==after
        database.execute('drop trigger fail_ticket19_public_audit'); database.commit(); database.close()
        run_import(binary,human_key,human_profile,runtime/'human.sock',password,malformed,'chrome',ok=False)
        stop(daemon); daemon=start(binary,bootstrap,runtime,vault)
        duplicate=run_import(binary,human_key,human_profile,runtime/'human.sock',password,chrome,'chrome'); assert b'new=0' in duplicate and b'skipped_exact=1' in duplicate
        paged=human_home/'paged.csv'; paged.write_text(''.join(rows),encoding='utf-8'); os.chown(paged,HUMAN,HUMAN); paged.chmod(0o400)
        paged_result=run_import(binary,human_key,human_profile,runtime/'human.sock',password,paged,'chrome')
        assert b'total=70 new=70' in paged_result and b'pages=2' in paged_result
        stop(daemon)
        database=sqlite3.connect(vault); assert database.execute('select count(*) from credential_authorizations').fetchone()==(0,); assert database.execute("select count(*) from authority_events where kind='item-revision'").fetchone()[0] == 73; database.close()
        for p,digest in hashes.items(): assert hashlib.sha256(p.read_bytes()).digest()==digest
        for path in state.iterdir():
            if path.is_file():
                data=path.read_bytes()
                for canary in (b'synthetic-chrome-canary',b'synthetic-apple-canary',b'synthetic-mapped-canary',b'synthetic-atomic-canary'): assert canary not in data
        print('PASS csv-import-e2e chrome=1 apple-explicit=1 mappable=1 unicode=1 unknown-preserved=1 malformed=no-effect symlink=rejected audit-failure=atomic response-loss=recovered restart=durable duplicate=explicit-skip paginated=2 source-unchanged=1 raw-canaries=absent')
    finally: shutil.rmtree(root,ignore_errors=True)
if __name__=='__main__': main()
