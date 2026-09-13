#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Ticket-22 lost-device recovery and root rotation over real human TLS/RPK."""

import os
import hashlib
import pathlib
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile

from linux_lab import as_uid, expect_unavailable, start_as, stop, wait_for_sockets, wire_fields

CUSTODIAN, HUMAN, AGENT_A, AGENT_B = 1, 2, 3, 4
SOURCE_DEVICE = "21212121212121212121212121212121"
TARGET_DEVICE = "22222222222222222222222222222222"


def create_vault(cli, path, password):
    def identity():
        os.setgroups([]); os.setgid(CUSTODIAN); os.setuid(CUSTODIAN)
    process = subprocess.Popen([cli, "vault", "create", path], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=identity)
    assert process.stdout.readline() == b"Master password (read from stdin):\n"
    process.stdin.write(password + b"\n"); process.stdin.flush()
    assert process.stdout.readline() == b"Confirm master password:\n"
    process.stdin.write(password + b"\n"); process.stdin.flush()
    line = process.stdout.readline()
    assert line.startswith(b"Recovery code (store externally): PMR1-"), line
    recovery = line.split(b": ", 1)[1].strip()
    assert process.stdout.readline() == b"Reintroduce recovery code to confirm the external copy:\n"
    process.stdin.write(recovery + b"\n"); process.stdin.close()
    stdout, stderr = process.stdout.read(), process.stderr.read()
    assert process.wait(timeout=20) == 0 and stderr == b"", (stdout, stderr)
    return recovery


def provision(binary, root):
    state, runtime, human_home, agent_a, agent_b, profiles = [root/name for name in
        ("state", "run", "human", "agent-a", "agent-b", "profiles")]
    for path, uid, mode in ((state,CUSTODIAN,0o700),(runtime,CUSTODIAN,0o755),
        (human_home,HUMAN,0o755),(agent_a,AGENT_A,0o755),(agent_b,AGENT_B,0o755),
        (profiles,0,0o755)):
        path.mkdir(); os.chown(path,uid,uid); path.chmod(mode)
    keys = []
    for uid, home, name in ((CUSTODIAN,state,"server"),(HUMAN,human_home,"human"),
        (AGENT_A,agent_a,"agent-a"),(AGENT_B,agent_b,"agent-b")):
        private, public = home/f"{name}.key", home/f"{name}.pub"
        as_uid(uid,[binary,"keygen","--private",private,"--public",public])
        keys.append((private,public))
    (server_key,server_pub),(human_key,human_pub),(agent_a_key,agent_a_pub),(_,agent_b_pub)=keys
    bootstrap=state/"bootstrap"
    as_uid(CUSTODIAN,[binary,"provision-bootstrap","--path",bootstrap,
        "--server-private",server_key,"--server-public",server_pub,
        "--agent-public",agent_a_pub,"--agent-uid",str(AGENT_A),
        "--human-public",human_pub,"--human-uid",str(HUMAN)])
    profile=profiles/"human.profile"
    subprocess.run([binary,"provision-profile","--path",profile,"--server-public",server_pub,
        "--server-uid",str(CUSTODIAN),"--role","human"],check=True,capture_output=True)
    return {"state":state,"runtime":runtime,"bootstrap":bootstrap,"profile":profile,
        "human_key":human_key,"agent_a_pub":agent_a_pub,"agent_b_pub":agent_b_pub,
        "server_pub":server_pub}


def start(binary, env, vault, device):
    daemon=start_as(CUSTODIAN,[binary,"serve-vault","--bootstrap",env["bootstrap"],
        "--agent-socket",env["runtime"]/"agent.sock","--human-socket",env["runtime"]/"human.sock",
        "--vault",vault,"--device",device])
    wait_for_sockets(daemon,[env["runtime"]/"agent.sock",env["runtime"]/"human.sock"])
    return daemon


def human(binary, env, command, fields, extra=(), ok=True):
    result=as_uid(HUMAN,[binary,command,"--profile",env["profile"],"--private",env["human_key"],
        "--socket",env["runtime"]/"human.sock",*extra],input=wire_fields(fields),check=False)
    if not ok:
        expect_unavailable(result); return result
    assert result.returncode == 0 and result.stderr == b"", result
    if command != "human-authorization":
        assert b"tls-rpk=1 alpn=pm-human/1" in result.stdout, result.stdout
    return result


def root_identity(path):
    db=sqlite3.connect(path)
    row=db.execute("select vault_id,human_public_key from vault_metadata").fetchone(); db.close()
    return row


def authority(path):
    db=sqlite3.connect(path)
    agents=db.execute("select * from agent_authorizations order by subject_id,generation").fetchall()
    delegated=db.execute("select * from delegated_state order by singleton").fetchall()
    credentials=db.execute("select * from credential_authorizations order by item_id").fetchall()
    events=db.execute("select event_digest,event from authority_events order by event_digest").fetchall()
    items=db.execute("select count(*) from vault_items").fetchone()[0]
    db.close(); return agents,delegated,credentials,events,items


def rotate_recovery(binary, env, password):
    def identity():
        os.setgroups([]); os.setgid(HUMAN); os.setuid(HUMAN)
    process=subprocess.Popen([binary,"human-recovery-rotate","--profile",env["profile"],
        "--private",env["human_key"],"--socket",env["runtime"]/"human.sock"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=identity)
    process.stdin.write(wire_fields([password])); process.stdin.flush()
    line=process.stdout.readline()
    assert line.startswith(b"Recovery code (store externally): PMR1-"), line
    code=line.split(b": ",1)[1].strip()
    assert process.stdout.readline()==b"Reintroduce recovery code to confirm the external copy:\n"
    process.stdin.write(wire_fields([code])); process.stdin.close()
    stdout,stderr=process.stdout.read(),process.stderr.read()
    assert process.wait(timeout=20)==0 and stderr==b"",(stdout,stderr)
    assert b"receipt-replay=1" in stdout and b"old-backups=remain-valid" in stdout
    assert b"exposed copies remain usable" in stdout
    return code


def main():
    assert os.geteuid()==0 and len(sys.argv)==3
    source_binary,source_cli=(pathlib.Path(value).resolve() for value in sys.argv[1:])
    root=pathlib.Path(tempfile.mkdtemp(prefix="pm-recovery-linux-lab-")); daemons=[]
    try:
        root.chmod(0o711); binary,cli=root/"pm-custody",root/"pm"
        shutil.copyfile(source_binary,binary); shutil.copyfile(source_cli,cli)
        binary.chmod(0o755); cli.chmod(0o755)
        source_root,target_root=root/"lost",root/"healthy"
        source_root.mkdir(); target_root.mkdir(); source_root.chmod(0o711); target_root.chmod(0o711)
        source,target=provision(binary,source_root),provision(binary,target_root)
        source_vault=source["state"]/"vault.sqlite3"; target_vault=target["state"]/"vault.sqlite3"
        source_password=b"synthetic ticket22 lost master"; target_password=b"synthetic ticket22 healthy master"
        rotated_password=b"synthetic ticket22 rotated healthy master"
        source_recovery=create_vault(cli,source_vault,source_password)
        old_target_recovery=create_vault(cli,target_vault,target_password)
        source_identity=root_identity(source_vault); target_identity=root_identity(target_vault)
        assert source_identity != target_identity

        daemon=start(binary,source,source_vault,SOURCE_DEVICE); daemons.append(daemon)
        exports=source_root/"exports"; exports.mkdir(); os.chown(exports,HUMAN,HUMAN); exports.chmod(0o700)
        observed=human(binary,source,"human-backup-exercise",[source_password],("--output-dir",exports))
        assert b"types=7" in observed.stdout
        source_archive=exports/"ticket21-backup.pmb1"; assert source_archive.stat().st_size>2*1024*1024
        archive_hash=hashlib.sha256(source_archive.read_bytes()).digest()
        stop(daemons.pop());
        archive=target_root/"recovery-input.pmb1"
        shutil.copyfile(source_archive,archive); os.chown(archive,HUMAN,HUMAN); archive.chmod(0o600)
        shutil.rmtree(source_root)
        assert not source_root.exists() and hashlib.sha256(archive.read_bytes()).digest()==archive_hash

        daemon=start(binary,target,target_vault,TARGET_DEVICE); daemons.append(daemon)
        human(binary,target,"human-authorization",[target_password,target["agent_a_pub"].read_bytes(),
            target["agent_b_pub"].read_bytes()],("--action","setup"))
        human(binary,target,"human-authorization",[target_password],("--action","resume-revoke-a"))
        before=authority(target_vault); assert any(row[-1]=="revoked" for row in before[0])
        recovered=human(binary,target,"human-recovery-restore",[target_password,source_recovery],
            ("--archive",archive))
        assert b"source-keyring=absent" in recovered.stdout and b"does not revoke exposed backups" in recovered.stdout
        after=authority(target_vault)
        assert after[:3]==before[:3]
        assert set(before[3]).issubset(after[3]) and len(after[3])>len(before[3])
        assert after[4]==before[4]+8 and root_identity(target_vault)==target_identity

        corrupt=target_root/"corrupt.pmb1"; data=bytearray(archive.read_bytes()); data[len(data)//2]^=1
        corrupt.write_bytes(data); os.chown(corrupt,HUMAN,HUMAN); corrupt.chmod(0o600)
        snapshot=authority(target_vault)
        human(binary,target,"human-recovery-restore",[target_password,source_recovery],
            ("--archive",corrupt),ok=False)
        human(binary,target,"human-recovery-restore",[target_password,old_target_recovery],
            ("--archive",archive),ok=False)
        assert authority(target_vault)==snapshot
        assert hashlib.sha256(archive.read_bytes()).digest()==archive_hash

        rotated=human(binary,target,"human-master-rotate",[target_password,rotated_password])
        assert b"receipt-replay=1" in rotated.stdout and b"old-backups=historical-paths" in rotated.stdout
        assert b"not erased or remotely invalidated" in rotated.stdout
        human(binary,target,"human-authorization",[target_password],("--action","suspend"),ok=False)
        human(binary,target,"human-authorization",[rotated_password],("--action","suspend"))
        new_recovery=rotate_recovery(binary,target,rotated_password)
        assert new_recovery != old_target_recovery
        assert root_identity(target_vault)==target_identity

        stop(daemons.pop())
        daemon=start(binary,target,target_vault,TARGET_DEVICE); daemons.append(daemon)
        human(binary,target,"human-authorization",[target_password],("--action","suspend"),ok=False)
        human(binary,target,"human-authorization",[rotated_password],("--action","suspend"))
        stop(daemons.pop())
        for path in target["state"].iterdir():
            if path.is_file():
                raw=path.read_bytes()
                for secret in (source_recovery,old_target_recovery,new_recovery,source_password,
                    target_password,rotated_password,b"ticket22-recovery-canary"):
                    assert secret not in raw
        assert stat.S_IMODE(target_vault.stat().st_mode)==0o600
        print("PASS recovery-e2e tls=rpk+alpn/pm-human/1 clean-env=1 source-keyring=absent "
            "fresh-vault+human+device=1 all-types+history+attachments=restored authority+revocations=current "
            "wrong-key+corrupt=atomic master+recovery-rotation=verified signed+audit+receipt=1 restart=durable "
            "old-backups=remain-historical external-credentials+exposed-copies=not-revoked raw-canaries=absent")
    finally:
        for daemon in daemons:
            if daemon.poll() is None: stop(daemon)
        shutil.rmtree(root,ignore_errors=True)


if __name__=="__main__": main()
