# SPDX-License-Identifier: AGPL-3.0-only
"""Full25 native keyboard driver. Public command calls are fixture setup only."""

import hashlib
import json
import os
import pathlib
import plistlib
import re
import sys
import zipfile

from tui_migration_fixtures import onepux, pairing_namespace
from tui_operations_lab import ClosingEndpoint

REMOTE_DEVICE = "25252525252525252525252525252525"
SYNC_LABEL = "com.santanajcp.passwordmanager.ticket26.sync"
REMOTE_LABEL = "com.santanajcp.passwordmanager.ticket26.remote"
NEW_PASSWORD = b"synthetic-ticket26-rotated-master"


def source_digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").digest()


def snapshot(m, session=None):
    code = """import hashlib,json,sqlite3,sys
with sqlite3.connect('file:'+sys.argv[1]+'?mode=ro', uri=True) as db:
 state={t:db.execute('select count(*) from '+t).fetchone()[0]
  for t in ('vault_items','revision_parts','authority_events','audit_purge_ranges')}
 rows=db.execute("select event_digest from authority_events where kind not in ('item-revision','trash') order by event_digest")
 state['authority_state']=hashlib.sha256(b''.join(row[0] for row in rows)).hexdigest()
 print(json.dumps(state))
"""
    command = [sys.executable, "-c", code, m.STATE / "vault.sqlite3"]
    result = m.sudo(command) if session is None else session.run_sudo_while_draining(command)
    assert result.returncode == 0 and result.stderr == b"", "durable fixture observer failed"
    return json.loads(result.stdout)


def submit(session, value, *, hidden=False):
    """Synchronize the visible suffix of long input using the existing UI grammar."""
    if hidden:
        session.send_text(value, enter=True, hidden=True)
        return
    mark = session.mark()
    session.send_text(value)
    session.wait_text(value[-48:], since=mark)
    session.send_key("enter")


def operation(session, menu, number, prompt, value=None, *, hidden=False):
    mark = session.mark()
    session.send_key(menu)
    session.wait_text({"m": "Migration:", "b": "Backup/recovery:",
                       "y": "Devices/sync:", "z": "Audit:"}[menu], since=mark)
    mark = session.mark()
    session.send_key(number)
    session.wait_text(prompt, since=mark)
    if value is not None:
        submit(session, str(value), hidden=hidden)
    return mark


def lock(m, session):
    session.send_key("l")
    assert session.wait_exit(timeout=8) == 0
    m.close_session_preserving_primary(session)


def start(m, binary, profile, private, endpoint, *, password=None, idle=30):
    session = m.start_macos_tui(binary, profile, private, endpoint,
                              idle=idle, reveal=10, copy=2,
                              password=m.PASSWORD if password is None else password)
    mark = session.mark()
    session.resize(240, 30)
    session.wait_text("Items (selection is metadata only)", since=mark)
    return session


def launch(m, label, arguments, scratch, labels, session=None):
    path = scratch / (label + ".plist")
    assert not path.exists()
    config = {
        "Label": label, "ProgramArguments": list(map(str, arguments)),
        "UserName": m.CUSTODIAN, "GroupName": m.CUSTODIAN,
        "RunAtLoad": True, "KeepAlive": False, "Umask": 63,
        "SoftResourceLimits": {"Core": 0}, "HardResourceLimits": {"Core": 0},
        "StandardErrorPath": str(m.STATE / (label + ".stderr")),
        "EnvironmentVariables": {"PMW2_TIMING": "1"} if label == SYNC_LABEL and m.SYNC_TIMING_ENABLED else {},
    }
    path.write_bytes(plistlib.dumps(config))
    m.sudo(["chown", "root:wheel", path]); m.sudo(["chmod", "0644", path])
    m.sudo(["launchctl", "bootstrap", "system", path]); labels.append(label)
    return path


def stop_launch(m, label, labels, session=None):
    command = ["launchctl", "bootout", "system/" + label]
    if session is None:
        m.sudo(command)
    else:
        session.run_sudo_while_draining(command)
    labels.remove(label)


def seed_remote_history(m, binary, profile, private, endpoint, scratch, labels):
    """Same signed-history setup as Linux Full25; not a keyboard acceptance claim."""
    audit = m.STATE / "vault.sqlite3.audit-custody"
    owner = m.STATE / "ticket25-owner.audit-custody"
    remote = m.STATE / "ticket25-remote.audit-custody"
    assert m.sudo(["test", "-e", owner], check=False).returncode == 1
    assert m.sudo(["test", "-e", remote], check=False).returncode == 1
    m.sudo(["launchctl", "bootout", "system/" + m.LABEL])
    moved = remote_loaded = False
    primary = None
    try:
        m.sudo(["mv", audit, owner]); moved = True
        launch(m, REMOTE_LABEL, [binary, "serve-vault", "--bootstrap", m.STATE / "bootstrap",
               "--agent-socket", m.RUNTIME / "agent.sock", "--human-socket", endpoint,
               "--vault", m.STATE / "vault.sqlite3", "--device", REMOTE_DEVICE], scratch, labels)
        remote_loaded = True
        wait_service(m, REMOTE_LABEL, endpoint)
        result = m.run([binary, "human-password-crud", "--profile", profile,
                        "--private", private, "--socket", endpoint], check=False,
                       input=m.wire_fields([m.PASSWORD, b"Remote device item", b"remote-user",
                        b"synthetic-ticket25-remote-secret", b"https://remote-device.invalid",
                        b"synthetic remote note", b"Remote device item edited",
                        b"synthetic-ticket25-remote-secret-2"]))
        assert result.returncode == 0 and result.stderr == b"" \
            and result.stdout.startswith(b"PASS human-crud-e2e"), "remote signed-history setup failed"
    except BaseException as error:
        primary = error
    failures = []
    for cleanup in (
        lambda: stop_launch(m, REMOTE_LABEL, labels) if remote_loaded else None,
        lambda: m.sudo(["mv", audit, remote]) if moved else None,
        lambda: m.sudo(["mv", owner, audit]) if moved else None,
        lambda: m.sudo(["launchctl", "bootstrap", "system", m.PLIST]),
        m.wait_for_service,
    ):
        try:
            cleanup()
        except BaseException as error:
            failures.append(error)
    if primary is not None:
        if failures:
            raise primary from BaseExceptionGroup("remote fixture cleanup failed", failures)
        raise primary
    if failures:
        raise BaseExceptionGroup("remote fixture cleanup failed", failures)


def wait_service(m, label, endpoint, session=None):
    deadline = m.time.monotonic() + 5
    while True:
        command = ["launchctl", "print", "system/" + label]
        result = m.sudo(command, check=False) if session is None \
            else session.run_sudo_while_draining(command, check=False)
        pid = m.running_launchd_pid(result)
        connectable = False
        probe = m.socket.socket(m.socket.AF_UNIX)
        try:
            probe.settimeout(0.2)
            probe.connect(str(endpoint))
            connectable = True
        except OSError:
            pass
        finally:
            probe.close()
        if pid is not None and connectable:
            identity = m.run(["ps", "-o", "user=", "-p", str(pid)], check=False)
            if identity.returncode != 0:
                diagnose_service_exit(m, label, session)
                raise AssertionError("native fixture PID disappeared during readiness")
            assert identity.stdout.strip() == m.CUSTODIAN.encode(), "native service UID mismatch"
            return pid
        if m.time.monotonic() >= deadline:
            diagnose_service_exit(m, label, session)
            raise AssertionError("native fixture service did not start")
        if session is not None:
            session._read_once(0.05)
        else:
            m.time.sleep(0.05)


def diagnose_service_exit(m, label, session):
    command = ["launchctl", "print", "system/" + label]
    result = m.sudo(command, check=False) if session is None \
        else session.run_sudo_while_draining(command, check=False)
    exits = re.findall(rb"^\s*last exit code = (-?[0-9]+)\s*$", result.stdout, re.M)
    signals = re.findall(rb"^\s*last terminating signal = ([0-9]+)\s*$", result.stdout, re.M)
    exit_code = exits[0].decode("ascii") if len(exits) == 1 else "unavailable"
    last_signal = signals[0].decode("ascii") if len(signals) == 1 else "unavailable"
    log = m.sudo(["cat", m.STATE / (label + ".stderr")], check=False)
    stderr = "unavailable" if log.returncode != 0 else (
        "empty" if not log.stdout else "sync-unavailable" if log.stdout == b"SYNC_UNAVAILABLE\n" else "other"
    )
    print("PM26_SYNC_LIFECYCLE exit=" + exit_code + " signal=" + last_signal
          + " stderr=" + stderr, flush=True)


def sync_phase_timings(m, session):
    if not m.SYNC_TIMING_ENABLED:
        return
    from collections import defaultdict
    totals = defaultdict(lambda: [0, 0, 0])
    for path, source in ((m.STATE / "w2-sync-timing.log", "job"),
                         (m.STATE / (SYNC_LABEL + ".stderr"), "server")):
        result = session.run_sudo_while_draining(["cat", path], check=False)
        assert result.returncode == 0, "sync timing log unavailable"
        value = result.stdout[session.w2_timing_offsets[source]:]
        for line in value.splitlines():
            match = re.fullmatch(rb"PMW2_TIMING category=([a-z_]+) count=([0-9]+) us=([0-9]+)", line)
            if match:
                category, count, us = match.groups()
                key = source + ":" + category.decode("ascii")
                totals[key][0] += int(count); totals[key][1] += int(us)
                totals[key][2] = max(totals[key][2], int(us))
    assert totals, "sync timing measurements missing"
    for category, (count, us, maximum) in sorted(totals.items()):
        print(f"PMW2_PHASE category={category} count={count} total_us={us} max_us={maximum}", flush=True)


def diagnose_sync_wait(m, session, since, sync_db, expected_pid):
    phases = ("invalid", "queued", "pushing", "pulling", "succeeded", "unavailable",
              "integrity", "backpressure", "journal-failure", "rejected")
    result = session.run_sudo_while_draining(
        ["cat", m.STATE / "vault.sqlite3.sync-status"], check=False)
    value = result.stdout
    phase = "unavailable-record" if result.returncode != 0 else (
        phases[value[21]] if len(value) == 38 and value[:5] == b"PMSS1"
        and 1 <= value[21] <= 9 else "invalid-record")
    page = session._current_text_after(since)
    labels = (("authorized and queued", "queued"), ("pushing ciphertext", "pushing"),
              ("pulling ciphertext", "pulling"), ("Sync complete through pinned TLS", "succeeded"),
              ("unavailable after bounded transport", "unavailable"),
              ("rejected integrity", "integrity"), ("stopped by backpressure", "backpressure"),
              ("journal/cleanup failed", "journal-failure"),
              ("rejected its fixed authority/request context", "rejected"),
              ("Sync endpoint offline", "offline"), ("Operation failed explicitly", "explicit-failure"))
    matches = [label for text, label in labels if page is not None and text in page]
    screen = matches[0] if len(matches) == 1 else "unclassified"
    record = session.run_sudo_while_draining(
        ["launchctl", "print", "system/" + SYNC_LABEL], check=False)
    pid = m.running_launchd_pid(record)
    process = "same" if pid == expected_pid else "missing" if pid is None else "changed"
    print(f"PM26_SYNC_WAIT durable={phase} screen={screen} process={process}", flush=True)
    record = session.run_sudo_while_draining(["launchctl", "print", "system/" + m.LABEL], check=False)
    custody_pid = m.running_launchd_pid(record)
    custody = "same" if custody_pid == session.w2_custodian_pid else "missing" if custody_pid is None else "changed"
    print(f"PMW2_LAUNCHD custodian={custody} server={process}", flush=True)
    code = """import json,sqlite3,sys
with sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True) as db:
 print(json.dumps([db.execute('select count(*) from '+t).fetchone()[0]
  for t in ('blocks','roots')]))
"""
    counts = session.run_sudo_while_draining([sys.executable, "-c", code, sync_db], check=False)
    assert counts.returncode == 0 and counts.stderr == b"", "sync durable diagnostic failed"
    blocks, roots = json.loads(counts.stdout)
    assert type(blocks) is int and type(roots) is int and blocks >= 0 and roots >= 0
    print(f"PM26_SYNC_OPAQUE blocks={blocks} roots={roots}", flush=True)
    sync_phase_timings(m, session)
    if process != "same":
        diagnose_service_exit(m, SYNC_LABEL, session)


def assert_stream(path):
    size = 16 * 1024 * 1024 + 4096
    canary = b"ticket05-large-stream-canary-"
    expected = hashlib.blake2b(digest_size=32)
    actual = hashlib.blake2b(digest_size=32)
    offset = 0
    assert path.stat().st_size == size and path.stat().st_mode & 0o777 == 0o600
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            pattern = bytes(canary[(offset + i) % len(canary)] for i in range(len(chunk)))
            assert chunk == pattern, "native attachment stream bytes differed"
            actual.update(chunk); expected.update(pattern); offset += len(chunk)
    assert offset == size and actual.digest() == expected.digest()


def expect_output_collision(session, kind, path, expected_digest, *, since):
    try:
        session.wait_text("Operation failed explicitly; no success was recorded", since=since)
    except BaseException as error:
        try:
            page = session._current_text_after(since)
            complete = {"backup": "Native encrypted backup complete",
                        "plaintext": "Plaintext export complete"}[kind]
            result = "unexpected-complete" if page is not None and complete in page else "unclassified"
            destination = "same" if source_digest(path) == expected_digest else "changed"
            print(f"PM26_OUTPUT_COLLISION kind={kind} result={result} destination={destination}", flush=True)
        except BaseException as diagnostic_error:
            raise error from diagnostic_error
        raise
    assert source_digest(path) == expected_digest, "collision changed the original output"


def wait_recovery_code(m, session, *, since):
    deadline = m.time.monotonic() + 8
    grammar = r"Exposure: (PMR1-[0-9a-f]{32}-[0-9]+(?:-[0-9a-f]{8}){9})"
    while True:
        page = session._current_text_after(since)
        if page is not None and "Recovery code shown temporarily" in page:
            codes = [match.group(1) for row in m.exposure_rows(page)
                     if (match := re.fullmatch(grammar, row)) is not None]
            if len(codes) == 1:
                return codes[0]
        remaining = deadline - m.time.monotonic()
        if remaining <= 0:
            raise AssertionError("complete recovery exposure did not paint within the original bound")
        session._read_once(min(0.1, remaining))


def diagnose_restore_wait(m, session, before, *, since):
    def status():
        page = session._current_text_after(since)
        if page is not None and "Restore committed with new IDs/keys" in page:
            return "complete"
        if page is not None and "Operation failed explicitly" in page:
            return "explicit-failure"
        return "unclassified"
    previous = status()
    after = snapshot(m, session)
    current = status()
    authority = "same" if after["authority_state"] == before["authority_state"] else "changed"
    delta = after["vault_items"] - before["vault_items"]
    print(f"PM26_RESTORE_WAIT before-ui={previous} after-ui={current} delta-items={delta} authority={authority}", flush=True)


def rejected_source(m, binary, profile, private, endpoint, path, *, onepux_source):
    before = snapshot(m)["vault_items"]
    session = start(m, binary, profile, private, endpoint)
    try:
        mark = operation(session, "m", "2" if onepux_source else "1",
                         "1PUX source" if onepux_source else "CSV source",
                         f"{path}|keep" if onepux_source else f"{path}|chrome|keep")
        session.wait_text("Operation failed explicitly; no success was recorded", since=mark)
        # The existing server ends the invalid human RPC; the subsequent
        # heartbeat fails closed.  Do not treat this session as still usable.
        assert session.wait_exit(timeout=8) == 4
        assert snapshot(m)["vault_items"] == before
    finally:
        m.close_session_preserving_primary(session)


def observe_pending_purged_graphs(m):
    code = """import json,sqlite3,sys
with sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True) as db:
 purged=db.execute('select count(*) from purged_items').fetchone()[0]
 pending=db.execute("select count(*) from outbox o join authority_events a on a.event_digest=o.event_digest join purged_items p on p.item_id=a.subject where a.kind='item-revision'").fetchone()[0]
 missing=db.execute("select count(*) from outbox o join authority_events a on a.event_digest=o.event_digest join purged_items p on p.item_id=a.subject left join vault_items i on i.item_id=a.subject where a.kind='item-revision' and i.item_id is null").fetchone()[0]
 print(json.dumps([purged,pending,missing]))
"""
    result = m.sudo([sys.executable, "-c", code, m.STATE / "vault.sqlite3"])
    assert result.returncode == 0 and result.stderr == b"", "outbox diagnostic failed"
    values = json.loads(result.stdout)
    assert len(values) == 3 and all(type(v) is int and v >= 0 for v in values)
    purged, pending, missing = values
    print(f"PM26_OUTBOX_PURGED items={purged} pending-revisions={pending} missing-items={missing}", flush=True)


def run_tui_ticket25_matrix(m, binary, profile, private, endpoint, scratch, labels):
    human = scratch / "human"
    observe_pending_purged_graphs(m)
    seed_remote_history(m, binary, profile, private, endpoint, scratch, labels)
    streamed = m.run([binary, "human-streaming-file", "--profile", profile,
                     "--private", private, "--socket", endpoint],
                    input=m.wire_fields([m.PASSWORD]), check=False)
    assert streamed.returncode == 0 and streamed.stderr == b"" \
        and streamed.stdout.startswith(b"PASS streaming-file"), "large attachment setup failed"
    sources = {}
    for name, content in {
        "chrome": "name,url,username,password,note,Future Column\nKeyboard Chrome,https://chrome.invalid,u,synthetic-ticket25-chrome,n,opaque\n",
        "apple": "Title,URL,Username,Password,Notes,OTPAuth\nKeyboard Apple,https://apple.invalid,u,synthetic-ticket25-apple,n,otpauth://totp/Issuer:acct?secret=JBSWY3DPEHPK3PXP\n",
        "mappable": "Title;Account;URL;Secret\nKeyboard Mapped;u;https://mapped.invalid;synthetic-ticket25-mapped\n",
        "malformed": 'name,url,username,password\nBad,https://bad.invalid,u,"unterminated',
    }.items():
        path = human / (name + ".csv"); assert not path.exists()
        path.write_text(content, encoding="utf-8"); path.chmod(0o400)
        sources[name] = path
    archive = human / "ticket25.1pux"; onepux(archive, owner=os.getuid(), group=os.getgid())
    hostile = human / "hostile.1pux"
    with zipfile.ZipFile(hostile, "w") as out:
        out.writestr("../escape", b"synthetic-ticket25-hostile")
    hostile.chmod(0o400)
    rejected_source(m, binary, profile, private, endpoint, sources["malformed"], onepux_source=False)
    rejected_source(m, binary, profile, private, endpoint, hostile, onepux_source=True)
    assert not (scratch / "escape").exists()
    digests = {p: source_digest(p) for p in [*sources.values(), archive, hostile]}
    native, plaintext, attachment, pairing = [human / name for name in
        ("keyboard.pmb1", "keyboard.jsonl", "large.bin", "pairing.cbor")]
    for path in (native, plaintext, attachment, pairing):
        assert not path.exists()
    sync_dir = m.STATE / "ticket25"; sync_runtime = m.RUNTIME / "ticket25"
    m.sudo(["install", "-d", "-o", m.CUSTODIAN, "-g", m.CUSTODIAN,
            "-m", "0700", sync_dir])
    m.sudo(["install", "-d", "-o", m.CUSTODIAN, "-g", m.CUSTODIAN,
            "-m", "0755", sync_runtime])
    sync_binary = sync_dir / "pm-sync"
    m.sudo(["install", "-o", m.CUSTODIAN, "-g", m.CUSTODIAN, "-m", "0755",
            pathlib.Path(__file__).resolve().parents[3] / "target/debug/pm-sync", sync_binary])
    server_key, server_pub, client_key, client_pub = [sync_dir / name for name in
        ("server.key", "server.pub", "client.key", "client.pub")]
    m.keygen(binary, m.CUSTODIAN, server_key, server_pub)
    m.keygen(binary, m.CUSTODIAN, client_key, client_pub)
    pin = m.sudo(["cat", server_pub]).stdout.hex()
    assert len(pin) == 88
    sync_socket, sync_db = sync_runtime / "sync.sock", sync_dir / "opaque.sqlite3"
    closing = None
    session = None
    primary = None
    try:
        session = start(m, binary, profile, private, endpoint)
        before = snapshot(m, session)
        mark = operation(session, "m", "1", "CSV source", f"{human / 'missing.csv'}|chrome|keep")
        session.wait_text("Operation failed explicitly; no success was recorded", since=mark)
        assert snapshot(m, session)["vault_items"] == before["vault_items"]
        for kind in ("chrome", "apple", "mappable"):
            before = snapshot(m, session)["vault_items"]
            mark = operation(session, "m", "1", "CSV source", f"{sources[kind]}|{kind}|keep")
            preview = session.wait_text("type IMPORT to commit", since=mark)
            assert "new=1" in preview and "Mapping=" + kind in preview
            assert "synthetic-ticket25-" not in preview
            submit(session, "IMPORT")
            session.wait_text("Import committed transactionally", since=mark)
            assert snapshot(m, session)["vault_items"] == before + 1
        before = snapshot(m, session)["vault_items"]
        for confirmation in ("NOT IMPORT", None):
            mark = operation(session, "m", "1", "CSV source", f"{sources['chrome']}|chrome|keep")
            session.wait_text("exact-duplicates=1", since=mark)
            if confirmation is None:
                session.send_key("escape"); session.wait_text("Cancelled", since=mark)
            else:
                submit(session, confirmation)
                session.wait_text("Confirmation mismatch; import cancelled", since=mark)
            assert snapshot(m, session)["vault_items"] == before
        mark = operation(session, "m", "1", "CSV source", f"{sources['chrome']}|chrome|replace")
        session.wait_text("duplicate-action=replace", since=mark)
        session.wait_text("type IMPORT to commit", since=mark)
        session.send_key("escape"); session.wait_text("Cancelled", since=mark)
        assert snapshot(m, session)["vault_items"] == before
        mark = operation(session, "m", "2", "1PUX source", f"{archive}|keep")
        preview = session.wait_text("type IMPORT to commit", since=mark)
        assert "new=2" in preview and "synthetic-ticket25-" not in preview
        submit(session, "IMPORT"); session.wait_text("Import committed transactionally", since=mark)
        assert snapshot(m, session)["vault_items"] == before + 2
        for path, digest in digests.items():
            assert source_digest(path) == digest, "import changed its source"

        print("PM26_MATRIX full25-import=observed", flush=True)
        mark = operation(session, "y", "3", "Exact device ID", REMOTE_DEVICE + "|RETIRE")
        session.wait_text("retired at every locally observed", since=mark)
        result = session.run_sudo_while_draining([sys.executable, "-c",
            "import sqlite3,sys;d=sqlite3.connect(sys.argv[1]);print(d.execute(\"select count(*) from authority_events where kind='device-retire' and subject=?\",[bytes.fromhex(sys.argv[2])]).fetchone()[0])",
            m.STATE / "vault.sqlite3", REMOTE_DEVICE])
        assert result.stdout == b"1\n" and result.stderr == b""

        mark = operation(session, "y", "1", "Observed server RPK", f"{pin}|{pairing}|PAIR")
        session.wait_text("Protected pairing created", since=mark)
        assert pairing.stat().st_mode & 0o777 == 0o600
        namespace = pairing_namespace(pairing.read_bytes())
        sync_value = f"{pairing}|{sync_binary}|{sync_socket}|{client_key}|{server_pub}|{pin}|SYNC"
        mark = operation(session, "y", "2", "pairing|pm-sync program", sync_value)
        session.wait_text("Sync endpoint offline; no sync was performed", since=mark)
        launch(m, SYNC_LABEL, [sync_binary, "serve", "--db", sync_db, "--socket", sync_socket,
            "--server-key", server_key, "--namespace", namespace, "--client-pub", client_pub], scratch, labels)
        sync_pid = wait_service(m, SYNC_LABEL, sync_socket, session)
        negative_count = snapshot(m, session)["vault_items"]
        wrong = "00" * 44
        mark = operation(session, "y", "2", "pairing|pm-sync program", sync_value.replace(pin + "|SYNC", wrong + "|SYNC"))
        rejected = session.wait_text("rejected its fixed authority/request context; no success recorded", since=mark)
        assert "no success recorded" in rejected
        assert snapshot(m, session)["vault_items"] == negative_count
        print("PM26_MATRIX full25-offline+wrong-pin=observed", flush=True)

        mark = operation(session, "b", "1", "New native backup path", native)
        session.wait_text("Native encrypted backup complete", since=mark)
        assert native.stat().st_mode & 0o777 == 0o600 and native.stat().st_size > 0
        native_digest = source_digest(native)
        mark = operation(session, "b", "2", "New plaintext export path", plaintext)
        session.wait_text("PLAINTEXT WARNING", since=mark)
        submit(session, "NOT EXPORT"); session.wait_text("Confirmation mismatch", since=mark)
        assert not plaintext.exists()
        mark = operation(session, "b", "2", "New plaintext export path", plaintext)
        session.wait_text("PLAINTEXT WARNING", since=mark)
        submit(session, "EXPORT"); session.wait_text("Plaintext export complete", since=mark)
        assert plaintext.stat().st_mode & 0o777 == 0o600 \
            and plaintext.read_bytes().startswith(b"PM-LOGICAL-JSONL/1\n")
        plaintext_digest = source_digest(plaintext)
        m.tui_search(session, "Large stream")
        mark = session.mark(); session.send_key("D")
        page = session.wait_text("large-雪.bin", since=mark)
        assert "Attachments (exact descriptor; values hidden)" in page
        assert "ticket05-large-stream-canary-" not in page
        session.send_key("enter"); session.wait_text("New destination path", since=mark)
        submit(session, str(attachment)); session.wait_text("Attachment streamed atomically", since=mark)
        assert_stream(attachment)

        mark = operation(session, "z", "1", "Audit metadata:")
        page = session.wait_text("records=", since=mark)
        records = re.search(r"records=(\d+)", page); assert records and int(records.group(1)) > 0
        before = snapshot(m, session)
        mark = operation(session, "z", "2", "generation:through-sequence", "1:2:PURGE AUDIT")
        session.wait_text("discontinuity retained", since=mark)
        after = snapshot(m, session)
        assert after["revision_parts"] == before["revision_parts"]
        assert after["audit_purge_ranges"] > before["audit_purge_ranges"]
        authority = after["authority_events"]
        authority_state = after["authority_state"]
        before_count = after["vault_items"]
        mark = operation(session, "b", "3", "Archive path|RESTORE", f"{native}|NOT RESTORE")
        session.wait_text("Confirmation mismatch", since=mark)
        assert snapshot(m, session)["vault_items"] == before_count
        mark = operation(session, "b", "3", "Archive path|RESTORE", f"{native}|RESTORE")
        try:
            session.wait_text("Restore committed with new IDs/keys", since=mark)
        except BaseException as error:
            try:
                diagnose_restore_wait(m, session, after, since=mark)
            except BaseException as diagnostic_error:
                raise error from diagnostic_error
            raise
        restored = snapshot(m, session)
        assert restored["vault_items"] > before_count and restored["authority_events"] > authority
        assert restored["authority_state"] == authority_state, "restore changed current authority"
        mark = operation(session, "b", "5", "Recovery code shown temporarily")
        code = wait_recovery_code(m, session, since=mark)
        submit(session, code, hidden=True)
        page = session.wait_text("Recovery rotated after exact re-entry; historical backups/copies remain usable", since=mark)
        assert "historical backups/copies remain usable" in page
        lock(m, session); session = None
        session = start(m, binary, profile, private, endpoint)
        mark = operation(session, "b", "4", "New master password|ROTATE",
                         NEW_PASSWORD.decode() + "|ROTATE", hidden=True)
        page = session.wait_text("Master password rotated; old backups and exposed copies retain historical paths", since=mark)
        assert "historical" in page
        lock(m, session); session = None
        wrong = m.MacPtySession.start(binary, profile, private, endpoint, idle=30, reveal=1, copy=1)
        try:
            wrong.wait_text("Password required")
            wrong.send_text(m.PASSWORD.decode(), enter=True, hidden=True)
            assert wrong.wait_exit(timeout=8) == 4
        finally:
            m.close_session_preserving_primary(wrong)
        session = start(m, binary, profile, private, endpoint, password=NEW_PASSWORD)
        for path, digest in digests.items():
            assert source_digest(path) == digest
        print("PM26_MATRIX full25-local=observed", flush=True)

        mark = operation(session, "b", "1", "New native backup path", native)
        expect_output_collision(session, "backup", native, native_digest, since=mark)
        mark = operation(session, "b", "2", "New plaintext export path", plaintext)
        session.wait_text("PLAINTEXT WARNING", since=mark)
        submit(session, "EXPORT")
        expect_output_collision(session, "plaintext", plaintext, plaintext_digest, since=mark)

        session.w2_custodian_pid = m.running_launchd_pid(
            session.run_sudo_while_draining(["launchctl", "print", "system/" + m.LABEL]))
        assert session.w2_custodian_pid is not None, "sync custodian was not running"
        session.w2_timing_offsets = {}
        if m.SYNC_TIMING_ENABLED:
            for source, path in (("job", m.STATE / "w2-sync-timing.log"),
                                 ("server", m.STATE / (SYNC_LABEL + ".stderr"))):
                value = session.run_sudo_while_draining(["cat", path])
                session.w2_timing_offsets[source] = len(value.stdout)
        sync_started = m.time.monotonic()
        mark = operation(session, "y", "2", "pairing|pm-sync program", sync_value)
        try:
            complete = session.wait_text("Sync complete through pinned TLS", timeout=20, since=mark)
        except BaseException as error:
            try:
                diagnose_sync_wait(m, session, mark, sync_db, sync_pid)
            except BaseException as diagnostic_error:
                raise error from diagnostic_error
            raise
        print(f"PMW2_TUI elapsed_ms={round((m.time.monotonic() - sync_started) * 1000)}", flush=True)
        diagnose_sync_wait(m, session, mark, sync_db, sync_pid)
        assert "pushed=" in complete and "pulled=" in complete
        job = re.search(r"job=([0-9a-f]{32})", complete); assert job
        mark = operation(session, "y", "4", "Exact sync job ID", job.group(1))
        session.wait_text("Sync complete through pinned TLS", since=mark)
        hostile_socket = scratch / "closing.sock"
        closing = ClosingEndpoint(hostile_socket)
        failed_value = sync_value.replace(str(sync_socket), str(hostile_socket))
        mark = operation(session, "y", "2", "pairing|pm-sync program", failed_value)
        queued = session.wait_text("authorized and queued", since=mark)
        failed_job = re.search(r"Sync job ([0-9a-f]{32})", queued); assert failed_job
        lock(m, session); session = None
        assert m.sudo(["test", "-f", m.STATE / "vault.sqlite3.sync-job"], check=False).returncode == 0
        m.sudo(["launchctl", "kickstart", "-k", "system/" + m.LABEL]); m.wait_for_service()
        session = start(m, binary, profile, private, endpoint, idle=1, password=NEW_PASSWORD)
        mark = operation(session, "y", "4", "Exact sync job ID", failed_job.group(1))
        progress = session.wait_text("Sync job", since=mark)
        assert "complete through" not in progress
        assert session.wait_exit(timeout=8) == 0
        m.close_session_preserving_primary(session); session = None
        session = start(m, binary, profile, private, endpoint, password=NEW_PASSWORD)
        mark = operation(session, "y", "4", "Exact sync job ID", failed_job.group(1))
        deadline = m.time.monotonic() + 75
        queried = m.time.monotonic()
        while True:
            page = session._current_text_after(mark)
            if page is not None and "unavailable after bounded transport" in page:
                break
            assert m.time.monotonic() < deadline, "same sync job did not reach bounded unavailability"
            if m.time.monotonic() - queried >= 20:
                mark = operation(session, "y", "4", "Exact sync job ID", failed_job.group(1))
                queried = m.time.monotonic()
            session._read_once(0.1)
        assert m.sudo(["test", "-e", m.STATE / "vault.sqlite3.sync-job"], check=False).returncode == 1
        closing.close(); closing = None

        lock(m, session); session = None
        stop_launch(m, SYNC_LABEL, labels)
        session = start(m, binary, profile, private, endpoint, password=NEW_PASSWORD)
        mark = operation(session, "y", "2", "pairing|pm-sync program", sync_value)
        session.wait_text("Sync endpoint offline; no sync was performed", since=mark)
        for path, digest in digests.items():
            assert source_digest(path) == digest
        assert b"synthetic-ticket25-" not in bytes(session.output) and b"\x1b]52;" not in bytes(session.output)
        lock(m, session); session = None
    except BaseException as error:
        primary = error
    failures = []
    for cleanup in (
        lambda: m.close_session_preserving_primary(session) if session is not None else None,
        lambda: closing.close() if closing is not None else None,
        lambda: stop_launch(m, SYNC_LABEL, labels) if SYNC_LABEL in labels else None,
    ):
        try:
            cleanup()
        except BaseException as error:
            failures.append(error)
    if primary is not None:
        if failures:
            raise primary from BaseExceptionGroup("Full25 fixture cleanup failed", failures)
        raise primary
    if failures:
        raise BaseExceptionGroup("Full25 fixture cleanup failed", failures)
    return NEW_PASSWORD
