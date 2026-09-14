#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Real Keycloak 26.7.3 Standard Token Exchange v2 P2 laboratory."""

import base64
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse

import web_auth_lab as common

CUSTODIAN, HUMAN, AGENT_A, AGENT_B, PROVIDER, DESTINATION = 1, 2, 3, 4, 5, 6
DEVICE = "11111111111111111111111111111111"
MASTER = b"synthetic ticket 11 e2e master"
CLIENT_ID = "pm-exchanger"
CLIENT_SECRET = "ticket11-requester-client-secret-canary"
TARGET = "pm-target"
SCOPE = "target.read"


def realm():
    return {
        "realm": "pm",
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "defaultDefaultClientScopes": [],
        "defaultOptionalClientScopes": [],
        "clientScopes": [{
            "name": "target.read",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false",
            },
        }],
        "clients": [
            {
                "clientId": CLIENT_ID,
                "name": "PM synthetic exchange requester",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": CLIENT_SECRET,
                "clientAuthenticatorType": "client-secret",
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "fullScopeAllowed": False,
                "defaultClientScopes": [],
                "optionalClientScopes": ["target.read"],
                "attributes": {
                    "standard.token.exchange.enabled": "true",
                    "standard.token.exchange.enableRefreshRequestedTokenType": "false",
                },
                "protocolMappers": [
                    {
                        "name": "requester audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": {
                            "included.client.audience": CLIENT_ID,
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    },
                    {
                        "name": "target audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": {
                            "included.client.audience": TARGET,
                            "access.token.claim": "true",
                            "id.token.claim": "false",
                        },
                    },
                ],
            },
            {
                "clientId": TARGET,
                "name": "PM synthetic target",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "bearerOnly": True,
            },
        ],
    }


def decode_chunked(body):
    out = bytearray()
    while True:
        line, body = body.split(b"\r\n", 1)
        size = int(line.split(b";", 1)[0], 16)
        if size == 0:
            return bytes(out)
        out.extend(body[:size])
        assert body[size:size + 2] == b"\r\n"
        body = body[size + 2:]


def https_request(port, ca_pem, path, form):
    context = ssl.create_default_context(cafile=str(ca_pem))
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    with context.wrap_socket(raw, server_hostname="auth.test") as tls:
        body = urllib.parse.urlencode(form).encode()
        tls.sendall(
            f"POST {path} HTTP/1.1\r\nHost: auth.test:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        data = bytearray()
        while True:
            piece = tls.recv(65536)
            if not piece:
                break
            data.extend(piece)
    headers, body = bytes(data).split(b"\r\n\r\n", 1)
    assert headers.startswith(b"HTTP/1.1 200 OK"), (headers, body)
    if b"transfer-encoding: chunked" in headers.lower():
        body = decode_chunked(body)
    return json.loads(body)


def jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def profile_text(port, ca_der, subject, audience=TARGET, token_path=None):
    token_path = token_path or "/realms/pm/protocol/openid-connect/token"
    return "\n".join([
        "version=1",
        "profile_id=keycloak-exchange-lab",
        "integration_id=keycloak-token-exchange",
        f"issuer=https://auth.test:{port}/realms/pm",
        f"token_endpoint=https://auth.test:{port}{token_path}",
        f"jwks_uri=https://auth.test:{port}/realms/pm/protocol/openid-connect/certs",
        f"requester_client_id={CLIENT_ID}",
        f"expected_subject={subject}",
        f"audience={audience}",
        f"scopes={SCOPE}",
        f"ca_der={ca_der}",
        "",
    ])


def start_adapter(adapter, profile, socket_path, log):
    return common.start_uid(
        PROVIDER,
        [adapter, "serve", "--profile", profile, "--socket", socket_path,
         "--custodian-uid", str(CUSTODIAN)],
        stdout=open(log, "ab"),
        stderr=subprocess.STDOUT,
    )


def start_daemon(custody, bootstrap, runtime, vault, provider_socket):
    return common.start_uid(
        CUSTODIAN,
        [custody, "serve-attempt-lab", "--bootstrap", bootstrap,
         "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
         "--vault", vault, "--device", DEVICE, "--provider-socket", provider_socket,
         "--provider-uid", str(PROVIDER)],
    )


def start_attempt(cli, env, item, nonce, context="keycloak-exchange-lab"):
    now = str(int(time.time() * 1_000_000))
    args = ["--json", "auth", "start", "--credential-id", item,
            "--integration-id", "keycloak-token-exchange", "--integration-version", "1",
            "--method", "token_exchange", "--destination", "keycloak-exchange-lab",
            "--context", context, "--issued-at", now, "--nonce", nonce * 32]
    return args, common.cli(AGENT_A, cli, env, args, check=False)


def safe_process_diagnostic(result, *secrets):
    """Return bounded process diagnostics with synthetic credentials redacted."""
    sensitive = [value for value in secrets if value]

    def redacted(value):
        for secret in sensitive:
            value = value.replace(secret, b"<REDACTED>")
        return value[:2048].decode("utf-8", "backslashreplace")

    return {
        "returncode": result.returncode,
        "stdout": redacted(result.stdout),
        "stderr": redacted(result.stderr),
    }


def wait_terminal(cli, env, attempt):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = common.cli(
            AGENT_A, cli, env,
            ["--json", "auth", "status", "--attempt", attempt], check=False,
        )
        if result.returncode == 0:
            value = json.loads(result.stdout)["result"]
            if value["state"] in ("SUCCEEDED", "FAILED", "INDETERMINATE", "CANCELLED"):
                return value, result.stdout
        time.sleep(.05)
    raise AssertionError("attempt did not finish")


def hostile_server(port, cert, key, capture, mode, subject_token):
    code = r'''import json,pathlib,socket,ssl,sys
port=int(sys.argv[1]);cert,key,capture,mode,token=sys.argv[2:]
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key)
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',port));s.listen();pathlib.Path(capture+'.ready').write_text('1')
c,_=s.accept()
with ctx.wrap_socket(c,server_side=True) as t:
 data=b''
 while b'\r\n\r\n' not in data:data+=t.recv(4096)
 head,rest=data.split(b'\r\n\r\n',1);length=int(next(x.split(b':',1)[1] for x in head.split(b'\r\n') if x.lower().startswith(b'content-length:')))
 while len(rest)<length:rest+=t.recv(4096)
 pathlib.Path(capture).write_bytes(head+b'\r\n\r\n'+rest)
 if mode=='reflect':
  body=json.dumps({'access_token':token,'expires_in':300,'token_type':'Bearer','issued_token_type':'urn:ietf:params:oauth:token-type:access_token','scope':'target.read'}).encode()
  t.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
 else:
  t.sendall(b'HTTP/1.1 302 Found\r\nLocation: https://evil.invalid/reflect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
 t.settimeout(.25)
 try:t.unwrap()
 except (TimeoutError,OSError,ssl.SSLError):pass
'''
    return common.start_uid(
        DESTINATION,
        [sys.executable, "-c", code, str(port), cert, key, capture, mode, subject_token],
    )


def main():
    custody, cli, adapter, kc_source, java_source = map(
        lambda value: pathlib.Path(value).resolve(), sys.argv[1:]
    )
    root = pathlib.Path(tempfile.mkdtemp(prefix="pm-token-exchange-linux-lab-"))
    processes = []
    try:
        root.chmod(0o711)
        auth_port = common.free_port()
        cert_root = root / "certs"; cert_root.mkdir()
        ca_pem, ca_der, auth_key, auth_cert, _, _ = common.certificates(cert_root)
        state, runtime, human_home, agent_home, agent_b_home, provider_home, destination_home, profiles = [
            root / name for name in ("state", "run", "human", "agent", "agent-b", "provider", "destination", "profiles")
        ]
        for path, uid, mode in [
            (state, CUSTODIAN, 0o700), (runtime, CUSTODIAN, 0o755),
            (human_home, HUMAN, 0o755), (agent_home, AGENT_A, 0o755),
            (agent_b_home, AGENT_B, 0o755), (provider_home, PROVIDER, 0o700),
            (destination_home, DESTINATION, 0o700), (profiles, 0, 0o755),
        ]:
            path.mkdir(); os.chown(path, uid, uid); path.chmod(mode)
        provider_socket_dir = root / "provider-socket"; provider_socket_dir.mkdir()
        os.chown(provider_socket_dir, PROVIDER, PROVIDER); provider_socket_dir.chmod(0o711)
        local_adapter = root / "pm-web-auth"; shutil.copy2(adapter, local_adapter); local_adapter.chmod(0o755)
        kc = destination_home / "keycloak"; shutil.copytree(kc_source, kc, symlinks=True); common.chown_tree(kc, DESTINATION)
        java = destination_home / "java"; shutil.copytree(java_source, java, symlinks=True); common.chown_tree(java, DESTINATION)
        imports = kc / "data" / "import"; imports.mkdir(parents=True, exist_ok=True)
        (imports / "pm-realm.json").write_text(json.dumps(realm()))
        common.chown_tree(kc / "data", DESTINATION)
        for path in (auth_key, auth_cert): os.chown(path, DESTINATION, DESTINATION); path.chmod(0o400)
        keycloak_log = destination_home / "keycloak.log"; keycloak_log.touch(); os.chown(keycloak_log, DESTINATION, DESTINATION)
        keycloak = common.start_uid(
            DESTINATION,
            [kc / "bin" / "kc.sh", "start", "--https-port", str(auth_port), "--http-enabled=false",
             "--https-certificate-file", auth_cert, "--https-certificate-key-file", auth_key,
             "--hostname", f"https://auth.test:{auth_port}", "--import-realm", "--db=dev-file"],
            cwd=kc,
            env={"JAVA_HOME": str(java), "PATH": f"{java / 'bin'}:/usr/bin:/bin"},
            stdout=open(keycloak_log, "wb"), stderr=subprocess.STDOUT,
        )
        processes.append(keycloak); common.wait_keycloak(keycloak, auth_port, ca_pem, keycloak_log)
        token_path = "/realms/pm/protocol/openid-connect/token"
        initial = https_request(auth_port, ca_pem, token_path, {
            "grant_type": "client_credentials", "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET, "scope": SCOPE,
        })
        subject_token = initial["access_token"]
        subject = jwt_claims(subject_token)["sub"]
        assert CLIENT_ID in jwt_claims(subject_token)["aud"]
        direct_exchange = https_request(auth_port, ca_pem, token_path, {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": TARGET,
            "scope": SCOPE,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        })
        assert direct_exchange["access_token"] != subject_token
        assert "id_token" not in direct_exchange and "refresh_token" not in direct_exchange

        shutil.copy2(ca_der, provider_home / "ca.der"); os.chown(provider_home / "ca.der", PROVIDER, PROVIDER); (provider_home / "ca.der").chmod(0o400)
        profile = provider_home / "exchange.profile"
        profile.write_text(profile_text(auth_port, provider_home / "ca.der", subject))
        os.chown(profile, PROVIDER, PROVIDER); profile.chmod(0o400)
        provider_log = provider_home / "provider.log"; provider_log.touch(); os.chown(provider_log, PROVIDER, PROVIDER)
        provider_socket = provider_socket_dir / "exchange.sock"
        web = start_adapter(local_adapter, profile, provider_socket, provider_log); processes.append(web); common.wait_path(web, provider_socket)

        local_custody, local_cli = root / "pm-custody", root / "pm"
        shutil.copy2(custody, local_custody); shutil.copy2(cli, local_cli); local_custody.chmod(0o755); local_cli.chmod(0o755)
        server_key, server_pub = state / "server.key", state / "server.pub"
        human_key, human_pub = human_home / "human.key", human_home / "human.pub"
        agent_key, agent_pub = agent_home / "a.key", agent_home / "a.pub"
        agent_b_key, agent_b_pub = agent_b_home / "b.key", agent_b_home / "b.pub"
        for uid, key, public in [(CUSTODIAN, server_key, server_pub), (HUMAN, human_key, human_pub), (AGENT_A, agent_key, agent_pub), (AGENT_B, agent_b_key, agent_b_pub)]:
            common.run_uid(uid, [local_custody, "keygen", "--private", key, "--public", public])
        bootstrap = state / "bootstrap"
        common.run_uid(CUSTODIAN, [local_custody, "provision-bootstrap", "--path", bootstrap,
            "--server-private", server_key, "--server-public", server_pub,
            "--agent-public", agent_pub, "--agent-uid", str(AGENT_A),
            "--human-public", human_pub, "--human-uid", str(HUMAN)])
        agent_profile, human_profile = profiles / "agent.profile", profiles / "human.profile"
        for role, output in (("agent", agent_profile), ("human", human_profile)):
            subprocess.run([local_custody, "provision-profile", "--path", output,
                "--server-public", server_pub, "--server-uid", str(CUSTODIAN), "--role", role], check=True, capture_output=True)
        vault = state / "vault.sqlite3"; common.create_vault(local_cli, vault)
        daemon = start_daemon(local_custody, bootstrap, runtime, vault, provider_socket); processes.append(daemon)
        common.wait_path(daemon, runtime / "agent.sock"); common.wait_path(daemon, runtime / "human.sock")
        common.human(local_custody, human_key, human_profile, runtime / "human.sock", "setup", agent_pub.read_bytes(), agent_b_pub.read_bytes())
        common.human(local_custody, human_key, human_profile, runtime / "human.sock", "add-keycloak-exchange", subject_token.encode(), CLIENT_SECRET.encode())
        env = {"PM_PROFILE": str(agent_profile), "PM_PRIVATE": str(agent_key), "PM_SOCKET": str(runtime / "agent.sock")}
        discovered = json.loads(common.cli(AGENT_A, local_cli, env, ["--json", "credentials", "list"]).stdout)["result"]["credentials"]
        item = next(row["id"] for row in discovered if row["destination"] == "keycloak-exchange-lab")
        assert "keycloak-token-exchange" in next(row for row in discovered if row["id"] == item)["integrations"]

        args, started_process = start_attempt(local_cli, env, item, "1")
        assert started_process.returncode == 0, (started_process.stdout, started_process.stderr)
        started = json.loads(started_process.stdout)["result"]
        finished, output = wait_terminal(local_cli, env, started["attempt_id"])
        assert finished["state"] == "SUCCEEDED", (finished, provider_log.read_text(errors="replace"), keycloak_log.read_text(errors="replace"))
        result = finished["result"]; exchanged = result["access_token"]
        claims = jwt_claims(exchanged)
        assert result["kind"] == "exchanged_access_token" and exchanged not in (subject_token, CLIENT_SECRET)
        assert claims["sub"] == subject and claims["azp"] == CLIENT_ID and claims["aud"] == TARGET
        assert set(claims["scope"].split()) == set(SCOPE.split())
        replay = common.cli(AGENT_A, local_cli, env, args)
        assert json.loads(replay.stdout)["result"]["attempt_id"] == started["attempt_id"]

        bad_args, bad = start_attempt(local_cli, env, item, "2", "agent-selected-context")
        assert bad.returncode != 0 and b"CREDENTIAL_UNAVAILABLE" in bad.stdout

        # Each hostile endpoint is installed by the provider owner, never selected by
        # the agent. Both stored credentials cross only the provider-side TLS request;
        # a reflection or redirect is terminal and no response body becomes a result.
        common.stop(daemon); processes.remove(daemon); common.stop(web); processes.remove(web)
        hostile_outputs = []
        for mode, nonce, reflected, expected_reason in (
            ("reflect", "3", subject_token, "INTEGRITY_FAILURE"),
            ("reflect", "4", CLIENT_SECRET, "INTEGRITY_FAILURE"),
            ("redirect", "5", "unused", "AUTH_REJECTED"),
        ):
            port = common.free_port(); capture = destination_home / f"hostile-{nonce}.request"
            server = hostile_server(port, auth_cert, auth_key, capture, mode, reflected); processes.append(server)
            common.wait_path(server, pathlib.Path(str(capture) + ".ready"))
            profile.write_text(profile_text(port, provider_home / "ca.der", subject, token_path="/token"))
            os.chown(profile, PROVIDER, PROVIDER); profile.chmod(0o400)
            web = start_adapter(local_adapter, profile, provider_socket, provider_log); processes.append(web); common.wait_path(web, provider_socket)
            daemon = start_daemon(local_custody, bootstrap, runtime, vault, provider_socket); processes.append(daemon)
            common.wait_path(daemon, runtime / "agent.sock"); common.wait_path(daemon, runtime / "human.sock")
            _, hostile = start_attempt(local_cli, env, item, nonce)
            assert hostile.returncode == 0, (hostile.stdout, hostile.stderr)
            terminal, public = wait_terminal(local_cli, env, json.loads(hostile.stdout)["result"]["attempt_id"])
            assert terminal["state"] == "FAILED" and terminal["reason"] == expected_reason and terminal["result"] is None, (mode, nonce, terminal, server.poll(), capture.exists(), provider_log.read_text(errors="replace"))
            hostile_outputs.extend((hostile.stdout, public))
            request = capture.read_bytes().split(b"\r\n\r\n", 1)[1]
            fields = urllib.parse.parse_qs(request.decode(), strict_parsing=True)
            assert set(fields) == {"grant_type", "subject_token", "subject_token_type", "requested_token_type", "audience", "scope", "client_id", "client_secret"}
            assert fields["audience"] == [TARGET] and fields["scope"] == [SCOPE]
            common.stop(daemon); processes.remove(daemon); common.stop(web); processes.remove(web); common.stop(server); processes.remove(server)

        # A real Keycloak denial (or a token not carrying exactly the installed
        # audience) is never exposed as a successful generic exchange.
        profile.write_text(profile_text(auth_port, provider_home / "ca.der", subject, audience="not-authorized"))
        os.chown(profile, PROVIDER, PROVIDER); profile.chmod(0o400)
        web = start_adapter(local_adapter, profile, provider_socket, provider_log); processes.append(web); common.wait_path(web, provider_socket)
        daemon = start_daemon(local_custody, bootstrap, runtime, vault, provider_socket); processes.append(daemon)
        common.wait_path(daemon, runtime / "agent.sock"); common.wait_path(daemon, runtime / "human.sock")
        _, denied_audience = start_attempt(local_cli, env, item, "6")
        assert denied_audience.returncode == 0, safe_process_diagnostic(
            denied_audience, subject_token.encode(), CLIENT_SECRET.encode(), MASTER
        )
        audience_terminal, audience_public = wait_terminal(local_cli, env, json.loads(denied_audience.stdout)["result"]["attempt_id"])
        assert audience_terminal["state"] == "FAILED" and audience_terminal["result"] is None, audience_terminal
        common.stop(daemon); processes.remove(daemon); common.stop(web); processes.remove(web)

        # With no provider worker an accepted attempt remains CREATED and can be
        # cancelled through the public TLS/RPK API; cancellation stays terminal.
        daemon = common.start_uid(CUSTODIAN, [local_custody, "serve-vault", "--bootstrap", bootstrap,
            "--agent-socket", runtime / "agent.sock", "--human-socket", runtime / "human.sock",
            "--vault", vault, "--device", DEVICE]); processes.append(daemon)
        common.wait_path(daemon, runtime / "agent.sock"); common.wait_path(daemon, runtime / "human.sock")
        _, cancellable = start_attempt(local_cli, env, item, "7")
        assert cancellable.returncode == 0
        cancel_id = json.loads(cancellable.stdout)["result"]["attempt_id"]
        cancelled = common.cli(AGENT_A, local_cli, env, ["--json", "auth", "cancel", "--attempt", cancel_id])
        assert json.loads(cancelled.stdout)["result"]["state"] == "CANCELLED"
        common.stop(daemon); processes.remove(daemon)

        # Keep a provider listening, then suspend before admission. The request is
        # rejected and the destination observes no POST. The lower-level vault test
        # separately covers an already leased request racing agent revocation.
        port = common.free_port(); blocked_capture = destination_home / "blocked.request"
        server = hostile_server(port, auth_cert, auth_key, blocked_capture, "redirect", "unused"); processes.append(server)
        common.wait_path(server, pathlib.Path(str(blocked_capture) + ".ready"))
        profile.write_text(profile_text(port, provider_home / "ca.der", subject, token_path="/token"))
        os.chown(profile, PROVIDER, PROVIDER); profile.chmod(0o400)
        web = start_adapter(local_adapter, profile, provider_socket, provider_log); processes.append(web); common.wait_path(web, provider_socket)
        daemon = start_daemon(local_custody, bootstrap, runtime, vault, provider_socket); processes.append(daemon)
        common.wait_path(daemon, runtime / "agent.sock"); common.wait_path(daemon, runtime / "human.sock")
        common.human(local_custody, human_key, human_profile, runtime / "human.sock", "suspend")
        _, paused = start_attempt(local_cli, env, item, "8")
        assert paused.returncode != 0 and b"ACCESS_SUSPENDED" in paused.stdout
        time.sleep(.2); assert not blocked_capture.exists()

        combined = b"".join([output, replay.stdout, bad.stdout, denied_audience.stdout,
            audience_public, cancellable.stdout, cancelled.stdout, paused.stdout, *hostile_outputs,
            provider_log.read_bytes()])
        assert subject_token.encode() not in combined and CLIENT_SECRET.encode() not in combined
        for candidate in state.rglob("*"):
            if candidate.is_file():
                persisted = candidate.read_bytes()
                assert subject_token.encode() not in persisted and CLIENT_SECRET.encode() not in persisted
        print("PASS token-exchange-p2 keycloak=26.7.3 exchange=standard-v2 A!=B subject+actor+audience+scope=bound tls=1.3")
        print("PASS token-exchange-adversarial reflect=subject+auxiliary redirect=closed audience=real-denial public=redacted")
        print("PASS token-exchange-controls credential=combined+custodied idempotency=stable context=closed cancel=terminal suspend=pre-post-denied result=token-B-only")
    finally:
        for process in reversed(processes):
            common.stop(process)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
