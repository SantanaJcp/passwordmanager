# Ticket 14 verification evidence

Date: 2026-09-13. Requirements: R03, R08, R09, R13, R14. Observed host:
Linux x86_64. Every account, password, certificate, key, identifier and token
is synthetic. The process laboratory runs in a disposable user/mount namespace
and deletes its private Keycloak database, browser profiles and vault.

## Implemented slice

The trusted `keycloak-webauthn/1` adapter starts a real Keycloak 26.7.3 OIDC
Authorization Code + PKCE flow, submits only the installed username, and waits
for Keycloak's real WebAuthn page. Its private CFT profile loads the pinned MV3
package only after hashing its exact five files; the profile copy binds one
vault item, issuer origin and RP ID. The adapter waits for the extension service
worker, MAIN-world installation and Keycloak module resource before clicking,
so neither a startup race nor a missing adapter can invoke an OS authenticator.

The extension has no compatibility fallback: both replaced CredentialsContainer
operations reject non-public-key requests. A Keycloak assertion crosses MV3,
Native Messaging and the existing TLS-RPK bridge to the same passkey item that
the real registration flow created. Custody releases no passkey seed. Required
UP/UV becomes the existing per-attempt `WAITING_FOR_HUMAN` state and only the
request-bound `/dev/tty` approval plus fresh master-password reauthentication
produces the signature. The OIDC result is published through the same closed
ten-field schema for CLI and MCP.

Provider restart deliberately loses the in-memory browser session and makes
reconciliation an `INTEGRITY_FAILURE`; it never recreates the assertion with a
virtual or OS key. Expired passkey requests cannot be confirmed and remain
without a result until explicitly cancelled. Agent revocation is rechecked
before signing. Installed account, exact origin/destination, RP, credential ID,
WebAuthn challenge, signed OIDC nonce/issuer/audience/subject and callback state
are all independently bound before delegated success.

## Verification method and observed evidence

The method applies the process seams already established by tickets 10 and 13:
fixed official Keycloak 26.7.3 plus pinned CFT 153.0.8010.36 as a laboratory
instrument, real MV3/Native Messaging, real TLS-RPK custodian and agent/human
UIDs, and a real pseudoterminal for human approval. No virtual authenticator,
OS passkey, mocked provider, password substitution, skip or stub is accepted.
Success requires the key created by registration to complete a real Keycloak
assertion and yield verified OIDC tokens. Each negative must have no result or
terminate failed/cancelled, with no alternate authentication path.

Focused public seams and workspace gate:

```text
./scripts/cargo-local.sh test -p pm-vault --test passkey_provider --locked --offline
# 2 passed; 0 failed

./scripts/cargo-local.sh test -p pm-web-auth --locked --offline
# 7 passed; 0 failed

./scripts/check.sh
# pinned inputs, fmt, workspace/all-target check/tests and clippy: exit 0

# An earlier check exposed three new style/size findings; after extraction/fixes:
./scripts/cargo-local.sh clippy --workspace --all-targets --locked --offline -- -D warnings
# exit 0

./scripts/clean-offline-build.sh
# removed 12,319 files / 3.1 GiB; locked/offline build finished in 30.96 s

git diff --check
# exit 0
```

Real P4 process laboratory:

```text
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3 \
PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64 \
./scripts/test-linux-passkey-login-lab.sh

PASS passkey-login keycloak=26.7.3 registration=real assertion=same-vault-key oidc=code+PKCE-S256 result=oidc_tokens
PASS passkey-login-human outer=WAITING_FOR_HUMAN UP=TTY UV=fresh-reauth presence-only=denied extension=MV3-native real
PASS passkey-login-binding challenge+credential+account+origin=bound passwordless-flow=username+webauthn wrong-origin+account=denied secrets=absent
PASS passkey-login-negative challenge-expired=denied provider-restart=integrity-failure revoke-before-UPUV=denied os-authenticator=unused
LIMIT cft=laboratory-instrument product-browser=ticket33-NOT_RUN six-native-targets=NOT_RUN
```

The first real assertion was red because the provider clicked before the MV3
MAIN-world replacement and Keycloak module listener were ready. A later green
run exposed a second public-seam omission: CLI/MCP redacted the valid OIDC
result for the new integration ID. Both races and the closed result mapping are
covered by the final real lab. A combined regression run later hit the new lab
before the human socket finished accepting; the laboratory now waits one second
after both socket paths appear, and the complete P4 run above passed.

All twelve earlier Linux labs were run against this candidate. The first ten
passed sequentially before that transient P4 readiness failure; after its fix,
P4, sync and real password/TOTP Keycloak web-auth all passed. Thus every current
`scripts/test-linux-*-lab.sh` laboratory has a successful candidate run, while
P1 and P4 each still use CFT only as the explicitly pinned conformance
instrument.

## Exact limits

- CFT 153.0.8010.36 is not the product-owned Chromium artifact or packaging
  required by tickets 29/33.
- Only Linux x86_64 was observed. The other native targets remain ticket 33.
- The laboratory controls elapsed challenge time by moving only the disposable
  request row behind the real clock; expiry enforcement, TTY rejection and the
  absence of a signed response execute in the real custody process.
- Formal Astra review remains the final DAG gate. Integration and ticket
  resolution belong to the separate merger.

## Verificación de integración unificada

El merger integró el código candidato sobre `817fe1e` preservando los perfiles
`keycloak-browser-oidc` y `keycloak-token-exchange`, SSH y los opcodes ya
publicados. El primer P4 unificado fue rojo de forma reproducible: el framing
compartido del opcode 4 añadía tanto el `credential_id` de WebAuthn como el
`subject_token` exclusivo del exchange; al no existir ese token en una passkey,
la llamada no llegaba al proveedor y la reconciliación cerraba el intento como
`INTEGRITY_FAILURE`. La corrección separa los dos payloads por integration ID,
sin sustitución ni ruta alternativa. El P4 posterior fue verde y el laboratorio
P2 confirmó que el token exchange seguía intacto.

Verificación final sobre el árbol integrado:

```text
./scripts/cargo-local.sh test -p pm-web-auth -p pm-vault -p pm-interface -p pm-cli
# exit 0

./scripts/check.sh
# fmt, check/test workspace --all-targets y clippy -D warnings: exit 0

./scripts/clean-offline-build.sh
# removed 13,975 files / 4.0 GiB; locked/offline build finished in 38.81 s

PM_KEYCLOAK_DIST=.scratch/lab-artifacts/keycloak/keycloak-26.7.3 \
PM_CFT_DIR=.scratch/lab-artifacts/cft/chrome-linux64 \
./scripts/test-linux-passkey-login-lab.sh
# las cuatro líneas PASS P4 y los límites documentados; exit 0

# Los 16 scripts/test-linux-*-lab.sh, en orden, con los mismos artefactos fijados
# ALL_LABS_EXIT=0

git diff --check
./scripts/cargo-local.sh fmt --all -- --check
# exit 0
```

La corrida conjunta cubrió P4 real y sus negativas de expiry, restart,
revocación, cuenta y origen, además de las regresiones P1, P2, SSH, recovery,
sync, contenido, historial, imports, backup, autorización, intentos y custodia.
No se usó autenticador virtual, llave del OS, mock de aceptación ni fallback.
