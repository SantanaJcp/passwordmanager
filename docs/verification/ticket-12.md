# Evidencia de verificación — ticket 12

Fecha: 2026-09-13. Plataforma ejecutada: Linux x86_64 dentro de user namespace + mount namespace descartables.

## Corte entregado

`pm-ssh-client` es el cliente confiable russh 0.63.3: crea TCP/SSH, valida la hostkey instalada sin TOFU, observa `AuthResult::Success` y conserva el mismo `Handle`. Custodia solo entrega password tras el READY posterior a KEX/hostkey, o firma un payload RFC 4252 estrictamente ligado a session-ID/usuario/servicio/método/algoritmo/clave del intento. El resultado cerrado contiene solamente `kind`, `consumer_ref` aleatorio de 256 bits, `host_key_sha256` y `username`.

El socket de consumo comprueba `SO_PEERCRED` contra el UID instalado; conocer el reference no basta. El consumidor abre y cierra un canal `session` sobre el `Handle` autenticado. No existen opcodes para bytes de canal, `exec`, shell, PTY, SFTP, forwarding, reconexión o administración de sesiones.

## Fuentes primarias y versiones fijadas

- [russh `Handle::authenticate_publickey_with` 0.63.3](https://docs.rs/russh/0.63.3/russh/client/struct.Handle.html#method.authenticate_publickey_with), [`authenticate_password`](https://docs.rs/russh/0.63.3/russh/client/struct.Handle.html#method.authenticate_password) y [`channel_open_session`](https://docs.rs/russh/0.63.3/russh/client/struct.Handle.html#method.channel_open_session).
- [russh `AuthResult` 0.63.3](https://docs.rs/russh/0.63.3/russh/client/enum.AuthResult.html): éxito separado de failure/partial-success.
- [RFC 4252 §7](https://www.rfc-editor.org/rfc/rfc4252.html#section-7): payload y firma de autenticación publickey.
- [OpenSSH 10.5 release](https://www.openssh.org/txt/release-10.5) y [`sshd_config` `AuthenticationMethods`](https://man.openbsd.org/sshd_config#AuthenticationMethods).

Dependencias repo-local exactas: `russh = 0.63.3` con `aws-lc-rs`, `tokio = 1.53.1`, `signature = 3.0.0`; lockfile completo. La expansión observada del registro Cargo durante preflight fue `169,024,178` bytes. Instrumento del host: `/usr/bin/sshd` reportó `OpenSSH_10.5p1, OpenSSL 3.6.4 25 Aug 2026`; SHA-256 del binario `c60ee743ec0452f3e34b78dce26706e3288d2faab9397ac60ce7afd4f1df208e`.

## TDD y pruebas negativas

RED conservado en el historial de ejecución antes del código: `cargo test -p pm-vault --test delegated_authorization ssh_attempts_bind...` falló por ausencia de getters/integración SSH de `AttemptLease`; `cargo test -p pm-ssh-client --test profile` falló porque `Profile` no existía. GREEN focalizado: 1/1 y 2/2 respectivamente.

El laboratorio `./scripts/test-linux-ssh-lab.sh` construye offline, superpone `/etc/passwd`, `shadow`, `group` y `gshadow` solo dentro del mount namespace, y ejecuta una cuenta `pmssh` sintética contra `sshd` real. No crea usuarios/servicios/configuración del host, no usa sudo ni contenedores privilegiados. Resultado exacto:

```text
PASS ssh-e2e russh=0.63.3 openssh=10.5p1 auth=publickey+password AuthResult=Success post-auth-channel=opened-and-closed
PASS ssh-boundaries hostkey=reject-before-secret username=installed signing=rfc4252-only consumer=uid-bound ownership=hidden revoke=pre-provider challenge=cancelled
```

Casos observados: Ed25519 y password exitosos; canal posterior sobre ambas conexiones; reference aleatorio incorrecto y mismo reference desde UID impostor rechazados; hostkey incorrecta rechazada antes de READY/secret; usuario instalado incorrecto rechazado; payload RFC4252 bien formado pero ligado a usuario/clave incorrectos desde proveedor hostil termina sin firma; intento de otro owner queda `NOT_FOUND`; revocación previa devuelve `AGENT_REVOKED` sin conexión al proveedor; `AuthenticationMethods publickey,password` produce partial-success, `WAITING_FOR_HUMAN` y cancelación terminal. Los canarios de password/clave no aparecen en stdout, stderr o entorno del agente, ni en el resultado público.

## Gates ejecutados

- `./scripts/check.sh`: verify-build-inputs, fmt, check/test/clippy workspace, all-targets, locked+offline — PASS.
- `./scripts/clean-offline-build.sh`: árbol limpio de build y recompilación offline — PASS.
- Laboratorios Linux ejecutados y PASS: custody, human-transaction, content, authorization, attempts, sync, CSV import, history, 1PUX import y SSH.

## Límites explícitos

Evidencia solo para Linux x86_64, OpenSSH 10.5p1, Ed25519 y password, en laboratorio descartable. macOS Remote Login, Windows OpenSSH, otros targets/algoritmos y empaquetado permanecen en ticket 33. No se afirma que russh zeroice internamente el `String` recibido por `authenticate_password`; la garantía observada es que vive en el proceso UID confiable y nunca en recursos/log/env del agente. La revocación impide una autenticación nueva; por contrato no mata conexiones ya autenticadas.

## Verificación unificada del merger

El candidato `2af343d523ec3cef5b8af492a0b8d868a2417b90`, basado en
`cb5654d88e4e6f0fc7f17b0352a3dffce6e74c8a`, se integró sin reescribir
historia sobre el HEAD unificado
`c8973fc2f85759d2a2b0f13b34efd0df142e6609` mediante el merge
`9328be55276817cbba2be405328a0d552b96eb03`. Los conflictos se resolvieron
como unión aditiva: el workspace y lock conservan backup, passkey, web auth y
sync junto con `pm-ssh-client`; `AttemptLease` conserva TOTP/passkey y añade
material SSH custodial; discovery y resultados públicos conservan OIDC y
agregan los dos perfiles SSH cerrados. No se integró el candidato del ticket
11.

El helper humano exclusivo del laboratorio SSH usaba provisionalmente el
opcode 41. Para preservar los opcodes humanos ya integrados (1PUX 31, backup
32--34, passkey 35--37 y web 40), y evitar el 41 reservado por el candidato 11,
se trasladó simétricamente a 45. Los opcodes del canal agente permanecen en su
espacio separado.

La primera ejecución integrada de `./scripts/check.sh` detectó dos límites
`clippy::too_many_lines` creados por la unión de TOTP/passkey y SSH. Se extrajo
el decodificador cerrado de material de autenticación y la construcción vacía
de reconciliación, sin cambiar el formato persistido. El primer recorrido del
laboratorio de intentos descubrió después una incompatibilidad observable:
`controlled.external` guarda un resultado opaco no JSON, pero el dispatcher
unificado intentaba parsear todo resultado antes de comprobar la integración y
respondía `INTERNAL_ERROR`/`CUSTODY_UNAVAILABLE`. La regresión pública ahora
prueba bytes opacos no JSON; solo OIDC y SSH parsean sus esquemas públicos
cerrados. `pm-interface` quedó en 4/4 y el laboratorio de intentos volvió a
pasar sus rutas E2E/crash.

Gates finales, ejecutados sobre el árbol corregido:

```text
./scripts/check.sh
# verify-build-inputs, fmt, workspace check/tests y clippy locked+offline: PASS

./scripts/clean-offline-build.sh
# Removed 14077 files, 4.0GiB total
# workspace/all-targets locked+offline build: PASS (35.37 s)

./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline
# 8 passed; 0 failed

./scripts/cargo-local.sh test -p pm-ssh-client --locked --offline
# profile: 2 passed; 0 failed
```

Después del build limpio se ejecutaron secuencialmente los trece laboratorios
Linux presentes, todos con salida cero y `PASS`:

```text
./scripts/test-linux-custody-lab.sh
./scripts/test-linux-human-transaction-lab.sh
./scripts/test-linux-content-lab.sh
./scripts/test-linux-authorization-lab.sh
./scripts/test-linux-attempts-lab.sh
./scripts/test-linux-csv-import-lab.sh
./scripts/test-linux-sync-lab.sh
./scripts/test-linux-history-lab.sh
./scripts/test-linux-1pux-import-lab.sh
./scripts/test-linux-backup-lab.sh
PM_KEYCLOAK_DIST=.scratch/lab-artifacts/keycloak/keycloak-26.7.3 PM_CFT_DIR=.scratch/lab-artifacts/cft/chrome-linux64 ./scripts/test-linux-web-auth-lab.sh
PM_CFT_DIR=.scratch/lab-artifacts/cft/chrome-linux64 ./scripts/test-linux-passkey-lab.sh
./scripts/test-linux-ssh-lab.sh
```

La corrida SSH final observó nuevamente OpenSSH 10.5p1 y russh 0.63.3, éxito
real por Ed25519 y password, y apertura/cierre de canal sobre ambas conexiones
retenidas. También repitió rechazo pre-secreto de hostkey, username y payload
de firma mal ligados, consumidor por UID, ownership oculto, revoke previo y
partial-success cancelado. Web auth volvió a ejecutar Keycloak 26.7.3 + CFT
153; passkey volvió a recorrer CFT/MV3/Native Messaging; backup volvió a
recorrer PMB1/PMF1. No se amplían los límites de plataforma ya declarados ni se
afirma soporte de macOS/Windows.
