# Integración 26–28 — composición y evidencia

Fecha: 2026-10-03. Rol: merger de candidatas publicadas. El corte vigente está en [Composición W3/W4/W2/W1 fijada](#composicion-w1-w4-20261003); las secciones anteriores conservan la integración y remediación históricas. Esta composición no corrige defectos abiertos ni cambia estados de tickets.

## Identidad y alcance

Worktree: `.worktrees/integration-26-28`; rama `codex/pm-integration-26-28`.
Base: `b3577d2f7a563df3e777380adf5cc120d1f7f9e0`.
SHA de código tras los cuatro merges (corte inicial): `6afa77c3090a87d296d8e676ccb4840ba6008f6f`.
SHA de código corregido: `3b1ec02e4bc085702aaa0e23d873d266fa77eae9`.
Los commits documentales posteriores no cambian el código probado. Cada corrida se atribuye abajo a su SHA exacto; Windows se verificó en `9c9ab96`, con la misma corrección Windows conservada en `3b1ec02`.

Las cuatro referencias locales y `origin` coincidían después de fetch y antes del primer merge. Se conservan esas ramas publicadas; cuatro merges, sin rebase/squash/force. No se movió `codex/implement-passwordmanager`, no se tocó la raíz sucia (`.gitignore`, `.pi/`, `odd/`), PR #1 ni sus reglas/base, ni se editaron estados de tickets.

## Merges y conflictos

| Orden | Candidata / SHA | Merge | Conflictos y resolución |
| --- | --- | --- | --- |
| 1 | `codex/pm-28` / `011e7707b0b7b0ca7998cb8c0beb8d3dfdb4de56` | `d1fd854fa9a0db89fc04ddc6a7279ad79c91b959` | Dos conflictos de documentación: conservar ambas cronologías y la evidencia parcial anterior, sin convertirla en cierre. |
| 2 | `codex/pm-shared-fixes` / `172eb11ab57fb1b78dabc5c75014addc113d397f` | `f610186f6fe741f221c1772fc7b1d8003673930e` | Declaraciones de módulos de vault y conflicto de tipos en fixture: conservar plaintext/publication y adaptar notes sintéticas a ProtectedText. |
| 3 | `codex/pm-26` / `c206c5a03ed2ea30aee6b50ad3f48cd648710b48` | `4a8e2db9333546379e65bdbe5e1ff1fa0fd8606a` | Custody lib/main/linux y vault human: combinar cfg macOS/diagnósticos/observación con owners protegidos, fallo cerrado y unlock auditado. |
| 4 | `codex/pm-27-composed` / `d7f7e328886a747f7374550ab326ac64e1e258cf` | `6afa77c3090a87d296d8e676ccb4840ba6008f6f` | Movimiento estructural y conflictos semánticos: trasladar engine y propiedades 28/26/shared a human_wire, agent_wire, tui, sync_job y seams nativos; conservar un engine. |

Detalle archivo:símbolo:

- 28: `.scratch/passwordmanager/issues/28-fallos-operativos-canarios-y-crash-safety-integral.md` y `docs/verification/ticket-28.md`: unión de bloques históricos; status claimed conservado.
- shared: `crates/pm-vault/src/lib.rs`: ambos módulos `plaintext`/`publication`; `crates/pm-sync/examples/shared_purge_probe.rs:record`: notes sintéticas con `ProtectedText::copy_from_str`, sin cambiar el escenario purge ni sus aserciones.
- 26: `crates/pm-custody/src/{lib,main}.rs`: cfg Linux/macOS con módulo failure completo; `linux.rs:{agent_rpc,human_authorization,rpc_unlock,handle_human_rpc,read_frame_classified}`: conservar ProtectedBytes, stdin nativo, serializers exactos y clasificación de errores/diagnósticos. Aserciones de Result protegido por `matches!`, sin implementar Debug. `crates/pm-vault/src/human.rs:HumanVault::unlock`: conexión observada de 26 más transacción/evento HumanUnlock vigente. Se retienen las regresiones de ambos lados.
- 27: `crates/pm-custody/src/{lib,main}.rs`: composición Linux/macOS/Windows y módulos comunes; `linux.rs:handle_human_request` delega a un único engine extraído. `human_wire.rs:{handle_request_slice,human_fields,encode_prepared,decode_wire_record,FrameReader,WirePrepared,ProtectedFrameWriter,read_frame_classified}` recibe la versión protegida de 28, las operaciones comunes/pending/passkey y diagnósticos Unix de 26; `agent_wire.rs:handle_attempt_request` usa cursor prestado y reader protegido comunes. Se retiraron las copias antiguas de handlers/parser, conservando fronteras de transporte nativo.
- 27: `crates/pm-custody/src/tui.rs:{App,ProtectedInput,submit_prompt,render_footer,transfer_import_file,ClipboardLease}`: owners protegidos de 28, scroll horizontal/footer de 27, AppKit de 26 y CP65001/ConPTY/clipboard Windows. Las rutas TUI Unix cubren Linux/macOS, las de Windows son separadas; los carriles de aceptación siguen exclusivamente `cfg(macos)`.
- 27: `crates/pm-custody/src/human_wire.rs:protected_frame_tests` contiene una sola regresión fuente, movida con su filtro de subprocess; `src/audit_custody_tests.rs` conserva el archivo y todas sus pruebas, importado por linux con path explícito. No se eliminaron tests ni se aflojaron oráculos, límites, KDF o deadlines.
- 27: `crates/pm-custody/src/{linux,windows}.rs:load_or_create_audit_custody` usa el predicado común de lectura SQLite `human_wire.rs:audit_device_initialized`. Custodia ausente de un device inicializado o bóveda ausente/inclasificable falla antes de listeners, sin generar un sustituto. Windows conserva DPAPI/identidad nativa.
- 27: `crates/pm-custody/src/windows.rs:{KeyMaterial,read_key,read_bootstrap,human_lock,rpc_unlock,rpc_commit,decode_prepared_response,agent_rpc}` y `pm-native-channel/src/windows.rs:dpapi_unprotect`: owners/frame/input protegidos, privados copiados directamente de la salida DPAPI a ProtectedBytes, sin owner Vec plaintext añadido. `pm-native-channel/Cargo.toml`/`Cargo.lock` incluyen el crate existente pm-crypto solo en Windows; sin versión externa nueva. `crypt` conserva liberación nativa y errores heredados.
- 27: `crates/pm-custody/src/windows.rs:rpc_download_atomic` conserva archivo privado/fsync/cleanup tipado y aplica publicación exclusiva y DestinationExists de shared; `crates/pm-sync/src/lib.rs:publish_staged_file` aplica el mismo helper exclusivo en la nueva seam. No hay rename alternativo.
- 27: `crates/pm-native-channel/src/lib.rs`: unión de exports Mac/Windows y native_file; `crates/pm-sync/src/main.rs:{serve_one_unix,client_exchange,read_key}`: guarda comprobada por conexión de 26 y clave privada protegida de 28, junto a named pipes de 27.
- 27: `crates/pm-vault/src/{onepux,native_fs}.rs:{available_capacity,checked_available_bytes,filesystem_available_bytes}`: seam portable de 27 con conversión/multiplicación checked de 26. El cálculo saturado del lado 27 no preservaba la intención checked de 26; la composición conserva rechazo de overflow y sus pruebas sin duplicar engine.

Los fallos de compilación/tipos/Clippy durante la composición se conservaron en `merge27-check*.log`, se resolvieron antes del merge y no se interpretan como defects de producto corregidos. No hubo decisión de producto usada para resolver un conflicto. La verificación nativa posterior detectó dos regresiones nuevas; la composición NO queda aceptada. No se corrigieron después de consumir los dispatch autorizados.

## Método de verificación

Método autorizado en la solicitud y en [ejecución](../../.scratch/passwordmanager/execution.md), [G7](ticket-28.md), [shared](shared-fixes.md), [macOS](ticket-26.md), [Windows](ticket-27.md) y [CI nativa](native-ci.md).
Cwd siempre este worktree. Cada invocación local cargo/check/clean/lab adquiere `flock /tmp/pm-cargo-window.lock`; los labs son secuenciales. Rust 1.98.1, grafo fijado offline y artefactos ya existentes; no se instalaron dependencias locales. Variables:

```sh
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
PYTHONDONTWRITEBYTECODE=1
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
# Cada uno de los 26 wrappers Linux excepto el nuevo wrapper parametrizado:
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-<nombre>-lab.sh
# Casos nuevos independientes:
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-download-publication-lab.sh backup
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-download-publication-lab.sh plaintext
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-download-publication-lab.sh attachment
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh audit
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh sqlite-sync
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh bootstrap completed
# REDs deliberadamente separados de check.sh:
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh vault completed
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh run -p pm-sync --example shared_purge_probe --locked --offline -- target/debug/pm-sync
```

El runner de evidencia local está en `/tmp/pmint-20261003-run-local.py`; resumen `/tmp/pmint-20261003-local-summary.log`, resultados por caso `/tmp/pmint-20261003-local-results.json`. Ninguna limpieza global de /tmp; cada fixture conserva su teardown. El inventario adicional de raíces es solo observación acotada, no evidencia integral de canales/custodia.

## Fallbacks y limitaciones heredadas conservadas

No se autorizó corregir estas fronteras. Se mantienen los inventarios de [28](ticket-28.md), [shared](shared-fixes.md), [26](ticket-26.md) y [27](ticket-27.md).

| Ubicación | Activación | Comportamiento que sustituye u oculta |
| --- | --- | --- |
| `pm-vault/src/{human,authorization}.rs:open_connection` | Main vault perdido; SQLite open sin requisito de existencia | Crea una SQLite vacía y puede responder rc4 sin preservar ausencia del main vault. El lab vault-loss sigue RED. |
| `pm-vault/src/reducer.rs:apply_received_package` | No encuentra kind del objeto en la consulta principal | `.or_else` usa un kind de la primera graph revision. El defecto purge/outbox está reproducido, sin corregir recepción/reducer. |
| `pm-custody/src/linux.rs:agent_attempt` | Respuesta vacía o UTF-8 inválido | Código DENIED por `unwrap_or(1)` y representación `from_utf8_lossy`; no se modifica. |
| `pm-native-channel/src/windows.rs:{crypt,Drop}` | Fallo de LocalFree/CloseHandle/DestroyWindow durante liberación | Se descarta el resultado nativo; la composición no añade retry ni reclama cleanup integral. DPAPI posee además un buffer nativo temporal que esta migración del owner Rust no acredita como bloqueado/wiped. |
| Importadores 1PUX y provider/transport, detallados en 28/shared | Campos incompatibles/TOTP no normalizable, errores de frames/worker/cleanup o staging existente | Permanecen sustituciones/errores ignorados ya inventariados; no se corrigen en esta composición. |

G7 sigue parcial: las copias PKCS8 requeridas por rustls, superficies de presentación/Ratatui, metadata y JSON/proveedor HTTP/CDP, import/export y buffers nativos conservan los pendientes documentados. ProtectedBytes en las fronteras trasladadas no demuestra ausencia integral de canarios ni seguridad validada en todo el producto. No se ejecutaron laboratorios humanos, reboot/FDE ni firma; tampoco Windows 11 x64 o Linux AArch64. Estos límites no cambian gates ni soporte declarado.
## Gates locales observados

Los cuatro `check.sh` posteriores a merge pasaron (rc0):

| Merge | Log aceptado | Incidencias previas |
| --- | --- | --- |
| 28 | `/tmp/pmint-20261003-merge28-check.log` | Ninguna en el gate. |
| shared | `/tmp/pmint-20261003-shared-check2.log` | `shared-check.log` rc101 por notes sintéticas incompatibles con ProtectedText; adaptadas sin cambiar el reproducer. |
| 26 | `/tmp/pmint-20261003-merge26-check.log` | Resolución de tipos/owners antes del gate. |
| 27 | `/tmp/pmint-20261003-merge27-check8.log` | Iteraciones de extracción/tipos/Clippy conservadas en `merge27-check*.log`; gate final completo rc0. |

Gate final `check.sh` rc0: `/tmp/pmint-20261003-final-check.log` (15.89 s).
Build limpio offline rc0: `/tmp/pmint-20261003-final-clean.log` (40.44 s).
Las pruebas de serializer movido y audit custody se ejecutaron realmente; no se aceptó un filtro con cero casos. La compilación lib/bin reutiliza el único archivo fuente de regresión.

Barrida de 26 wrappers: **25 PASS / 1 FAIL conocido**, TUI operations. Los tres casos nuevos de publicación y tres de custody/fault pasaron. RED vault y RED purge continúan rc1, fuera de check.sh. Los 36 casos del runner sumaron 340.99 s, incluidos build y lock; ningún residual nuevo bajo su patrón acotado de raíces /tmp. No se ampliaron deadlines ni hubo retries.

| Caso | rc | Segundos | Log |
| --- | ---: | ---: | --- |
| final-check | 0 | 15.89 | `/tmp/pmint-20261003-final-check.log` |
| final-clean | 0 | 40.44 | `/tmp/pmint-20261003-final-clean.log` |
| lab-1pux-import | 0 | 29.63 | `/tmp/pmint-20261003-lab-1pux-import.log` |
| lab-adapter-protected-frame | 0 | 18.20 | `/tmp/pmint-20261003-lab-adapter-protected-frame.log` |
| lab-attempts | 0 | 3.13 | `/tmp/pmint-20261003-lab-attempts.log` |
| lab-authorization | 0 | 2.44 | `/tmp/pmint-20261003-lab-authorization.log` |
| lab-backup | 0 | 2.34 | `/tmp/pmint-20261003-lab-backup.log` |
| lab-cleanup-fault | 0 | 0.29 | `/tmp/pmint-20261003-lab-cleanup-fault.log` |
| lab-content | 0 | 4.86 | `/tmp/pmint-20261003-lab-content.log` |
| lab-csv-import | 0 | 2.70 | `/tmp/pmint-20261003-lab-csv-import.log` |
| lab-custody | 0 | 0.61 | `/tmp/pmint-20261003-lab-custody.log` |
| lab-custody-protected-input | 0 | 0.26 | `/tmp/pmint-20261003-lab-custody-protected-input.log` |
| lab-fault-safety | 0 | 0.40 | `/tmp/pmint-20261003-lab-fault-safety.log` |
| lab-github-bearer | 0 | 3.29 | `/tmp/pmint-20261003-lab-github-bearer.log` |
| lab-history | 0 | 2.64 | `/tmp/pmint-20261003-lab-history.log` |
| lab-human-transaction | 0 | 2.57 | `/tmp/pmint-20261003-lab-human-transaction.log` |
| lab-passkey | 0 | 5.98 | `/tmp/pmint-20261003-lab-passkey.log` |
| lab-passkey-login | 0 | 35.06 | `/tmp/pmint-20261003-lab-passkey-login.log` |
| lab-recovery | 0 | 4.86 | `/tmp/pmint-20261003-lab-recovery.log` |
| lab-rpc-cleanup-fault | 0 | 1.01 | `/tmp/pmint-20261003-lab-rpc-cleanup-fault.log` |
| lab-ssh | 0 | 4.16 | `/tmp/pmint-20261003-lab-ssh.log` |
| lab-storage-fault | 0 | 1.14 | `/tmp/pmint-20261003-lab-storage-fault.log` |
| lab-sync | 0 | 1.12 | `/tmp/pmint-20261003-lab-sync.log` |
| lab-token-exchange | 0 | 26.33 | `/tmp/pmint-20261003-lab-token-exchange.log` |
| lab-tui-access | 0 | 6.92 | `/tmp/pmint-20261003-lab-tui-access.log` |
| lab-tui-content | 0 | 30.36 | `/tmp/pmint-20261003-lab-tui-content.log` |
| lab-tui-operations | 1 | 12.81 | `/tmp/pmint-20261003-lab-tui-operations.log` |
| lab-web-auth | 0 | 49.22 | `/tmp/pmint-20261003-lab-web-auth.log` |
| publication-backup | 0 | 2.02 | `/tmp/pmint-20261003-publication-backup.log` |
| publication-plaintext | 0 | 2.36 | `/tmp/pmint-20261003-publication-plaintext.log` |
| publication-attachment | 0 | 4.02 | `/tmp/pmint-20261003-publication-attachment.log` |
| custody-audit | 0 | 1.07 | `/tmp/pmint-20261003-custody-audit.log` |
| sqlite-sync | 0 | 1.77 | `/tmp/pmint-20261003-sqlite-sync.log` |
| bootstrap-completed | 0 | 1.09 | `/tmp/pmint-20261003-bootstrap-completed.log` |
| red-vault | 1 | 1.21 | `/tmp/pmint-20261003-red-vault.log` |
| red-purge | 1 | 18.79 | `/tmp/pmint-20261003-red-purge.log` |

TUI operations espera `exact-duplicates=1`; la pantalla real muestra el status `Mapping=chrome duplicate-action=keep; Preview values hidden: total=1 new=0 re…`. Es el defecto de presentación heredado de 27, no una nueva pérdida de input ni un oráculo cambiado. El primer CSV largo ya fue confirmado; falla en el siguiente preview y no se acredita el resto del recorrido.

Audit-loss observó rc4/closed=1, replacement-created=0, original-restored=1, cleanup errors=0. SQLite-sync observó la inyección EIO/WAL, atomicidad, canario ausente y restart en su alcance. Vault-loss observó provider-calls=1, rc4, main-vault=1, exact-restoration=1 y cleanup errors=0: falla expresamente porque la pérdida se sustituye por una DB nueva. Purge observó graphless-reception-accepted=false, `Err(Reduction(Storage(QueryReturnedNoRows)))`, pending=4, signed-headers=4, opaque-blocks=2 y roots=0. El candidato shared dejó un bloque opaco; el número depende del orden de eventos/digests y no cambia el oráculo: no hay raíz ni ack, y se retiene el outbox. No se declara un fix de recepción/export.

## CI nativa: corridas únicas, terminadas

SHA exacto de ambos runs: `6afa77c3090a87d296d8e676ccb4840ba6008f6f`. Repositorio público confirmado por API, workflows activos/manuales, runners estándar, permisos contents/read, sin caches/artifacts/secrets/larger. No se cambió ningún workflow, regla ni rama principal. Se esperaron todas las conclusiones; no queda run propio activo.

- [macOS custody acceptance — 37100087391](https://github.com/SantanaJcp/passwordmanager/actions/runs/37100087391), **FAIL**; input `pasteboard_diagnostic=true`, binarios ordinarios. [Apple Silicon 111137753467](https://github.com/SantanaJcp/passwordmanager/actions/runs/37100087391/job/111137753467) y [Intel 111137753560](https://github.com/SantanaJcp/passwordmanager/actions/runs/37100087391/job/111137753560): **FAIL ambos**. Logs `/tmp/pmint-20261003-native-macos.log` y `native-macos-arm.log`, metadata `native-macos-final.json` con el mismo prefijo.
- [Ticket 27 Windows custody — 37100088496](https://github.com/SantanaJcp/passwordmanager/actions/runs/37100088496), **FAIL**; inputs `diagnostic_only=false`, `service_diagnostics=false`, `tui_conpty_red=true`. [Producto ARM64 111137756185](https://github.com/SantanaJcp/passwordmanager/actions/runs/37100088496/job/111137756185): **FAIL**. El job opt-in de storage diagnostics queda skipped por ese input, no como test de producto aprobado. Logs `/tmp/pmint-20261003-native-windows.log`, metadata `native-windows-final.json` con el mismo prefijo.

Windows observó Windows 11 Enterprise 10.0.26200/build26200, imagen `win11-vs2026-arm64 20260924.168.1`, host Rust ARM64 MSVC1.98.1. Preflight, fetch fijado, fuente libsodium autenticada y su build ARM64/MT pasan; falla el build del producto antes de los grupos nativos y la TUI. Teardown de la raíz exacta se ejecutó; no se acredita cleanup integral de handles.

macOS observó 15.7.9/kernel24.6.0, hosts Rust1.98.1 aarch64/x86_64 Apple Darwin. ARM: imagen macos15 `20260907.0337.1`, runner_arch ARM64; Intel: macos15 `20260824.0482.1`, runner_arch X64. Los labels son macos-15 y macos-15-intel respectivamente. Build/test/Mach-O, libsodium, control con conexión humana abierta, Ticket23, partial Ticket24, discovery concurrente y Full25-import completan en ambos. Después el daemon sync termina rc4/SYNC_UNAVAILABLE y la readiness falla con `native fixture PID disappeared during readiness`. La salida es anterior a `full25-offline+wrong-pin`, `full25-local`, colisiones y happy sync; no acredita los grupos posteriores ni toda aceptación.

## Comparación con las candidatas y regresiones nuevas

Baselines leídos, no repetidos:
[26 run37094118542](https://github.com/SantanaJcp/passwordmanager/actions/runs/37094118542), código `53f8aa54881d190ced7ac17e0de7658d65eb4288` (c206c5a añade documentación), y
[27 run37094133145](https://github.com/SantanaJcp/passwordmanager/actions/runs/37094133145), código `e536f9590f7bd75106ebec6922a2855213d392d9` (d7f7e32 añade documentación).
Logs locales `/tmp/pmint-20261003-candidate-{macos,windows}.log`, metadata `.json` con el mismo prefijo.

| Frontera | Candidatas | Integración | Clasificación |
| --- | --- | --- | --- |
| Build Windows | 27 pasó primitives/TUI hasta preview | E0004 en `crates/pm-custody/src/failure.rs:77`, `after_native_cleanup` no cubre `Failure::DestinationExists` | **REGRESIÓN NUEVA de composición, bloqueo de build.** Al unir shared y 27 quedó incompleto el match Windows; el gate Linux no compila ese cfg. |
| Readiness sync macOS | 26 mantuvo daemon y readiness, offline/wrong-pin/local | Ambos procesos salen rc4; no completan readiness | **REGRESIÓN NUEVA observable.** Causa interna aún no probada; stdout/stderr categórico no identifica la fase. No atribuirla sin discriminante a locking, key parser o guard. |
| Backup destino existente | 26 sobrescribía y cambiaba digest; FAIL probado en ambos CPUs | Linux nuevos negativos backup/plaintext/attachment PASS; helper exclusivo compuesto en Mac/Win, pero matrices nativas no llegan a colisiones | Fix shared preservado y probado Linux; **nativo no revalidado**, no declarar resuelto allí. |
| Purge/outbox | 26 cinco revisiones pendientes sin payload; shared RED cuatro headers | Mac ambos muestran items=1/pending-revisions=5/missing-items=5; probe Linux sigue RED | **FAIL conocido conservado**, independiente del nuevo fallo readiness. |
| Resumen importación | 27 Linux/Windows recorta contador previo a confirmación | Linux operations FAIL exact-duplicates=1; Windows no llega al preview | **FAIL conocido de 27**, sin fix ni aserción reducida; nativo no reejecutado. |
| Clipboard Intel -1700 | Baseline26 indeterminado + AppleScript -1700, diagnostic=false | No se repite -1700 en este run, diagnóstico=true; control humano antes/después leído, probe aislado nonzero sin canario y shared-domain unsupported | No convertir ausencia puntual en cierre: input diagnóstico distinto y matrices/alcance parcial. |
| Vault perdido | 28 RED por DB sustituta | RED con mismo reemplazo y restauración exacta | **FAIL conocido conservado**, fuera del gate. |

Warnings nativos adicionales conservados en logs: helper checked Unix sin uso en Windows; import MetadataExt y helpers ClipboardControl test-only sin uso en build macOS. No son la causa de los FAIL, ni se aflojaron lints para ocultarlos.

## Entrega y decisiones pendientes — corte previo a la remediación

La rama contiene cuatro merges y este informe; **composición realizada, aceptación nativa fallida**. Se entrega al orquestador con evidencia, sin corregir los defectos abiertos ni repetir runs autorizados una sola vez.

1. Orquestador: asignar el cierre mecánico del match `Failure::after_native_cleanup` conservando primary DestinationExists y todos los errores de cleanup; verificar Windows sin wildcard, fallback ni weakening.
2. Orquestador: discriminar el rc4 de `pm-sync` macOS en su fase real, preservando owners bloqueados, parser/límites y guardas por conexión; la causa requiere evidencia. No restaurar Vec secreto ni generalizar los carriles macOS a Linux.
3. Usuario: decidir ubicación del resumen obligatorio completo durante preview, pendiente de 27. No se cambia el footer aceptado ni se confirma import con contador oculto.
4. Usuario/orquestador: autorización del dueño de purge/outbox y del fallback SQLite/reducer ya excluido; G5 confirmado no se reabre ni se eliminan headers/outbox.
5. Nueva autorización para CI después de un candidato corregido: los dos dispatch permitidos se consumieron y terminaron. Además quedan gates humanos/reboot/FDE, firma y targets no acreditados.

El helper Git configurado falló por apuntar a un gh inexistente. Se usó el override de credenciales autorizado, exclusivamente en los comandos push normales de esta rama; no se alteró configuración persistente ni se hizo force. La creación remota informó bypass de restricción de creación por los permisos existentes; no se cambiaron reglas. El PR borrador #1 y su base permanecen fuera de esta entrega.

## Remediación de integración autorizada — 2026-10-03

Solicitud posterior: corregir únicamente las dos regresiones de composición,
push normal a esta rama y nuevos dispatch exactos (máximo razonable cuatro por
plataforma). No cambia estados de tickets ni autoriza los defectos conocidos.

### Discriminante macOS previo a la corrección

La comparación con `c206c5a` identifica una llamada adicional a
`configure_unix_stream` en `pm-sync/src/main.rs:serve`, antes de crear el worker.
Su `?` puede terminar el servidor. La candidata mantenía esta guarda solamente
en el handler por conexión. El helper nativo conserva exactamente su guard
Darwin `SO_NOSIGPIPE`; el readiness conecta y cierra el peer sin enviar TLS.
La composición también duplica la guarda cliente en `client_exchange`.

Hipótesis discriminadas: (1) guarda del socket aceptado fatal al listener;
(2) lectura/locking de la clave protegida, permisos/rutas o inicialización del
store antes de bind; (3) publicación exclusiva del sync paginado. La tercera
no está en el camino de arranque/readiness: `publish_staged_file` se invoca
únicamente al terminar `download_paged_file`. La primera se comprobará con una
línea fija `SYNC_FAILURE phase=accepted-socket-guard` al retornar el error ya
existente; el fixture publica exclusivamente la categoría failed/unobserved.
No imprime rutas, errores nativos, claves ni payloads y no altera el resultado.

Método solicitado: gate y barrida local de los mismos 36 casos, secuenciales
con flock y las mismas variables; comparar rc caso por caso con el baseline.
Sin targets Darwin/Windows instalados localmente (solo x86_64 Linux), no se
instala ninguno. CI Windows normal comprueba exhaustividad del cfg y el avance
hasta el preview; CI macOS observa primero el discriminante sin parchear la
guarda y después el mismo readiness/matriz sobre la corrección demostrada.
Mismos límites, aserciones y inputs que los runs de integración originales.
Logs nuevos exclusivamente `/tmp/pmint2-20261003-*.log`.

Windows: `after_native_cleanup` incorpora el brazo explícito DestinationExists,
con primary idéntico y cleanup NativeResourceRestoration; los brazos restantes
ya conservan la variante en todos los cfg. La seam sigue conectada desde
`windows.rs:rpc_download_atomic` y `pm-sync/src/lib.rs:publish_staged_file` a
`pm-vault/src/publication.rs:publish_native` (`MoveFileExW`, flags 0, sin
REPLACE_EXISTING/COPY_ALLOWED). Esto es revisión fuente; aún falta la nueva CI.

Primer candidato de remediación (Windows + discriminante macOS): `check.sh`
rc0 (42.55 s), clean offline rc0 (42.55 s), 36 casos en 371.93 s y **cero
cambios de rc respecto al baseline**. Los únicos rc1 son TUI operations
(mismo `exact-duplicates=1` recortado), RED vault y RED purge. Sync y las tres
publicaciones PASS; cero raíces residuales nuevas en el inventario acotado.
Resumen `/tmp/pmint2-20261003-local-summary.log`, detalle
`/tmp/pmint2-20261003-local-results.json`. AST Python, configuración CI y
enlaces relativos del informe comprobados; no cambia ningún workflow.

### Discriminante nativo y corrección mínima

Commit publicado `9c9ab960d6c23ce43d46c9fdfbb3696e572d4734`:

- [macOS 37101488048](https://github.com/SantanaJcp/passwordmanager/actions/runs/37101488048),
  **FAIL terminado, ambas CPU**. Jobs [ARM 111141736709](https://github.com/SantanaJcp/passwordmanager/actions/runs/37101488048/job/111141736709)
  e [Intel 111141736823](https://github.com/SantanaJcp/passwordmanager/actions/runs/37101488048/job/111141736823).
  Ambos completan Full25-import y observan `PM26_SYNC_FAILURE
  accepted-socket-guard=failed`, `exit=4`, seguido de la desaparición del PID
  durante readiness. La categoría demuestra que el error viene del guard
  del socket aceptado, después de bind; descarta inicialización/clave protegida
  y publicación paginada como causa de esta salida. Log
  `/tmp/pmint2-20261003-native-macos-diagnostic.log` y metadata `.json`.
- [Windows 37101489213](https://github.com/SantanaJcp/passwordmanager/actions/runs/37101489213),
  **FAIL terminado por el defecto conocido del resumen**, job
  [111141740142](https://github.com/SantanaJcp/passwordmanager/actions/runs/37101489213/job/111141740142).
  Build nativo pasa sin E0004; primitives 13, pipe 1, observer 16 y sync-lib 1
  pasan. TUI normal: first-prompt, hidden-input, unlock y footer-horizontal
  PASS; llega al preview CSV y falla exactamente en `exact-duplicates=0`,
  sin teclear IMPORT. Recupera el mismo punto de la candidata 27. Teardown
  termina sin error adicional reportado; no acredita los Drops que ocultan
  errores. Log `/tmp/pmint2-20261003-native-windows.log` y metadata `.json`.

La causa macOS es la llamada redundante compuesta en `serve`, cuyo `?`
propagaba el rechazo de una conexión al servidor completo. Se elimina esa
llamada; `serve_one_unix` conserva la misma guarda comprobada como primera
operación, antes de timeouts/TLS/bytes. Un rechazo termina y cierra solamente
ese stream mediante el camino existente del worker. También se retira la
segunda guarda idéntica de `client_exchange`, quedando una antes de TLS como
en 26. Sin cambio del helper nativo, parser protegido, publicación exclusiva,
permisos, límites o plazos. Se retira el diagnóstico temporal y su lector del
fixture: la siguiente CI usa binarios normales y el probe original intacto.

Se vuelve a ejecutar el método completo ya autorizado después de este cambio;
logs `/tmp/pmint2-20261003-fixed-*.log`. No se repite Windows: su corrección
es idéntica y los cambios posteriores de producto están exclusivamente en cfg
Unix; no justificarían una corrida Windows idéntica.

Segunda barrida, con la corrección macOS: `check.sh` rc0 (43.10 s), clean
offline rc0 (42.88 s), **36 casos / 368.15 s, cero cambios de rc respecto al
baseline**, mismo único mismatch de TUI y ambos REDs conservados. Sync y las
tres publicaciones PASS; cero raíces residuales nuevas en el inventario
acotado. Resumen `/tmp/pmint2-20261003-fixed-local-summary.log` y detalle
`/tmp/pmint2-20261003-fixed-local-results.json`. Diff y enlaces comprobados.

### Resultado nativo del código corregido

[macOS 37102206965](https://github.com/SantanaJcp/passwordmanager/actions/runs/37102206965),
SHA exacto `3b1ec02e4bc085702aaa0e23d873d266fa77eae9`, **FAIL global terminado**.
Jobs [Intel 111143806165](https://github.com/SantanaJcp/passwordmanager/actions/runs/37102206965/job/111143806165)
y [Apple Silicon 111143806326](https://github.com/SantanaJcp/passwordmanager/actions/runs/37102206965/job/111143806326)
terminaron FAIL, sin nueva regresión distinta de los FAIL conocidos.
Input `pasteboard_diagnostic=true`, idéntico al run inicial de integración;
binarios normales, sin el diagnóstico temporal de sync ni cambio del fixture.
Logs `/tmp/pmint2-20261003-native-macos-fixed.log`, `-failed.log`, `-arm.log`
y metadata `/tmp/pmint2-20261003-native-macos-fixed.json`.

Ambos completan build/tests/Mach-O, control con conexión humana abierta,
discovery concurrente, Ticket23, partial Ticket24, Full25-import,
**readiness del proceso real de sync**, offline/wrong-pin y Full25-local.
Superan el punto alcanzado por la candidata 26: también completan las
negativas de destino existente de backup y plaintext. No se deduce ese PASS
solo de la ausencia de una línea de error: la traza llega al wait de happy
sync (`macos_tui_migration_lab.py:534`), posterior a ambas llamadas secuenciales
de `expect_output_collision`, cuyo oráculo intacto exige rechazo explícito y
digest original inalterado. La publicación exclusiva no se relajó.

Después falla el wait original de 20 s de happy sync, con TUI viva y
`durable=integrity screen=integrity process=same`. Ambos ya habían observado
`items=1 pending-revisions=5 missing-items=5`; roots=0 en ambos, opaque blocks=1
en ARM y 65 en Intel. Es la clase de fallo preexistente de sync/purge-outbox
documentada en 26 y reproducida por el RED shared local, no una nueva pérdida
de readiness. El número de bloques no es un oráculo de aceptación; no se
declara una causa nueva por su variación. La atribución interna completa del
fallo de exportación sigue fuera de esta remediación. No se alcanzan los
grupos posteriores de mismo-job/status, closing endpoint, restart/idle/backoff,
offline final y suspensión/restart finales. Cleanup estricto termina sin
error adicional reportado; no acredita los Drops heredados ni cleanup integral.

Entornos observados: macOS 15.7.9/kernel24.6.0, Rust1.98.1 nativo,
`macos-15-intel` x86_64 (imagen `20260824.0482.1`) y `macos-15` arm64
(`20260907.0337.1`). Windows: Windows11 Enterprise10.0.26200/build26200,
`windows-11-vs2026-arm`, imagen `win11-vs2026-arm64 20260924.168.1`,
host Rust1.98.1 ARM64 MSVC, libsodium1.0.22 autenticada/ARM64/MT. Preflight
sigue siendo evidencia de entorno, no soporte ni aceptación de todo el producto.

### Clasificación final y siguiente acción

| Frontera | Resultado de esta remediación | Clasificación / límite |
| --- | --- | --- |
| Windows E0004 / cleanup de colisión | Match exhaustivo explícito; primary DestinationExists y lista de cleanup preservados; compila y llega al mismo preview que 27. | **Regresión de composición corregida.** Colisiones Windows no se ejecutan en la TUI porque el resumen bloquea antes; la seam exclusiva sí está conectada y compila. |
| macOS rc4 anterior a readiness | Categoría nativa confirma guard del stream aceptado fatal al listener; una sola guarda por conexión y cliente. Ambos CPUs pasan readiness y más allá de 26. | **Regresión de composición corregida.** Rechazo de guard conserva cierre de esa conexión antes de TLS. |
| Backup/plaintext destino existente macOS | Ambas negativas concluyen con digest original conservado en ambos CPUs. | **Fix shared preservado y ahora revalidado nativamente** en esos dos casos; no extensión de alcance ni validación Windows. |
| Resumen de importación | Linux sigue fallando exact-duplicates=1; Windows exact-duplicates=0 en el preview, igual a 27. | **FAIL conocido; requiere decisión del usuario** sobre la presentación completa. Sin IMPORT ni grupos posteriores Windows. |
| Purge/outbox y happy sync | RED local intacto; ambos Mac con cinco revisiones purgadas sin payload, integrity y cero roots. | **FAIL conocido; requiere decisión/autorización del workstream dueño.** Sin borrar headers/outbox ni modificar reducer/export. |
| Segundo agente / proveedor | single-bootstrap sigue bloqueando segunda identidad y daemon ordinario sigue sin provider. | **Brechas conocidas, fuera de alcance**, sin engine ni proveedor sustituto. |
| Clipboard Intel -1700 | No se reproduce en estas corridas con diagnóstico=true; control humano pre/post positivo, probe aislado nonzero sin canario. | **Pendiente conocido, no cerrado** por ausencia puntual ni por inputs distintos a la candidata 26. |
| Vault-loss | RED local rc1 conservado, fuera del gate. | **FAIL conocido, fuera de alcance**; fallback SQLite intacto. |
| Otros FAIL de composición | Ninguno observado tras comparar los puntos alcanzados, firmas de fallo y oráculos intactos. | Verificación acotada; no aceptación global ni cierre de tickets. |

El diff final de producto frente a `15b83e7` toca únicamente `failure.rs` y
`pm-sync/src/main.rs`; el fixture y workflows quedan idénticos a la base.
Las dos barridas de 36 casos no empeoran el baseline. Se usaron dos corridas
macOS (discriminante y corrección) y una Windows; las tres terminaron, sin
repetición idéntica ni run propio activo. Pushes normales únicamente a la rama
de integración, con el override de helper ya autorizado y bypass de permisos
existentes; sin force, cambio de reglas, merge del PR ni avance de tickets.
La rama unificada permanece en `b3577d2`; trabajo ajeno de la raíz preservado.

Siguiente acción del orquestador: revisar/integrar esta remediación acotada sin
fusionar el PR borrador #1. Resolver con el usuario las decisiones del resumen
y purge/outbox antes de ampliar las matrices; los gates humanos/reboot/FDE,
firma y targets no acreditados siguen pendientes. La aceptación global nativa
continúa FAIL; las dos fronteras de regresión solicitadas sí están restauradas.

## Composición de G7 fases 4–5 y clipboard — 2026-10-03

### Identidad, merges y preservación

Base local/remota verificada después de fetch: `36eecc8c365328ca4c8ca074ae013564767d79b7`.
Mismo worktree `.worktrees/integration-26-28` y rama `codex/pm-integration-26-28`.
SHA final de código/fixtures/workflows: `272aac8f7383464fd1e0448717110cccfab0fa9f`.
La actualización posterior de este informe es exclusivamente documental; no es otra versión de producto ejecutada por los runs indicados abajo.

| Orden | Candidata, local = origin | Operación y resultado |
| --- | --- | --- |
| 1 | `codex/pm-28-phase4` / `b4e8ad79ebdad92d8c7a3863b328a799ed011f98` | Fast-forward desde `36eecc8`, sin commit de merge adicional. |
| 2 | `codex/pm-26-clipboard` / `0fadac6f604e7ae3344151665be0b0b5fe958657` | Merge commit `272aac8`; mensaje cita el SHA completo. Padres: `b4e8ad7`, `0fadac6`. |

**Cero conflictos**, textuales o decisiones de producto necesarias. Los 28 paths de G7 y los seis de clipboard son disjuntos; sus objetos Git en la composición son idénticos a los de cada candidata. Ambos commits siguen en la ascendencia. Se conserva el engine único, sin edición del merger en producto, tests, límites, deadlines, KDF o fallbacks. Las únicas ediciones posteriores al merge son de este informe.

### Gates locales y comparación

Mismo método, cwd y requisitos del baseline, con `PM_KEYCLOAK_DIST`, `PM_CFT_DIR` y `PYTHONDONTWRITEBYTECODE=1` indicados arriba. Cada comando adquiere `flock /tmp/pm-cargo-window.lock`; barridos secuenciales, sin instalación local de dependencias. Runners: `/tmp/pmint3-run-local.py` y `/tmp/pmint3-run-g7.py`. Logs nuevos exclusivamente `/tmp/pmint3-*.log`; ninguna limpieza de paths ajenos.

Comparación caso por caso con `/tmp/pm28p5-local-results.json`: **36 casos, 33 rc0, cero cambios de rc**, 372.65 s. Check rc0 en 44.79 s; build limpio locked/offline rc0 en 42.12 s. Los 26 labs Linux conservan 25 PASS y el mismo FAIL TUI operations. Publication backup/plaintext/attachment y custody-audit/sqlite-sync/bootstrap-completed conservan 3/3 y 3/3 rc0. Detalle: `/tmp/pmint3-local-results.json`; resumen: `/tmp/pmint3-local-summary.log`. Sin raíces residuales nuevas en el inventario acotado; no es prueba integral de cleanup.

El único mismatch de gates sigue siendo `exact-duplicates=1`: la pantalla recorta `Mapping=chrome duplicate-action=keep; Preview values hidden: total=1 new=0 re…`. Vault-loss completado conserva replacement=1/rc1; purge conserva `QueryReturnedNoRows`, pending=4, signed-headers=4, roots=0/rc1. Ambos RED permanecen fuera de gates, con sus oráculos intactos.

Diez modos adicionales, `/tmp/pmint3-g7-results.json` y `/tmp/pmint3-g7-summary.log`:

| Argumentos de `verify-ticket28-custody-loss.sh`, después de flock | rc inicial | Comparación; log en `/tmp/` |
| --- | ---: | --- |
| `matrix` | 1 | RED conocido: commit/outbox/audit EIO y ENOSPC conservan staging 1/1/17 tras error/restart; atomicidad/autoridad pasan. `pmint3-g7-matrix.log`. |
| `inflight result-sync` | 1 | **FAIL adicional** tras EIO: `partial state settlement after fsync failure`. `pmint3-g7-inflight-result-sync.log`. |
| `inflight bootstrap` | 0 | Cierre/restitución/INDETERMINATE, calls=1. `pmint3-g7-inflight-bootstrap.log`. |
| `inflight audit` | 0 | Mismos controles. `pmint3-g7-inflight-audit.log`. |
| `inflight crash` | 0 | SIGABRT real, WCOREDUMP=false, calls=1. `pmint3-g7-inflight-crash.log`. |
| `canaries` | 0 | Canales activos/históricos y controles UID/scanner completos en su alcance. `pmint3-g7-canaries.log`. |
| `inflight vault` | 1 | RED conocido, replacement=1. `pmint3-red-inflight-vault.log`. |
| `inflight-live bootstrap` | 1 | RED conocido, CREATED; fixture cancela antes de otro login. `pmint3-red-live-bootstrap.log`. |
| `inflight-live audit` | 1 | Mismo RED de admisión en caliente. `pmint3-red-live-audit.log`. |
| `inflight-live vault` | 1 | Admisión rechazada; RED conocido replacement=1 en recuperación. `pmint3-red-live-vault.log`. |

Primera barrida: cuatro positivos rc0, cinco RED conocidos rc1 y un FAIL adicional rc1; 43.85 s. Todos los teardown de esos modos reportan errors=0. Una repetición enfocada de `inflight result-sync`, con vaults nuevos y el mismo SHA/comando/oráculo/plazos, termina rc0 en 5.07 s: control, EIO y ENOSPC, calls=1, INDETERMINATE y autoridad exacta. Evidencia: `/tmp/pmint3-g7-result-sync-repeat.{log,json}`. **La repetición no convierte la primera barrida en PASS.** El fallo es intermitente y no documentado en el baseline; su causa y si refleja producto o carrera del observador están sin demostrar. El producto y fixture Linux son idénticos a 28; no hay evidencia para atribuirle una corrección mecánica de merge ni reclasificarlo como RED conocido. Se entrega al dueño de G7.

### CI nativa y publicación

Repositorio público y workflows manuales activos comprobados por API. Guards CI, shell/YAML/AST y diff pasan. Runners estándar de los workflows, contents/read, datos sintéticos, sin caches/artifacts/secrets. La gratuidad de runners estándar en repositorios públicos se revalidó contra [GitHub](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Un dispatch aceptado por modo, todos sobre `272aac8f7383464fd1e0448717110cccfab0fa9f`:

| Run | Inputs y referencia | Resultado |
| --- | --- | --- |
| [macOS normal 37110528957](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110528957) | pasteboard_diagnostic=false, final_phase_only=false; referencia [37107763341](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107763341), SHA `e3f02d4f34ea45c50754b150f5eec96e9c1a77b6` | **FAIL terminado, ambas CPU**, happy sync/integrity conocido. Intel conserva el punto de referencia; ARM supera el aviso de rotación y también llega a happy sync. |
| [macOS independiente 37110533130](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110533130) | pasteboard_diagnostic=false, final_phase_only=true; referencia [37107761539](https://github.com/SantanaJcp/passwordmanager/actions/runs/37107761539), SHA `e3f02d4f34ea45c50754b150f5eec96e9c1a77b6` | **PASS acotado terminado, Intel + ARM**, mismo alcance que referencia; Full25 NOT_RUN, acceptance NOT_CLAIMED. |
| [Windows 37110536568](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110536568) | diagnostic_only=false, service_diagnostics=false, tui_conpty_red=true; referencia [37101489213](https://github.com/SantanaJcp/passwordmanager/actions/runs/37101489213), SHA `9c9ab960d6c23ce43d46c9fdfbb3696e572d4734` | **FAIL terminado**, mismo preview CSV/`exact-duplicates=0` que referencia; sin regresión de build. Storage diagnostics skipped por input, no PASS de producto. |

Mac normal: jobs [Intel 111167387879](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110528957/job/111167387879) y [ARM 111167387756](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110528957/job/111167387756). Ambos pasan build/tests/Mach-O, control humano abierto, discovery concurrente, Ticket23/partial24 y AppKit aislado: nil/exit69 explícito, canarios ausentes, controles humanos positivos estables y dentro del lease. Ambos alcanzan Full25-import/offline+wrong-pin/local, incluido restore/rotation y las colisiones backup/plaintext sin cambiar el oráculo. Fallan únicamente en el wait original de 20 s de happy sync: `durable=integrity screen=integrity process=same`, missing-items=5, blocks=2 y roots=0. El baseline Intel tenía blocks=25; ese conteo no es oráculo de aceptación ni prueba de una causa nueva. ARM supera el fallo previo del aviso de rotación, sin que una sola observación cierre su intermitencia histórica. No llegan a los grupos posteriores de sync ni a las fases finales del modo normal.

Mac independiente: jobs [Intel 111167400244](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110533130/job/111167400244) y [ARM 111167400415](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110533130/job/111167400415). Ambos emiten el PASS acotado después de cleanup estricto: core, AppKit aislado, expiración real empty/nil con coercion-1700 humana, canario embebido, suspensión persistida, primer restart real con identidad intacta, resume y segundo restart con autorización/metadata preservadas y humano locked, y probes nativos TTY/core/AppKit. Se conserva expresamente `full25=NOT_RUN acceptance=NOT_CLAIMED`.

Windows: job [111167410650](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110536568/job/111167410650). Build nativo y grupos primitives13/pipe1/observer16/sync-lib1 pasan. ConPTY first-prompt/hidden-input/unlock/footer-horizontal PASS; mismo FAIL de resumen recortado a 15 s antes de IMPORT. Teardown del servicio y raíz exacta termina sin fallo adicional reportado. No acredita colisiones/operaciones posteriores ni los Drops heredados.

| Entorno observado | Label / imagen | Toolchain y OS |
| --- | --- | --- |
| Mac Intel, ambos modos | macos-15-intel / macos15 20260824.0482.1 | Rust1.98.1 x86_64-apple-darwin; macOS15.7.9/kernel24.6.0. |
| Mac ARM, ambos modos | macos-15 / macos15 20260907.0337.1 | Rust1.98.1 aarch64-apple-darwin; macOS15.7.9/kernel24.6.0. |
| Windows ARM64 | windows-11-vs2026-arm / win11-vs2026-arm64 20260924.168.1 | Rust1.98.1 aarch64-pc-windows-msvc; Windows11 Enterprise10.0.26200/build26200, libsodium1.0.22 autenticada/ARM64/MT. |

**Sin FAIL nativo nuevo ni regresión de composición observada** frente a las referencias. Los tres runs y todos sus jobs han terminado; no queda run propio activo. Logs y metadata: `/tmp/pmint3-native-{macos-normal,macos-independent,windows}.{log,json}`. Comparación por marcadores: `/tmp/pmint3-native-comparison.json`. Preflight solo acredita entorno; ni los PASS parciales ni el modo independiente certifican soporte o aceptación global.

GitHub rechazó con HTTP422 la solicitud inicial que usaba SHA como ref, sin crear run. Después se usó el nombre de esta rama, comprobando su SHA por API antes/después de cada dispatch y el headSha de cada run. Registro: `/tmp/pmint3-dispatch-record.json`; no se repite ningún dispatch aceptado. Logs/metadata de referencias y corridas usan el mismo prefijo `pmint3`.

Push normal del merge y del informe únicamente a la rama de integración. El helper configurado apuntaba a un gh inexistente; se usó el override por comando autorizado, sin cambiar configuración persistente. GitHub informó bypass de los permisos existentes sobre el ref protegido; no se cambiaron reglas. El commit del informe se identifica por ser el hijo documental de `272aac8`; la CI corresponde al SHA exacto de código indicado, sin dispatch repetido por la actualización documental.

### Fallos heredados y decisiones pendientes

Se conservan los inventarios de fallbacks de [28](ticket-28.md), [26](ticket-26.md) y este informe: SQLite crea DB vacía cuando falta vault; reducer busca kind en otra revisión; getters/diagnósticos de providers sustituyen campos ausentes y varios caminos de worker/transporte/cleanup agrupan o descartan errores. También se observó `linux.rs::run_provider_once`: ante AccessSuspended/AgentRevoked/CredentialUnavailable descarta el error de `attempts.settle` y retorna Ok, ocultando un eventual fallo de persistir AUTHORITY_REVOKED. Se conserva, sin corregirlo ni usarlo para aceptar la composición.

Pendientes: presentación completa de resumen/avisos; purge/outbox; vault-loss; composición de staging preparado con cleanup G7; retirada en caliente de bootstrap/audit; clasificación del FAIL intermitente result-sync; memoria restante, segundo agente/proveedor y gates humanos, reboot/FDE, firma y targets no acreditados. No se decide producto ni se cambian tickets. La raíz y `codex/implement-passwordmanager` se preservan; PR borrador #1 no se fusiona ni se modifica.

Entrega: composición publicada y verificación ejecutada; **aceptación global continúa FAIL**. No hay fix mecánico de composición pendiente identificado. El dueño de G7 debe clasificar la primera falla result-sync antes de declarar ese gate estable; las demás decisiones/RED anteriores requieren su autorización específica. No se transforma la documentación en cierre de G7 ni en revisión formal final.


<a id="composicion-w1-w4-20261003"></a>

## Composición W3 → W4 → W2 → W1 — 2026-10-03

### Identidad y resolución

Base comprobada local/origin: `ee3c1fd31cad59060e4120f3e2518b1196a90c1a`.
SHA final de código/fixtures: `dedb8f6c2bbcd71837a1c51da51cf4fdb934c605`.
Worktree y rama de integración originales. W1 avanzaba en paralelo, pero el
merge usa exclusivamente `eb78c5e173a1712f54b98f8f807a2e8f33d51865`.
Cuatro merge commits, sin rebase/squash/force ni cambios de estado de tickets.

| Orden | Candidata fijada | Merge | Conflictos / resolución |
| --- | --- | --- | --- |
| 1 | W3 `e0eec49303b3d1212aacb7a0988fe383bd29af6d` | `93b5c0afac1b142af7e79255ec0f6cf3df916ec9` | Sin conflictos. Owners, vault existente, guard y errores tipados íntegros. |
| 2 | W4 `549c5122f67d70a842ff3fe1558e9d0f19092068` | `9de97bb2ffe96faf60b8c24b0dcf9a0220e82d53` | Un conflicto textual en main.rs: conservar ambos módulos. Conectar el guard W3 con los carriles nativos de W4. |
| 3 | W2 `7a45b49333279b7a570793a1813a5e52cb586674` | `7b8ff954667c76831a9da47c8d9f4c682e062e3c` | Automático: backup/reducer conservan apertura W3 y digest/root v3/rechazo de kind W2. |
| 4 | W1 `eb78c5e173a1712f54b98f8f807a2e8f33d51865` | `dedb8f6c2bbcd71837a1c51da51cf4fdb934c605` | Automático: fixtures Mac conservan sync/counters W2 y panel/colisión W1; Windows conserva pool/admisión y transferencia. |

Resolución archivo:símbolo:

- `crates/pm-custody/src/main.rs`: declarar `connection_dispatch` y
  `custody_admission` con los cfg originales; lib.rs ya los combinó automáticamente.
- `crates/pm-custody/src/linux.rs:accept_one`: ambos carriles Linux/Darwin
  verifican `VaultService.admission` antes de handler/dispatch. Fallo cierra esa
  conexión, manteniendo el servicio y trabajo en vuelo; no hay ruta sustituta.
- `crates/pm-custody/src/windows.rs:serve_role`: SID nativo y guard W3 antes
  de reservar worker agente. `handle_server_connection` comprueba el mismo guard
  en ambos roles antes de TLS/engine. Se conserva el guard W3 de opcodes
  30/33/40/41 para conexiones persistentes y el pool de cuatro.
- `crates/pm-vault/src/backup.rs:{write_backup,restore_graph_digest}` y
  `reducer.rs:{open,connect,apply_received_package}`: hunks distintos, composición
  automática, sin CREATE para bóveda existente ni `.or_else` de kind; sin otro
  decoder al fallar v3, borrado de headers o ack sin root.
- `crates/pm-custody/tests/{macos_lab,macos_tui_migration_lab}.py`: W2 mantiene
  tiempos/diagnóstico/counters de sync; W1 mantiene panel actual, colisiones con
  digest original y oráculos completos. `tui_access_lab.py` conserva discovery
  con TUI abierta y el render W1.
- `crates/pm-native-channel/src/windows.rs`: derechos individuales/capacidad
  de pipes W4 y validación/diagnóstico de lease W1, sin relajar DACL ni límites.

No hubo decisiones de producto ni correcciones de defectos abiertos por el
merger. Manifest `/tmp/pmint4-preservation.json`: los 40 paths exclusivos
(W3 12, W4 4, W2 11, W1 13) son idénticos a sus candidatas; diez paths
compartidos inspeccionados. Ascendencia de los cuatro SHAs, AST de fixtures
compartidos, diff-check y ausencia de cambios en tickets/workflows/Cargo.lock
comprobados. Un único engine y ningún ajuste de KDF/deadlines/asserts/tests.

### Método, gates locales y comparación

Método del baseline y de los cuatro informes, cwd este worktree, Rust1.98.1
locked/offline, artefactos Keycloak/CFT absolutos indicados arriba,
PYTHONDONTWRITEBYTECODE=1. Cada cargo/check/build/lab bajo
`flock /tmp/pm-cargo-window.lock`, secuencial. Driver propio
`/tmp/pmint4-run-local.py`, resultados `/tmp/pmint4-local-results.json`,
resumen `/tmp/pmint4-local-summary.{log,json}`; fuentes y HEAD estables durante
el barrido. Ninguna instalación local ni limpieza de paths ajenos.

Check posterior a cada merge: `/tmp/pmint4-merge-w3-check.log`,
`-merge-w4-check.log`, `-merge-w2-isolated-check.log`, `-merge-w1-check.log`.
Todos rc0. La primera corrida W2 `-merge-w2-check.log` queda **descartada**
como evidencia aislada: el merger inició el merge pendiente W1 antes de que
terminara. Tras concluirla se abortó solamente ese merge pendiente propio,
se reejecutó check sobre W2 limpio y luego se volvió a componer W1. Ningún
resultado de esa primera corrida reemplaza los gates nuevos.

Barrido completo terminado: **52 casos / 47 rc0 / tres RED conocidos / dos
regresiones**; runner rc1, 553.902 s agregados con esperas de lock incluidas.
Los 48 comandos W3 incluyen exactamente los 40 del baseline; se agregaron
concurrencia, probe purge, E2EE/shared-purge y digest restore. No se reutilizaron
logs ni se repitió un fallo sin cambio/discriminante.

| Baseline, mismos nombres/comandos | Candidata rc0/casos | Integración rc0/casos | Resultado |
| --- | --- | --- | --- |
| `/tmp/pmrs-gate-results.json` | 38/40 | 37/40 | Regresión bootstrap; operations sigue rc1 pero cambia la causa, no se conserva su RED histórico. |
| W1 `/tmp/pmw1b-final-gate-results.json` | 39/40 | 37/40 | Operations 0→1 y bootstrap 0→1. |
| W2 `/tmp/pmw2d-gate-results.json` | 38/40 | 37/40 | Mismas dos fronteras; purge/restore pasan. |
| W3 `/tmp/pmw3c-final-results.json` | 44/48 | 43/48 | Bootstrap 0→1; guard/live/vault/result-sync/errores tipados preservados en sus casos. |
| W4 `/tmp/pmw4-resume-gate-results.json` | 39/41 | 38/41 | Mismas fronteras; new-concurrency se compara con concurrency (comando idéntico), rc0. |

| Gate / frontera | Resultado y evidencia |
| --- | --- |
| Final check / clean locked-offline | PASS rc0, 57.731 / 44.001 s; `/tmp/pmint4-final-{check,clean}.log`. |
| Labs Linux + publication | 28/29 rc0; operations falla en stop tras el caso de endpoint que cierra. Publication backup/plaintext/attachment PASS. |
| W3 inflight result-sync/audit/crash + canaries | PASS, 4/4; bootstrap separado abajo. |
| W3 vault completed / inflight vault / tres inflight-live | PASS, 5/5; sin reemplazo, nueva admisión cerrada, calls=1, cleanup=0. |
| W3 matrix trace | PASS rc0. |
| Concurrencia W4 | PASS rc0; TUI abierta, mismo daemon, cuarto admitido/quinto rechazado y recuperación del pool. `/tmp/pmint4-concurrency.log`. |
| Probe purge W2 | PASS rc0: `Ok(4)`, pending=0, signed-headers=4, opaque-blocks=6, roots=1. `/tmp/pmint4-purge-probe.log`. |
| W2 E2EE / shared-purge | PASS 32 + 1 tests; paginado 259 eventos/2 páginas/payloads0, sesión TLS, restore y convergencia real. `/tmp/pmint4-purge-sync-tests.log`. |
| Digest restore | PASS 2 comparaciones con el reductor. `/tmp/pmint4-restore-digest-tests.log`. |
| g7-matrix | RED conocido rc1: exactamente commit-outbox-audit EIO/ENOSPC por staging retenido; listas RED/ProductRed iguales a W3, cleanup errors=0. |
| g7-extra-bootstrap / g7-extra-vault | Dos rc1 diagnósticos conservados, autoridad/receipts, replacement=0, closed=1, cleanup errors=0; fuera de gates. |
| lab-tui-operations | **Regresión de gate**, esperado W1 rc0, observado rc1. Ya pasó el panel/import/sync y llega a `tui_operations_lab.py:222`; `linux_lab.py:stop` observa stderr `SYNC_UNAVAILABLE\n`. También se propaga ese error en teardown; no es la truncación exact-duplicates histórica. `/tmp/pmint4-lab-tui-operations.log`. |
| g7-inflight-bootstrap | **Regresión de gate**, 0→1: tras restauración, `g7_canary_channels.py:241` rechaza un fd/recurso no clasificado en `inflight-historical-restored`; closed=1/replacement=0/calls=1 y cleanup=0 previos. `/tmp/pmint4-g7-inflight-bootstrap.log`. |

Causas: `pm-sync/src/session.rs:Session::spawn` hereda stderr del child y
`pm-sync/src/main.rs:main` emite SYNC_UNAVAILABLE al fallar el endpoint.
Es una vía visible compatible con el primer FAIL, **inferencia causal** aún
sin aislamiento; no se corrige/silencia ese stderr desde el merger. El scanner
no imprime qué fd/target incumplió su inventario: no se atribuye el segundo
FAIL a canario filtrado, vault sustituido ni a una causa interna demostrada.
Ambos son regresiones frente a las candidatas, aun sin atribución definitiva
a un hunk concreto. Se entregan al dueño para diagnóstico, sin retries,
relajar scanner, KDF, plazos o asserts. Multiagente RED W4 no se ejecuta ni
entra en los gates; su binding de producto sigue pendiente.

### CI nativa y clasificación

Repositorio público y workflows manuales activos comprobados por API; mismos
workflows y runners estándar, sin caches/artifacts/secrets/larger ni cambios de
reglas. [Gratuidad](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
verificada en fuente primaria. Runs sobre SHA exacto
`dedb8f6c2bbcd71837a1c51da51cf4fdb934c605`, binarios normales:

- [macOS 37135611956](https://github.com/SantanaJcp/passwordmanager/actions/runs/37135611956),
  `pasteboard_diagnostic=false`, `final_phase_only=false`.
- [Windows 37135614086](https://github.com/SantanaJcp/passwordmanager/actions/runs/37135614086),
  `diagnostic_only=false`, `service_diagnostics=false`, `tui_conpty_red=true`.

Ambos workflows terminaron; una corrida macOS y una Windows de un máximo
2+2. No se consumen las segundas corridas repitiendo un SHA sin cambio ni
hipótesis discriminante. Metadata `native-{macos,windows}.json` y logs
`native-macos.log`, `native-macos-{intel,arm}.log`, `native-windows.log`, todos
con prefijo `/tmp/pmint4-`. Referencias descargadas por API con sus headSha y
logs propios `reference-<run>.{json,log}` bajo el mismo prefijo.

| Plataforma / job | Resultado exacto frente a referencias | Clasificación |
| --- | --- | --- |
| [Mac ARM 111239421098](https://github.com/SantanaJcp/passwordmanager/actions/runs/37135611956/job/111239421098) | **PASS del lab completo**. Discovery con humano abierto/mismo PID; ambas colisiones rejected/destination=same; happy sync 17.604 s del span TUI, durable/screen=succeeded, pushed=59/pulled=59, blocks=287/roots=1. Full25 completo, status/same-job/restart/lock/idle/offline/retire y cleanup verificados, además de core/fase final. | Supera el bloqueo previo ARM de colisión de W2; conserva la negativa de W1 [37129005704](https://github.com/SantanaJcp/passwordmanager/actions/runs/37129005704), SHA `c4038653314a8adeef1e75f16d3828106894d5aa`, y el discovery W4 [37123539350](https://github.com/SantanaJcp/passwordmanager/actions/runs/37123539350), SHA `e4a8f49e62f1081875e821ea53b1dbe83d6fc7cc`. No acredita reboot/FDE/firma/humano externo. |
| [Mac Intel 111239421248](https://github.com/SantanaJcp/passwordmanager/actions/runs/37135611956/job/111239421248) | **FAIL global; happy sync durable/root PASS acotado**. Discovery y Full25-local/colisiones pasan; span TUI20.368 s (incluye interacción/observación, wait20 original intacto); durable/screen=succeeded, pushed=59/pulled=59, blocks=287/roots=1, PIDs iguales. Falla `macos_tui_migration_lab.py:631`, `assert "pushed=" in complete and "pulled=" in complete`. No alcanza consulta same-job y grupos posteriores. | **FAIL visual conocido**, misma aserción de [W2 37133730351](https://github.com/SantanaJcp/passwordmanager/actions/runs/37133730351), SHA `4282843c3cc9acb4fdda893d23f56b68f5e4b893`, con span18.05s/root1. El panel W1 no lo elimina en esta observación. No es retorno de integrity/roots0 ni pérdida de readiness. La causa precisa de la observación/panel sigue sin aislar. |
| [Windows ARM64 111239429948](https://github.com/SantanaJcp/passwordmanager/actions/runs/37135614086/job/111239429948) | **FAIL global** tras build/static, 14 primitivas (pool incluido), pipe1, observer20 y sync-lib1 PASS; TUI first-prompt/hidden-input/unlock/siete tipos PASS. Resize100×30 pasa por secuencia; en 42×12 falla `fresh native resize repaint` tras15s, hijo vivo/parser ground/salida presente. 80×24, CSV/1PUX y grupos posteriores no alcanzados en esta corrida. | **FAIL nuevo de la candidata resize W1**, posterior al antiguo CSI t de [37132151922](https://github.com/SantanaJcp/passwordmanager/actions/runs/37132151922), SHA `99b40aefac0852b7d4799f9e37a1fe2023da4901`. Sin regresión observada de build/14 primitivas/pool frente a [W4 37123864276](https://github.com/SantanaJcp/passwordmanager/actions/runs/37123864276), SHA `37c1bd82d2cf2c37f02c326397298715d23faed2`. El positivo 1PUX de [W1 37128434031](https://github.com/SantanaJcp/passwordmanager/actions/runs/37128434031), SHA `7e5febb8586c1f3d897abb9896be79e01996a811`, queda **sin revalidar** aquí. No se demuestra una regresión de ese positivo ni aceptación Windows integral. |

El diagnóstico Windows exige simultáneamente cursor/repaint nuevo, reporte de
resize y literal esperado (`windows_tui_conpty_fixture.rs:2071`); el log no
individualiza cuál condición falla. No se deduce que el producto no resize ni
se rebaja ese oráculo. Cleanup de servicio/raíz no reporta fallo adicional;
no acredita los Drops heredados. El job storage diagnostics quedó skipped por
input normal, sin usarlo como aceptación.

Entornos observados: macOS15.7.9/kernel24.6.0, Rust1.98.1 nativo, Intel
`macos15/20260824.0482.1` x86_64-apple-darwin y ARM
`macos15/20260907.0337.1` aarch64-apple-darwin. Windows11 Enterprise
10.0.26200/build26200, `win11-vs2026-arm64/20260924.168.1`,
aarch64-pc-windows-msvc1.98.1, libsodium1.0.22 ARM64/MT,
UAC_ENABLE_LUA=1. Preflight es sólo entorno.

**Objetivo Mac de llegar al happy sync durable y publicar roots en ambas CPU:
PASS acotado. Aceptación global de integración: FAIL.** Quedan dos regresiones
locales, el visual Intel conocido y la nueva frontera resize Windows; no se
implementan fixes por el merger ni se cierran tickets.

### Pendientes y publicación

Se preservan los fallbacks heredados de los informes W1–W4: handler/accept
ignorado en loops, discovery fallido convertido en rechazo genérico, selección
legada de cuerpo en decode_event, colisión staging con recreación y errores
best-effort de cleanup/Drop; sus lugares, condiciones y sustituciones siguen
inventariados en esos informes. Las aperturas SQLite y `.or_else` de kind de
las tablas históricas anteriores ya están corregidas por W3/W2 en este corte.
No se retiran ni corrigen otros fallbacks desde el merger.

Decisiones pendientes: representación durable/retención/replay frente al RED
staging G7; binding/provisión/migración nativos por RPK de múltiples agentes;
configuración/selección/provisión del proveedor ordinario (`provider: None`
conservado). Reboot/FDE/firma, Windows11 x64, Linux AArch64 y aceptación humana
no acreditados por estos gates. No se cierran 26/27/28 ni W1–W4.

Push normal únicamente a `codex/pm-integration-26-28`: el helper original
falló por gh inexistente; se usó el override explícitamente autorizado, sin
cambiar config ni reglas. GitHub anunció el bypass de permisos previamente
autorizado. Rama raíz `codex/implement-passwordmanager` en b3577d2 y trabajo
ajeno `.gitignore`, `.pi/`, `odd/` preservados. PR#1 continúa sin fusionar.
El commit posterior de este informe es exclusivamente documental: su árbol
de código/fixtures/workflows coincide con el SHA de los runs, sin atribuirle
una ejecución nativa diferente.

## Remediación de composición — método pmint5 (2026-10-03)

Encargo explícito sobre `8f29e49`, únicamente las dos regresiones locales y la
observación de sync Intel. Resize Windows, defectos abiertos, estados de
tickets, límites/KDF/deadlines y fallbacks heredados permanecen fuera del cambio.

Se conserva el método de 52 casos anterior, cada invocación bajo
`flock /tmp/pm-cargo-window.lock`, artefactos absolutos y logs `/tmp/pmint5-*`.
Los discriminantes de proceso registran sólo categorías, estado de recursos y
cantidad de stderr pendiente antes de SIGTERM; nunca contenidos. El scanner
sigue rechazando recursos desconocidos y exige lectura completa sin canario.
Si el recurso es transitorio, se comprueba la quiescencia documentada de todos
los tasks, conservando el presupuesto de parada de 5 s; no se añade una lista
blanca por tipo o sufijo.

Para transporte: negativa pública del cliente `session` con endpoint realmente
cerrado, respuesta IPC de error explícita, exit no cero y reap del cliente; la
negativa TUI conserva estado unavailable, ausencia de éxito, mismo job tras
restart y oráculo de stderr intacto. No sustituir un error por respuesta válida.

Para Intel: control sintético de repaint con prefijo de éxito antes de job y
contadores, y sufijo posterior en el panel actual. La observación exige juntos
el mensaje terminal, ID canónico y ambos contadores, dentro del mismo wait20s.
Medir por separado envío/espera/repaint y job durable mediante categorías y
tiempos. Un resultado posterior al deadline conserva FAIL; no ampliar el plazo.
Hasta tres corridas macOS y una Windows autorizadas, SHAs exactos publicados,
workflows normales gratuitos/sintéticos sin cache/artifacts/secrets, sin lock
local retenido durante la espera. No repetir SHA/hipótesis sin cambio pertinente.

### Causas y controles enfocados

**Operations:** RED reproducido `/tmp/pmint5-red-lab-tui-operations.log`.
`/tmp/pmint5-probe-stop2.log` registra **17 bytes ya pendientes en stderr antes
de SIGTERM**. El endpoint que cierra causa un fallo real de handshake del hijo
`pm-sync session`; W2 había cambiado su canal de diagnóstico a stderr heredado.
No lo crea el dispatcher al parar. Se reporta ahora el fallo por el IPC
enmarcado propio (`ok=false/code=unavailable`) y exit4; el padre devuelve
`SyncError::Unavailable`, cierra/recolecta esa sesión y conserva el retry/backoff
y estado público fallido del mismo job. Stderr sigue heredado y un fallo al
escribir el error IPC todavía llega a stderr; no se descarta ni se filtra.
Los demás modos CLI conservan su diagnóstico anterior. RED público del IPC:
`/tmp/pmint5-red-session-ipc.log`, rc101, respuesta ausente en vez del error;
GREEN del endpoint que corta el handshake:
`/tmp/pmint5-green-closing-session.log`. También pasa la negativa de pérdida
real de conexión sin replay interno. Operations completo rc0:
`/tmp/pmint5-green-lab-tui-operations.log`, mismo job tras restart/idle,
bounded-unavailable, sin éxito inventado y stderr vacío exigido por el lab.

**Scanner:** el log pmint4 no conservó la identidad del descriptor. Muestreo
de los fd en el custodio restaurado identifica **SHM de este vault, regular,
desvinculado**, transitorio durante cierre SQLite, no un recurso de sync.
`/tmp/pmint5-monitor-bootstrap-{3,5}.log` conserva sólo categoría/deleted; ambos
terminan rc0 y el recurso deja de aparecer. La fuente SQLite3.53.2 fijada en
el grafo explica la ventana: `unixShmUnmap` hace unlink al llegar a nRef0 antes
de `unixShmPurge`/close. W4 permite solapar conexiones y detenerse en ese
intervalo. No se puede recuperar el inode concreto del log antiguo; atribuirle
ese mismo descriptor es una inferencia respaldada por el muestreo y el control.

Se clasifica exclusivamente el alias Linux `vault.sqlite3-shm (deleted)` del
SHM exacto registrado, con tipo regular, nlink0 y propietario esperado; se lee
**todo el inode por `/proc/<pid>/fd`**, con estabilidad/tamaño/overlap y sin
canarios. No hay permiso para otros deleted, SQLite o temporales. El control
reproduce unlink antes de close: RED
`/tmp/pmint5-red-unlinked-shm-control.log`, rc1 por recurso no clasificado;
GREEN `/tmp/pmint5-green-unlinked-shm-control.log`, con detección de canario
entre chunks y rechazo de otro recurso deleted. `pause_owned` comprueba todos
los tasks detenidos dentro de los mismos5s. Bootstrap enfocado rc0:
`/tmp/pmint5-green-g7-inflight-bootstrap.log`, closed1/replacement0/calls1,
autoridad exacta y cleanup0. El primer replay y el stress sin barrera no
reprodujeron el fallo antiguo; no se presentan como RED. Una pausa diagnóstica
adelantada produjo timeout del get y cleanup0, no un RED válido del scanner
(`/tmp/pmint5-stop-monitor-bootstrap-3.log`), y se retiró.

**Panel Intel:** `/tmp/pmint5-red-panel.log` reproduce determinísticamente el
prefijo visible antes del job/contadores; `wait_information` devolvía esa
captura parcial. El observador conserva el mismo wait20, panel actual y mark,
y añade el patrón completo ID32/pushed/pulled a su condición de devolución;
las aserciones originales se conservan. Helpers con repaint partido rc0:
`/tmp/pmint5-final-macos-helpers.log`. El producto TUI y sync no reciben cambios
de rendimiento. La medición nativa de submit/espera y prefijo/panel completo
se registra abajo.

Fallos heredados inspeccionados y conservados: `serve_one` sustituye un error
parser/dispatch por `ok=false` genérico; `sync_job::record_journal_failure`
descarta el error secundario al persistir el estado de emergencia; los accept
loops descartan errores de handler y el worker de proveedor descarta errores
de ejecución/settle. Se activan en esas respectivas fallas y mantienen el
comportamiento documentado en W2/W4. No se usan para aceptar esta remediación.

### Barrido congelado y checkpoint publicado

Código verificado/publicado:
`6e6ee7ad0022713245e139fe7d322d954670a353` (hijo de `7e34eb7`).
El primer intento parcial se conservó: check rc101 por dos casts del test
nuevo rechazados por Clippy, tras tests de comportamiento verdes. Clean rc0;
se interrumpió sólo el driver propio y se dejó concluir su hijo activo antes
de editar. Logs `/tmp/pmint5-final-{check,clean}.log` y summary parcial. No se
presenta esa barrida incompleta como evidencia de integración.

Después de sustituir esos casts por `u32::try_from`, y de añadir un control
que rechaza un panel completo llegado después del deadline, se repitió todo
el barrido sobre HEAD/árbol congelados. Driver
`/tmp/pmint5-verified-run-local.py`, resultados
`/tmp/pmint5-verified-local-results.json`, resumen
`/tmp/pmint5-verified-local-summary.{log,json}`. **52 casos / 49 rc0 / tres
RED conocidos / cero diferencias inesperadas**, runner rc0. Los únicos cambios
de rc frente a pmint4 son operations1→0 y bootstrap1→0. Son exactamente los
52 comandos anteriores; no se reutilizaron filas/logs del primer intento.

| Gate | Resultado sobre 6e6ee7a; log bajo `/tmp/pmint5-verified-` |
| --- | --- |
| check / clean locked-offline | rc0 / rc0, 107.763 / 89.936 s; `final-check.log`, `final-clean.log`. |
| operations / inflight bootstrap | rc0 / rc0, 77.846 / 4.091 s; `lab-tui-operations.log`, `g7-inflight-bootstrap.log`. |
| 26 labs Linux base / tres publicaciones | 26/26 y 3/3 rc0; oráculos originales conservados. |
| G7 inflight result-sync/audit/crash, vault/live y canaries | rc0; autoridad/calls/replacement y cleanup intactos. |
| Concurrencia / purge / E2EE / digest | rc0; 33 E2EE + 1 shared-purge y dos comparaciones digest. |
| g7-matrix | rc1 conocido; mismos RED/ProductRed de commit-outbox-audit EIO/ENOSPC, cleanup0. |
| g7-extra-bootstrap / g7-extra-vault | rc1 diagnósticos conocidos de autoridad/receipts, replacement0/closed1, cleanup0; fuera de gates. |

974.049 s agregados **incluyen las esperas del lock compartido**; no son
medición de rendimiento. Helpers finales con deadline:
`/tmp/pmint5-verified-macos-helpers.log`, rc0. Diff/AST/enlaces locales PASS;
sin cambios de Windows/resize, workflows, dependencias, KDF, límites, tickets
ni rama raíz. No quedan probes DEBUG en fuentes. Multiagente W4 no se ejecutó
ni se reclasifica; conserva su decisión de binding pendiente.

Push normal sólo a `codex/pm-integration-26-28`. El helper instalado falló por
gh ausente y se usó exactamente el override por comando autorizado; ningún
cambio persistente de credenciales/reglas ni force. GitHub anunció el bypass
de permisos previamente autorizado. Raíz verificada en b3577d2 con
`.gitignore`, `.pi/`, `odd/` intactos. PR#1 continúa borrador, sin fusionar.

### CI nativa pmint5

Una corrida macOS y una Windows sobre el SHA exacto anterior, inputs normales
(Mac false/false; Windows false/false/true), workflows sin cambios. Repo público
y labels estándar comprobados por API; [facturación primaria](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
reconfirmada. Sin caches/artifacts/secrets, sin lock local retenido al esperar.
Hipótesis nueva Mac: captura parcial del mensaje terminal; exigir el mismo
panel completo dentro de wait20. Windows verifica compatibilidad previa al
resize conocido, cuyo dueño continúa en otra rama.

| Run | SHA | Estado |
| --- | --- | --- |
| [Mac 37139870950](https://github.com/SantanaJcp/passwordmanager/actions/runs/37139870950) | `6e6ee7ad0022713245e139fe7d322d954670a353` | **Completed/success, Intel y ARM: lab completo PASS.** |
| [Windows 37139887157](https://github.com/SantanaJcp/passwordmanager/actions/runs/37139887157) | mismo SHA | **Completed/failure**, mismo resize42×12 conocido. |

Metadata final `/tmp/pmint5-native-{macos,windows}1.json` y `...-jobs.json`;
logs completos `...macos1.log`, `...macos1-{intel,arm}.log` y `...windows1.log`.
Ambos runs terminados: **1/3 Mac y 1/1 Windows**, sin repeats. API de artifacts
confirma total0 para ambos; workflows, permisos y flags originales intactos.

| CPU / job, todos en SHA6e6ee7a | Evidencia y resultado |
| --- | --- |
| [Intel 111251887983](https://github.com/SantanaJcp/passwordmanager/actions/runs/37139870950/job/111251887983) | **PASS completo.** Prefijo19.044 s incompleto (`complete-at-prefix=0`); panel completo19.045 s, dentro del wait20 original. Submit1.710 s y span total20.755 s. Durable/screen succeeded, pushed59/pulled59, blocks287/roots1, mismo custodio/servidor. Full25, same-job/restart/lock/idle/bounded-unavailable/retire/offline y fase final/cleanup PASS. |
| [Apple Silicon 111251888417](https://github.com/SantanaJcp/passwordmanager/actions/runs/37139870950/job/111251888417) | **PASS completo.** Primera captura del prefijo incompleta; panel completo9.550 s, submit0.912 s y span10.461 s. Mismos59/59, blocks287/roots1 y PIDs estables; Full25/core/fase final/cleanup PASS. |
| [Windows ARM64 111251937146](https://github.com/SantanaJcp/passwordmanager/actions/runs/37139887157/job/111251937146) | **FAIL global conocido** en `fresh native resize repaint`,42×12, wait15s; hijo vivo/parser ground/output presente. Build/static, primitivas14 (pool incluido), pipe1, observer20, sync-lib1 y prompt/hidden/unlock/siete tipos PASS. No hay nueva regresión observada antes de resize; los grupos posteriores no se alcanzan ni se validan. Sin cambios de producto/fixture Windows en esta entrega. |

**Discriminación Intel cerrada:** la primera captura del mensaje terminal era
parcial. La captura completa llega dentro del mismo deadline,1ms después del
prefijo en la medición redondeada; no después de20s. El span20.755 incluye la
interacción1.710 y no es duración del wait ni del job. No hay un perfil nuevo
de duración interna del job en esta corrida normal. Margen observado Intel
**0.955 s**: este PASS no garantiza margen de rendimiento para toda carga o
futura composición, y cualquier incumplimiento del wait20 sigue siendo FAIL.
No se modifica rendimiento de sync ni se aumenta un plazo. Ambas CPU pasan
las dos colisiones con destino intacto,33 E2EE y todos los gates nativos del
modo normal; no se requiere otra corrida idéntica.

Entorno observado: macOS15.7.9/kernel24.6.0, Intel imagen20260824.0482.1 y
ARM20260907.0337.1, Rust1.98.1 por host/Mach-O nativos. Windows11 Enterprise
10.0.26200/build26200 ARM64, imagen20260924.168.1, UAC_ENABLE_LUA1,
Rust1.98.1-aarch64-pc-windows-msvc, libsodium1.0.22 ARM64/MT v145 verificado.
Preflight permanece evidencia de entorno; reboot/FDE/firma y aceptación
humana externa permanecen pendientes, sin cambios de estado de tickets.

### Entrega y siguiente acción pmint5

Remediación autorizada: las dos regresiones locales vuelven a rc0 y la
aserción Intel pasa con panel completo dentro de20s. Las causas y límites de
identificación del descriptor antiguo están explícitos arriba. Gates locales
sin empeoramiento, y objetivo macOS completo **ambas CPU PASS**. El commit de
evidencia posterior cambia sólo este informe; su árbol de código/fixtures es
idéntico a6e6ee7a y no se le atribuye otra corrida.

FAIL restantes: tres RED locales conocidos (staging de matriz, dos diagnósticos
de autoridad/receipts) y resize Windows42×12 fuera de esta remediación. W4
multiagente/proveedor, G7 integral y evidencia externa conservan su frontera;
no se convierten en PASS por estas corridas. La aceptación integral del
producto/Windows sigue pendiente.

Siguiente acción: el coordinador integra la candidata W1 fase3 cuando sea
verificada y revalida la composición, manteniendo el wait20 y vigilando el
margen Intel. Resolver decisiones de binding/proveedor/staging corresponde a
sus dueños, sin abrir esas funciones desde esta rama de remediación. PR#1
continúa borrador; no merge ni cambio de tickets/reglas.
