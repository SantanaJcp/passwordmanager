# Integración 26–28 — composición y evidencia

Fecha: 2026-10-03. Rol: merger de candidatas publicadas. El corte vigente está en [Composición de G7 fases 4–5 y clipboard](#composición-de-g7-fases-45-y-clipboard--2026-10-03); las secciones anteriores conservan la integración y remediación históricas. Esta composición no corrige defectos abiertos ni cambia estados de tickets.

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
