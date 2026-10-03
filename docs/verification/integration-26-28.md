# Integración 26–28 — composición y evidencia

Fecha: 2026-10-03. Rol: merger; composición de candidatas publicadas, sin corrección de defectos abiertos ni cierre de tickets.

## Identidad y alcance

Worktree: `.worktrees/integration-26-28`; rama `codex/pm-integration-26-28`.
Base: `b3577d2f7a563df3e777380adf5cc120d1f7f9e0`.
SHA final de código integrado: `6afa77c3090a87d296d8e676ccb4840ba6008f6f`.
El informe se publica en un commit documental posterior: los runs nativos y los gates prueban ese SHA de código, no el SHA documental que contiene sus resultados.

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

## Entrega y decisiones pendientes

La rama contiene cuatro merges y este informe; **composición realizada, aceptación nativa fallida**. Se entrega al orquestador con evidencia, sin corregir los defectos abiertos ni repetir runs autorizados una sola vez.

1. Orquestador: asignar el cierre mecánico del match `Failure::after_native_cleanup` conservando primary DestinationExists y todos los errores de cleanup; verificar Windows sin wildcard, fallback ni weakening.
2. Orquestador: discriminar el rc4 de `pm-sync` macOS en su fase real, preservando owners bloqueados, parser/límites y guardas por conexión; la causa requiere evidencia. No restaurar Vec secreto ni generalizar los carriles macOS a Linux.
3. Usuario: decidir ubicación del resumen obligatorio completo durante preview, pendiente de 27. No se cambia el footer aceptado ni se confirma import con contador oculto.
4. Usuario/orquestador: autorización del dueño de purge/outbox y del fallback SQLite/reducer ya excluido; G5 confirmado no se reabre ni se eliminan headers/outbox.
5. Nueva autorización para CI después de un candidato corregido: los dos dispatch permitidos se consumieron y terminaron. Además quedan gates humanos/reboot/FDE, firma y targets no acreditados.

El helper Git configurado falló por apuntar a un gh inexistente. Se usó el override de credenciales autorizado, exclusivamente en los comandos push normales de esta rama; no se alteró configuración persistente ni se hizo force. La creación remota informó bypass de restricción de creación por los permisos existentes; no se cambiaron reglas. El PR borrador #1 y su base permanecen fuera de esta entrega.
