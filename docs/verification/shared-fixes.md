# Shared fixes — método y evidencia

Fecha: 2026-10-03. Base: `b3577d2f7a563df3e777380adf5cc120d1f7f9e0`.
Worktree exclusivo `shared-fixes`, rama `codex/pm-shared-fixes`. No integración,
merge de PR, cambios de tickets ni credenciales reales.

## Método definido antes de ejecutar

La solicitud autoriza ampliar las comprobaciones existentes de
[backup/restore](ticket-21.md), [TUI de operaciones](ticket-25.md),
[sync](ticket-17.md) y [purga](ticket-18.md). Prerrequisitos: Linux x86_64,
Rust 1.98.1 bajo `.toolchain/`, dependencias fijadas disponibles offline,
user/mount namespaces, subuid/subgid, tmux y helpers del lab existente.
Toda invocación Cargo, check, clean o lab usa exclusivamente
`flock /tmp/pm-cargo-window.lock`, con cwd en este worktree.

A: para backup, plaintext confirmado y adjunto, la nueva fixture de teclado
crea primero un destino válido mediante el servicio humano real. Repite la
operación sobre ese mismo destino y exige error, digest/longitud/permisos
originales conservados y ausencia del `.partial` propio. Se conserva RED por
cada flujo, antes de cambiar producto. GREEN debe usar publicación nativa
sin reemplazo y un error público tipado. Se comprueban también destino nuevo,
symlink existente y colisión entre escritores; no hay rename alternativo si
la primitiva no está disponible. Cada fixture elimina solo sus recursos.

B: crear una bóveda sintética real, emparejar, crear/editar un elemento,
enviarlo a papelera y purgarlo mediante `HumanVault::commit`. Inspeccionar
payloads, marcadores y headers/outbox; ejecutar `SyncReplica::push` contra el
proceso TLS/RPK `pm-sync` existente. Una reproducción fallida conserva código,
conteos y error, sin acks falsos, eliminación de headers o sustitución del
servidor. Resolver la semántica desde G5 §§9.1–9.3 y tickets 16–18; si falta una
decisión o se necesita cruzar un fallback excluido por el encargo, detener B
y explicar la frontera. Una eventual corrección debe probar también recepción,
replay, purga selectiva, lotes y persistencia del outbox ante fallo remoto.

Regresión final: `check.sh` completo, `clean-offline-build.sh` y labs Linux
secuenciales de backup, recovery, history, sync, contenido y TUI operaciones.
Artefactos externos fijados por la solicitud; no instalación de dependencias.
Éxito significa resultados observables aprobados, sin convertir evidencia
Linux en soporte macOS/Windows ni cerrar gates humanos/reboot/firma.

## A — causa, RED y GREEN

`rpc_download_atomic` creaba exclusivamente el `.partial`, pero publicaba con
`fs::rename`, que sustituye el destino en Unix. La descarga paginada de
`SyncReplica::download_paged_file` tenía el mismo defecto. Crear staging
exclusivo no acredita exclusividad del destino final.

Los cuatro RED se ejecutaron sobre el producto de la base antes de modificarlo:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-download-publication-lab.sh backup
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-download-publication-lab.sh plaintext
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-download-publication-lab.sh attachment
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-sync \
  --test e2ee_replication paged_download_never_replaces_an_existing_destination \
  --locked --offline
```

| Caso | RED conservado, resultado | GREEN conservado, resultado |
| --- | --- | --- |
| Backup teclado | `/tmp/pmshared-20261003-red-backup.log`, rc 1; éxito inesperado y digest cambiado | `/tmp/pmshared-20261003-green2-backup.log`, rc 0 |
| Plaintext confirmado | `/tmp/pmshared-20261003-red-plaintext.log`, rc 1; éxito inesperado y digest cambiado | `/tmp/pmshared-20261003-green2-plaintext.log`, rc 0 |
| Adjunto teclado | `/tmp/pmshared-20261003-red-attachment.log`, rc 1; éxito inesperado sobre ruta existente; mismos bytes no cambian digest | `/tmp/pmshared-20261003-green2-attachment.log`, rc 0; también inode intacto |
| Descarga paginada sync | `/tmp/pmshared-20261003-red-sync-publication.log`, rc 101; devolvió `Ok(())` | `/tmp/pmshared-20261003-green-publication.log`, rc 0; devuelve `SyncError::InvalidRequest` |

GREEN usó los mismos cuatro comandos. Las fixtures finales exigen el código
público `DESTINATION_EXISTS` en la TUI, digest, longitud, modo e inode intactos,
ausencia del `.partial` y cleanup comprobado antes de anunciar PASS. Se amplió
solo el ancho de la PTY a 160 columnas para observar el código completo; se
conserva la espera existente de ocho segundos.

`pm_vault::publish_new_file` usa exactamente una primitiva por SO:
Linux `renameat2(RENAME_NOREPLACE)`, macOS `renamex_np(RENAME_EXCL)` y seam
Windows `MoveFileExW` con flags cero (sin reemplazo ni copia entre volúmenes).
Utiliza la `libc 0.2.189` existente y un binding de sistema a Kernel32; no
cambia manifests, lockfile ni instala dependencias. Si la primitiva/FS no está
disponible, devuelve el error; no intenta `rename`, link/copy u otro camino.
El caller conserva la responsabilidad sobre fsync y cleanup.

En custodia, el error primario es `DestinationExists`, preservado incluso si
falla eliminar el staging propio. CLI imprime `DESTINATION_EXISTS` y sale 4;
TUI conserva la frase de fracaso existente y añade ese código. Una colisión
se elimina por la vía de cleanup tipada ya integrada. En descarga paginada se
usa la categoría pública existente `SyncError::InvalidRequest`; el cleanup
heredado permanece sin modificación, como se detalla abajo.

Prueba adicional del helper: archivo existente, symlink existente, symlink
colgante y dos escritores concurrentes. Solo uno publica; el perdedor recibe
`AlreadyExists`. Comando y log:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault \
  publication::tests --locked --offline
# 2 passed; /tmp/pmshared-20261003-green-publication.log
```

La primera corrida TUI posterior al fix NO fue aceptada:
`/tmp/pmshared-20261003-green-backup.log`, rc 1. Todas las aserciones de producto
se completaron, pero la fixture enviaba `l` y cerraba tmux mientras salía la
última sesión, causando `server exited unexpectedly`. La fixture final deja
esa sesión viva para el cierre estricto existente de sus recursos exactos;
no reintenta cleanup ni acepta su error como éxito. Se conservó el log original.

Referencias de las APIs consultadas, sin sustituir la ejecución nativa:
[Linux rename](https://man7.org/linux/man-pages/man2/rename.2.html),
[Apple exclusive rename](https://developer.apple.com/documentation/foundation/urlresourcevalues/volumesupportsexclusiverenaming),
[Microsoft MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).
Solo Linux x86_64 se compiló/ejecutó aquí; macOS/Windows y FS sin soporte de la
primitiva siguen sin validación runtime en esta entrega.

## B — reproducción y frontera detenida

El reproducer [`shared_purge_probe.rs`](../../crates/pm-sync/examples/shared_purge_probe.rs)
usa `PendingVault`, `HumanVault::commit`, alta de custodia de auditoría real,
pairing y el proceso Rust `pm-sync` con TLS/RPK fijado. Datos exclusivamente
sintéticos; fixture exclusiva 0700, claves 0400, servidor y raíz propios
eliminados con errores de cleanup explícitos. No copia DB/WAL para sincronizar.

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh build -p pm-sync --locked --offline
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh run -p pm-sync \
  --example shared_purge_probe --locked --offline -- target/debug/pm-sync
```

RED `/tmp/pmshared-20261003-red-purge.log`, rc 1:

```text
PRE push items=0 payloads=0 purge-markers=1 signed-headers=4 pending=4 revisions=2
POST push result=Err(Reduction(Storage(QueryReturnedNoRows))) pending=4 signed-headers=4 opaque-blocks=1 roots=0
RED pending purged revision headers must publish without deleted payloads
```

La observación final del mismo candidato, añadiendo únicamente el diagnóstico
independiente de recepción, volvió a dar rc 1 en
`/tmp/pmshared-20261003-red2-purge.log`. Antes del push registró
`PRE independent graphless-reception-accepted=false`; headers y outbox siguieron
en cuatro. El push conservó ese outbox y volvió a dejar un bloque opaco y
cero roots. Esto comprueba la frontera adicional de recepción; no se repitió
una operación hasta convertirla en éxito.

El conteo concreto depende del fixture: aquí crear/editar/trash/purge da cuatro
eventos y dos revisiones. Ticket26 tiene cinco revisiones pendientes de su
recorrido más amplio. La causa es la misma: `apply_item_purge` elimina payloads
y el elemento, conserva correctamente headers/outbox, y
`export_ciphertext_graph` exige el join a `revision_parts` + `vault_items`
para toda revisión vinculada. `SyncReplica::push` sube el header opaco antes
de ese export, pero falla antes de publicar la raíz o reconocer el outbox.
No se eliminaron eventos ni se simularon acks.

El contrato **sí determina la semántica lógica**:
[G5 §§9.1–9.3](../design/synchronization.md) exige purga monotónica/terminal,
headers, parents y hashes permanentes, y permite descartar payload purgado.
La [spec §15](../../.scratch/passwordmanager/spec.md#15-estado-consolidado-acuerdos-cierres-de-diseño-y-validación)
confirma ese cierre; tickets 16–18 y [ADR0002](../adr/0002-borrado-frente-a-edicion-concurrente.md)
no autorizan eliminar antecedentes firmados. No se reabre G5 por esta evidencia.

No se aplicó un GREEN parcial de «omitir export cuando está purgado»:
`apply_received_package` exige exactamente un grafo para cada revisión
vinculada, incluso cuando el ledger ya acredita la purga. Después necesita una
revisión visible al activar los elementos. La recepción también contiene un
fallback no autorizado: si no encuentra el grafo de la revisión visible,
`.or_else` toma el `kind` del primer grafo de ese elemento y sustituye la
información faltante. La corrección compuesta debe alcanzar esa clasificación
y activación; por la regla del despacho «si se cruzan con tu fix, detente y
repórtalo», B se detuvo sin cambiar ese método ni el reductor.

Opciones para el orquestador:

1. **Recomendada, consistente con G5:** transportar el evento de purga firmado
   y conservar los headers/antecedentes; omitir solo los payloads cuya purga
   quede autenticada, aplicar el marcador y la retirada de payload en una
   transacción. Debe cubrir prueba ausente/incompleta o inválida, replay,
   purga selectiva, fallo de publicación y purga separada de antecedentes por
   el límite de 256 eventos. Coordinar primero la frontera del fallback de
   recepción y su dueño. No modificar silenciosamente el contrato ni ese
   fallback para hacer pasar el caso pequeño.
2. Esperar a vaciar outbox antes de purgar cambiaría la operación offline y
   añadiría un requisito de red no autorizado. No implementado/recomendado.
3. Excluir/borrar revisiones firmadas del outbox o reconocerlas sin raíz
   publicada rompe antecedentes y la evidencia de publicación. Rechazado.

La elección de retención está cerrada; lo pendiente es autorización/coordinación
de la frontera implementativa anterior y el método concreto de transferencia
de sus pruebas entre lotes. El ejemplo deliberadamente devuelve 1 mientras el
defecto exista. `check.sh` lo compila pero no lo ejecuta: un check verde **no**
es un GREEN de B. No se añadió test ignorado ni se escondió ese RED.

## Otros caminos revisados y comportamiento heredado

| Camino | Resultado |
| --- | --- |
| Backup nativo, export plaintext confirmado, adjuntos TUI | Comparten `rpc_download_atomic`; corregidos, con RED separado por flujo |
| `SyncReplica::download_paged_file` | Mismo contrato de archivo nuevo/staging; corregido con su RED |
| Restore en bóveda existente | Staging y commit SQLite con IDs/keys nuevos, conserva autoridad actual; no publica sustituyendo un archivo de salida por `rename`; sin cambio |
| Creación de bóveda/restauración a ruta nueva | `persist_new_with_cleanup` publica con `hard_link` exclusivo y `VaultError::AlreadyExists`; sin cambio |
| Archivo protegido de pairing | `create_private_output` usa `create_new`, sin rename sobre destino existente; sin cambio |
| Journal de trabajo sync | `sync_job::write_journal` reemplaza deliberadamente el estado del mismo trabajo; contrato de actualización, no export/archivo nuevo; sin cambio |

Heredados encontrados y conservados:

- `SyncReplica::download_paged_file`: `let _ = remove_file(temporary)` después
  de un fallo ignora error de unlink; podría dejar staging sin informar su
  cleanup. La publicación ya no reemplaza; no se alteró ese descarte de errores.
- `ProcessTlsTransport::put`: descarta error de eliminar su input temporal
  después del RPC; fallo de escritura previa también puede dejarlo. Sin cambio.
- `sync_stage`: una colisión `AlreadyExists` borra/recrea el directorio en vez
  de rechazarlo; puede activar tras un push fallido. No se usó como corrección
  ni se modificó.
- `CausalReducer::open`/aperturas SQLite pueden crear implícitamente un archivo
  si falta; el fix no cambia su política de apertura.
- `decode_event` puede aceptar `decode_legacy_body` si falla el decode primario;
  compatibilidad heredada ya reportada por 26, preservada.
- Labs existentes como `backup_lab.py` y `linux_lab.py` usan
  `shutil.rmtree(..., ignore_errors=True)`: un fallo de cleanup puede ocultar
  residuos. La barrida de esta entrega compara un inventario previo/posterior
  de sus raíces temporales conocidas, sin eliminarlas ni tocar residuos ajenos.

El .partial de custodia en esta base ya propaga los errores tipados de cleanup;
la nota de 26 sobre un descarte corresponde a su rama separada. El merger debe
conservar tanto la exclusión nueva como la propagación integrada, y no elegir
el cuerpo de una rama completo por conveniencia.

## Verificación general y entrega

Código candidato: `4e02aedb5e3c51b6868239f754720e6c5e82eb2b`.
El commit posterior de este informe no altera producto/fixtures.

```sh
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
# PASS: /tmp/pmshared-20261003-check2.log
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
# PASS: /tmp/pmshared-20261003-clean.log, 18,864 archivos/5.8 GiB, build 38.77 s
git diff --check
# PASS
```

Primera corrida general `/tmp/pmshared-20261003-check.log`: tests aprobados,
Clippy rechazó `format_collect` en el reproducer. Se corrigió ese código de
fixture, sin suprimir el lint. La segunda corrida completa pasó sin warnings.
Reportó 145 tests aprobados y dos entradas heredadas `ignored`; no se añadió
ningún ignore para estos defectos. B conserva su ejecución separada roja.

Barrida definida y ejecutada secuencialmente:

```sh
flock /tmp/pm-cargo-window.lock env \
  PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3 \
  PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64 \
  python3 /tmp/pmshared-20261003-labs.py > /tmp/pmshared-20261003-labs.log 2>&1
```

El runner ejecuta `./scripts/test-linux-{nombre}-lab.sh`, uno cada vez, y
conserva stdout/stderr por lab en `/tmp/pmshared-20261003-lab-{nombre}.log`.
Orden: backup, recovery, history, sync, content, csv-import, 1pux-import,
tui-content, tui-operations. Detiene la barrida ante error o nuevas raíces
temporales residuales. Solo inventario/lectura de `/tmp`, ningún sweep/borrado.

Resultado: `SUMMARY completed=9 planned=9 failures=0`. Cada lab terminó rc 0,
con `new-residual-roots=0`. Logs:

| Lab | Segundos | Log |
| --- | ---: | --- |
| backup | 17.5 | `/tmp/pmshared-20261003-lab-backup.log` |
| recovery | 40.9 | `/tmp/pmshared-20261003-lab-recovery.log` |
| history | 19.8 | `/tmp/pmshared-20261003-lab-history.log` |
| sync | 0.6 | `/tmp/pmshared-20261003-lab-sync.log` |
| content | 35.8 | `/tmp/pmshared-20261003-lab-content.log` |
| csv-import | 23.7 | `/tmp/pmshared-20261003-lab-csv-import.log` |
| 1pux-import | 38.3 | `/tmp/pmshared-20261003-lab-1pux-import.log` |
| tui-content | 43.0 | `/tmp/pmshared-20261003-lab-tui-content.log` |
| tui-operations | 112.9 | `/tmp/pmshared-20261003-lab-tui-operations.log` |

Los labs existentes de sync no combinan el purge/outbox defectuoso de B; su
PASS es regresión de los casos descritos por ticket17, no cierre de B. La
TUI completa mantuvo import/backup/export/restore/rotaciones, adjunto de más
de 16 MiB y trabajo sync persistente con backoff/restart/idle. La TUI de
contenido también mantuvo papelera/restauración/purga y clipboard ownership.
El único artefacto nuevo bajo el worktree fue el bytecode
`crates/pm-custody/tests/__pycache__/linux_lab.cpython-314.pyc`, creado por los
labs existentes. Se comprobó archivo regular/owner local y se eliminó esa
ruta exacta junto con su directorio ya vacío; no se tocó bytecode ajeno.

Se comprobaron enlaces relativos de este informe, consistencia de estados y
ausencia de cambios a manifests/lockfile. La raíz siguió en `b3577d2`, con su
`.gitignore` modificado y `.pi/`/`odd/` intactos. Los worktrees 26/27/28 no se
modificaron. Las limitaciones de labs sobre Internet público, servicios/FDE y
reboot se conservan; tampoco hay validación runtime macOS/Windows de esta rama.

Archivos de producto tocados: `pm-vault/src/publication.rs` nuevo y export en
`pm-vault/src/lib.rs`; llamada final de `pm-custody/src/linux.rs`; categorías en
`failure.rs`/`main.rs`; mensaje en `linux/tui.rs`; un brazo exhaustivo del test
de `linux/sync_job.rs`; llamada final en `pm-sync/src/lib.rs`. Fixtures:
`download_publication_lab.py`, su runner y una prueba en `e2ee_replication.rs`;
reproducer de B en `pm-sync/examples/shared_purge_probe.rs`. Este informe
completa la evidencia. No manifests, `.gitignore`, tracker ni ramas ajenas.

Conflictos previsibles: 28 modifica intensamente `linux.rs` y `pm-vault`;
resolver el fragmento de descarga preservando sus buffers/cleanup y agregar el
export del helper sin sustituir sus otros cambios. 26 modifica dispatcher en
`linux.rs`; 27 compone el handler/TUI y selecciones de plataforma de
`lib.rs`/`main.rs`. Ambos deben conservar la nueva categoría de error y llamar
el mismo helper en los paths compartidos. No se tocó su worktree ni se afirma
integración/compilación nativa de esas composiciones.

Siguiente acción: revisión/integración por orquestador/merger distinto para A;
coordinar la frontera indicada de B y sus RED de recepción/lotes antes de
implementarlo. Después ejecutar los gates originales de 26/27 sobre el SHA
compuesto. PR #1 permanece borrador, sin merge ni cambios de reglas.
