# W7 — organización/edición con adjuntos en streaming y diagnóstico de staging

Estado actual: **fase 2 implementada; W7 16/16 y check.sh PASS; barrido/CI pendientes**.
Recifrado autorizado el 2026-10-04, sin integración.
El registro de fase 1 siguiente conserva su RED y diagnóstico originales. Base exacta
`fdfc2230a3d80ad53fccd9bd86126e4ba14975ca`, worktree
`.worktrees/w7-vault-org`, rama `codex/pm-w7-vault-org`.
Zona fase 2: edición/organización/streams en `pm-vault`, sus tests y este
documento. Tickets sin cambios.

## Contrato y método

Fuentes: [spec §15](../../.scratch/passwordmanager/spec.md#15-estado-consolidado-acuerdos-cierres-de-diseño-y-validación),
[G2 §9](../design/key-hierarchy.md#9-composición-completa-con-g5g6g7),
[G4 transacción humana](../design/agent-identity.md#transacción-humana-local),
[G7](../design/security-operations.md), tickets
[05](../../.scratch/passwordmanager/issues/05-todos-los-tipos-y-organizacion-humana.md),
[21](../../.scratch/passwordmanager/issues/21-backup-pmb1-pmf1-y-exportacion-humana.md)
y [22](../../.scratch/passwordmanager/issues/22-recuperacion-rotacion-de-vias-y-compromiso.md).
La lectura W1 es `git show ea4c358:docs/verification/ticket-27.md`, sección
«W1 fase 9», líneas 5179–5480; no se trasladan sus cambios al worktree W7.

Todos los comandos locales Cargo/check/lab se ejecutan desde este worktree
bajo `flock /tmp/pm-cargo-window.lock`, uno por bloque. Datos únicamente
sintéticos. Logs propios `/tmp/pmw7-*.log`; ningún borrado global de `/tmp`.

El RED solicitado se extiende a tres tests en `backup_lifecycle.rs`:

1. Crear Password con adjunto inline, backup PMB1 y restore **en la misma bóveda**.
   Usar los IDs retornados para operar sobre ambas copias, sin escoger por orden
   aleatorio del catálogo. Confirmar representación inline/stream antes de operar.
2. Organización: favorito y tags; lectura y contenido exacto tras commit.
3. Renombrar/editar: nuevo título, notas y credencial protegidos, conservando el
   descriptor del adjunto restaurado. Exigir lectura íntegra tras commit.
4. Papelera/history: trash y restore explícito de la revisión seleccionada,
   estado activo final y revisión histórica legible.
5. Tras operaciones exitosas, exigir contenido/digest exactos, preservación de
   los headers/chunks de **todas las revisiones previas** y exportación de cada
   grafo de outbox por el reductor, que valida su digest firmado.

Comando y log:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault \
  --test backup_lifecycle w7_ --locked --offline -- --nocapture
# /tmp/pmw7-red.log
```

Resultado Linux: **rc101, 1 PASS / 2 FAIL**. Los marcadores `W7_COPY` confirman
que las tres operaciones pasan sobre inline. En la copia restaurada:

| Operación | Resultado observable |
| --- | --- |
| organización | `prepare_organize` devuelve `InvalidInput` |
| rename/edición de campos | prepare y commit terminan; `read_record` devuelve `InvalidCommand` |
| papelera/restore/history | PASS sobre ambas copias; graph export y contenido exacto PASS |

No se llama GREEN a compilaciones fallidas del fixture durante su preparación.
El log final anterior corresponde a fallos conductuales con los controles
inline ya ejecutados, no a ausencia de dependencias.

## Restricción criptográfica descubierta

`set_organization` llama `validate_shape(true)` indirectamente;
`prepare_record_write` cifra cada `attachment_inputs()` como cuerpo inline,
incluso un descriptor cuyo cuerpo está vacío. El segundo defecto puede por
ello confirmar una revisión cuyo adjunto no concuerda con tamaño/hash lógico.

Cada stream existente tiene su **ID de revisión original** en el target/header,
en el sobre de clave y en el AAD de cada chunk (`pm/file/v1`).
`FileOpener::new` exige igualdad con la revisión solicitada.
Por tanto, copiar sin cambios header/ciphertext bajo una revisión nueva no
produce un adjunto legible; reenvolver sólo la clave tampoco cambia el AAD de
los chunks. No se puede satisfacer literalmente ciphertext idéntico en la
revisión nueva usando el formato actual.

Test discriminante adicional, sin modificación criptográfica productiva:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault \
  --test stream_revision_contract --locked --offline
# /tmp/pmw7-stream-contract.log
```

**PASS, rc0**: header/ciphertext se abre con la revisión original y se rechaza
con `CryptoError::Authentication` bajo otro ID. Es evidencia del contrato de
pertenencia, **no GREEN del defecto de organización**.

Se pidió aclaración sobre dos opciones:

- **Recomendación:** conservar byte a byte los streams históricos, pero recifrar
  incrementalmente los adjuntos de la revisión nueva usando buffers protegidos,
  como ya hace history/restore. Preservar el digest del contenido; ciphertext y
  digest del grafo de la revisión nueva cambian. Reutilizar el método existente,
  validar descriptores contra la fuente y comprobar exportación/reimportación.
- Si también debe ser idéntico el ciphertext de la nueva revisión, diseñar una
  referencia autenticada al objeto de archivo de la revisión original. Requiere
  resolver pertenencia/purga y modificar lecturas, backup/restore y formato;
  excede el arreglo acotado y no se implementa sin decisión explícita.

Cuidado adicional para la futura corrección: grafo inline usa
`SHA256(CBOR([package, CBOR(attachments)]))`; streams usan `pm/staged-stream/v1`.
La rama de streams del digest actual no incorpora adjuntos inline; restore ya
rechaza una mezcla de streams e inline. No firmar una mezcla que deje partes
fuera del digest ni introducir una restricción nueva a los flujos actuales.

El fixture Windows W1 selecciona la primera coincidencia Password del catálogo
ordenado por IDs aleatorios después del restore. Los tests W7 cubren **ambos IDs**
explícitamente, que es la alternativa Linux solicitada. No se modifica la TUI ni
su fixture fuera de la zona autorizada.

## Staging: evidencia, clasificación y límites

La premisa «revision productivo no vacío después de SYNC exitoso» **no queda
confirmada por la evidencia W1 indicada**. La corrida final W1
[37188616185](https://github.com/SantanaJcp/passwordmanager/actions/runs/37188616185),
SHA `a479bbbfa8e530d92d4c1cbd499e1d73b407c764`, está completed/failure
(metadata consultada de nuevo mediante API). Log `/tmp/pmw1h-run4.log`:

- Antes de SYNC, `WINDOWS_CLEANUP_TEST case=completed-sync-residue result=pass`
  sigue a `directories=1 files=1`. El archivo `revision` **sintético** se creó
  expresamente con `WriteAllText` para probar el oráculo de cleanup.
- Más tarde SYNC36 termina exitosamente (`process_exit_success count=1`).
- El inventario productivo final, tras detener custodio/SCM, informa
  `WINDOWS_CLEANUP_STAGING directories=0 files=0` y ausencia de recursos propios.
- El fallo agregado es local-operations/device-retire-durable, no ese residuo.

Las corridas W1 con corte de SYNC fallido sí inventarían staging; no demuestran
el mismo fenómeno tras éxito. No reclasificar esas observaciones como éxito.

Si el path es `.pm-sync-stage-<PID>-<64hex>/revision`, corresponde al staging
**de sync** común `pm-sync::sync_stage`: push exporta `revision` y pull descarga
`revision`. El nombre solo no distingue export de descarga; hace falta vincular
el sufijo al digest del evento de push o al hash de grafo de pull y al momento
observado. No es staging humano G4, que consiste en tablas `human_staging`,
`human_staging_streams/chunks` en SQLite, ni un destino humano `.partial` de
`rpc_download_atomic`. El archivo contiene ciphertext de revisión, no se lee
ni registra plaintext para diagnosticarlo.

**Linux, observación ejecutada:** test existente
`human_streaming_attachment_graph_is_complete_before_atomic_activation` de
`pm-sync/e2ee_replication`, sin cambiar sus aserciones ni producto. Un interposer
observacional `/tmp/pmw7-sync-observer.c` registra resultado real de `unlinkat`
para hijos del namespace de sync; devuelve exactamente el resultado y errno
originales, sin inyectar errores. Compilado con `cc -shared -fPIC -O2 -Wall
-Wextra -Werror ... -ldl`. Comandos:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-sync \
  --test e2ee_replication --locked --offline --no-run
# /tmp/pmw7-sync-diagnostic-build.log
flock /tmp/pm-cargo-window.lock env LD_PRELOAD=/tmp/pmw7-sync-observer.so \
  target/debug/deps/e2ee_replication-c477343772a7b27e \
  --exact human_streaming_attachment_graph_is_complete_before_atomic_activation \
  --nocapture
# /tmp/pmw7-sync-observation.log
```

**rc0**; todos los unlinkat observados de `revision` y chunks del namespace sync
retornan rc0/errno0. El test incluye push exitoso, dos pulls rechazados y pull
final exitoso con contenido exacto. Esto no es un inventario quiescente de cada
fase ni demuestra ausencia universal de residuos; **no reproduce** el residuo
alegado. No se ejecutó una reproducción macOS W7 ni se inyectó fallo de cleanup.

**Causa demostrada en código, condicionada al fallo de borrado:** push y pull
hacen `let _ = remove_dir_all(stage)` después de operar correctamente. Si el
filesystem rechaza el borrado, continúan hasta devolver éxito; un `revision`
puede sobrevivir. Es comportamiento común a Linux/macOS/Windows. No hay evidencia
que atribuya un incidente Windows concreto a ACL, sharing violation, antivirus
u otro errno; faltan path productivo, syscall/error y fase exactos.

Fallbacks heredados observados, **sin alterar**:

- `pm-sync/src/lib.rs:sync_stage`: ante `AlreadyExists` borra y recrea el mismo
  directorio. Sustituye el rechazo explícito de colisión y puede borrar evidencia
  de una operación previa; no se acredita como recuperación autorizada.
- `push`/`pull`: descartan el fallo de `remove_dir_all`, ocultando cleanup fallido
  tras una operación que puede quedar reportada exitosa.
- `upload_graph`/`download_graph`: descartan `remove_file(joined)` tras usar el
  archivo unido. No prueba que se activaran en el incidente alegado.
- `retry`: ante `SyncError::Unavailable` reintenta con backoff 1/2/4/8/16/30s.
  Se conserva; su existencia no explica por sí sola un residuo tras éxito.

Opciones para el diagnóstico/correctivo posterior, **ninguna ejecutada**:

1. **Recomendación:** obtener el log/path del incidente real; observar fallo de
   cleanup con categoría/errno y fase push/pull, con custodio detenido antes del
   inventario. Mantener el FAIL del oráculo tras SYNC exitoso con residuo.
2. RED con interposer limitado a un PID/path owned de sync que deniegue unlink
   de `revision`; exigir que el transporte confirme el lote, capturar retorno
   público y residuo antes del teardown, y limpiar sólo ese path con owner
   separado. Necesita definir esa extensión del método de fault injection antes
   de ejecutarla; no se simula aquí una causa histórica.
3. Tras autorización, propagar cleanup fallido conservando el estado durable del
   sync y sus recibos/outbox; decidir por separado tratamiento de colisiones.
   No recrear staging como arreglo, no reenviar eventos ni devolver acks falsos.
4. Mantener staging humano como asunto separado sujeto al punto 10 del usuario;
   no inferir política replay/abort desde este archivo de sync.

## Gates y entrega — fase 1 histórica

Gates ejecutados en W7, todos bajo flock:

- `./scripts/clean-offline-build.sh`: **rc0**, build locked/offline 39.37s;
  log `/tmp/pmw7-clean-offline.log`.
- `./scripts/check.sh`: **rc101**, configuración/fmt/check y tests precedentes
  pasan; `backup_lifecycle` informa 6 PASS / 2 FAIL, exactamente los RED nuevos
  organización/edición. Al detenerse Cargo, no se ejecuta clippy ni se acredita
  aceptación del workspace; log `/tmp/pmw7-check.log`.
- `git diff --check` y existencia de los enlaces locales del documento: PASS.

El barrido completo W7 de 52 casos es **NOT_RUN** mientras falta la corrección;
no se solicita omitir/asumir verdes los RED nuevos. El método vigente es el de
[integración pmint8](integration-26-28.md#composicion-w6-pmint8): 49 rc0 y tres RED
conocidos (`g7-matrix`, `g7-extra-bootstrap`, `g7-extra-vault`); W4 concurrency
observación fuera de gates. `PM_KEYCLOAK_DIST` y `PM_CFT_DIR` son los paths
absolutos del encargo, Wayland real si el entorno inicial no sirve.
No se afirma haber ejecutado ese barrido sobre una corrección W7 inexistente.

CI W7 **NOT_RUN**: presupuesto intacto 0/2 Windows, 0/1 macOS. No consumir
corridas de aceptación mientras no exista una corrección compatible con el
requisito aclarado. Cuando exista: push normal del SHA exacto, dispatch manual
Windows completo y macOS normal, conforme [native-ci](native-ci.md), público/
estándar/sintético, sin caches/artifacts/secrets. No tocar FAIL conocidos de
unlock/sync, límites/KDF/plazos ni integración/PR #1.

Siguiente acción al cerrar fase 1 (resuelta por el encargo de fase 2): aclarar si «conservar streams existentes» permite recifrado
protegido de la revisión **nueva** manteniendo inmutables las anteriores. Después
implementar, obtener GREEN de los RED nuevos y ejecutar la verificación completa.

## Fase 2 — método autorizado (2026-10-04)

Decisión del orquestador: recifrar streams bajo el AAD de la revisión nueva,
conservar los históricos byte a byte y mantener formato/G2/presupuesto/plazos.
Verificar primero el RED anterior y los nuevos tests `w7_large_stream_*`:
organización, rename y campos por separado, sobre copias PMB1 restauradas con
2 MiB +73 bytes y 31 MiB +73 bytes. Generación/lectura sintética acotada;
plaintext recifrado sólo en `ProtectedBytes`, chunks <=1 MiB. Medir prepare y
prepare+commit; el tamaño del archivo no equivale a memoria plaintext viva.
Comparar headers/chunks históricos y autenticar cada chunk bajo su AAD original.
Exportar y aplicar el grafo nuevo a una réplica sembrada antes de editar, leer
metadata y digest exactos, y volver a comprobar papelera/history/restore.
Fuente corrupta a mitad de stream debe rechazar prepare sin nuevos staging,
challenges, revisiones, outbox, eventos ni auditoría. La firma/digest de staging
impide confirmar un grafo alterado después de prepare. Mantener controles de
inline, creación/reemplazo/eliminación de adjuntos y fuentes inexistentes.

Comandos enfocados: `cargo-local.sh test -p pm-vault --test backup_lifecycle
w7_ --locked --offline -- --nocapture --test-threads=1`; test del contrato AAD;
regresión pm-vault/history; E2EE existente de pm-sync. Todos bajo flock, logs
`/tmp/pmw7b-*.log`. Gates y CI conservan el método anterior y el presupuesto
máximo del encargo (2 Windows, 1 macOS); sin tocar sync ni staging humano G4.

La ruta legacy `prepare_edit(PasswordRecord)` también produce revisión nueva;
`PasswordRecord` no expresa adjuntos. La prueba exige conservarlos en original
inline y copia streaming, además de tamaños grande/cerca del presupuesto y
lectura replicada. Recifrado de esa ruta dentro de pm-vault, sin cambiar el wire.

### Evidencia fase 2 local

- `/tmp/pmw7b-red-original.log`: HEAD 11cfd5b, 1 PASS/2 FAIL conductuales.
- `/tmp/pmw7b-red-final.log`: producto exacto 11cfd5b con fixture ampliado,
  13 casos, 1 PASS/12 FAIL, rc101. Incluye cada operación/tamaño por separado.
- `/tmp/pmw7b-red-password.log`: ruta legacy pierde el adjunto inline, rc101.
- `/tmp/pmw7b-green-final.log`: 16/16 PASS, rc0; mismas aserciones de integridad,
  contenido, históricos, réplica y atomicidad. Los tamaños son 2.097.225 y
  32.505.929 bytes; 3 y 32 chunks respectivamente (último de 73 bytes).
- `/tmp/pmw7b-check-initial.log`: todos los tests pasan; rc101 al llegar a
  clippy por `type_complexity` del snapshot heredado de fase 1. Corregido con
  `W7StreamRow`, sin suprimir el lint ni cambiar la aserción.

Garantía: prepare autentica fuente/propiedad/índices/FINAL/tamaño/hash y recifra
cada chunk mediante `FileOpener -> ProtectedBytes -> FileSealer` con nueva clave,
nonce/header y revisión propia; sin plaintext ordinario/disco ni cambio de AAD.
Si falla fuente o staging, rollback antes de crear challenge/publicar revisión.
El commit verifica de nuevo `pm/staged-stream/v1` contra el cuerpo firmado;
alteración de chunk posterior a prepare falla sin cambiar efectos durables.
No se copian streams viejos a la nueva revisión; los históricos no se escriben.
La ruta legacy conserva adjuntos moviendo sus owners, sin `Clone` de secretos.
Reemplazo/eliminación explícita por `prepare_edit_record` sigue disponible,
incluida sustitución por archivo vacío y conservación de stream vacío/FINAL.

Lectura cruzada: el fixture replica **sólo** el evento nuevo y su grafo cifrado
mediante `export_ciphertext_graph -> apply_received_package` del receptor real
pm-vault, sobre seed previo a la edición. Autentica metadata y todos los bytes
por digest/longitud en la réplica. No copia SQLite después de editar, no altera
wire/servidor/proveedor y no sustituye las pruebas E2EE de transporte pm-sync.

Coste Linux debug, prepare exclusivo de la operación (fixture/hash de entrada
preparados antes del cronómetro), `/tmp/pmw7b-green-final.log`:

| Operación | 2 MiB+73 prepare / prepare+commit s | 31 MiB+73 prepare / prepare+commit s |
| --- | --- | --- |
| organización | 0.017767 / 0.027248 | 0.225763 / 0.351163 |
| rename | 0.017104 / 0.026577 | 0.227384 / 0.339475 |
| campos | 0.017516 / 0.027122 | 0.236635 / 0.357285 |
| PasswordRecord legacy | 0.017830 / 0.027297 | 0.224283 / 0.334825 |

Memoria: cada plaintext recifrado <=1 MiB, liberado al finalizar ese chunk;
header/ciphertext/snapshots del fixture son ciphertext ordinario. Muestreo de
`/proc/PID/status` cada 5 ms, dos tests aislados bajo flock, rc0:
`/tmp/pmw7b-memory{.log,-summary.json}` y logs `…-w7_*rename_and_replica.log`.
Pico **observado**, no cota formal, VmLck=1.092 KiB en ambos tamaños; VmRSS
97.644/300.084 KiB incluye KDF, SQLite y snapshots/backup cifrados del fixture,
no significa 31 MiB de plaintext protegido. El sampler es observacional,
no cambia límites, presupuesto ni mlock. No acredita extracción/dumps nativos.

Comportamientos heredados adicionales inspeccionados y sin cambiar:
`TestDir::drop` de backup_lifecycle descarta error de `remove_dir_all` (teardown
puede ocultar residuos de fixture). `prepare_create_record_streaming` y
`prepare_1pux_import` usan buffers propios `Zeroizing<Vec<u8>>` para entrada;
no son el camino nuevo de recifrado y zeroizar no equivale a memoria bloqueada.
Los fallbacks de cleanup/retry de sync documentados arriba siguen intactos.

`./scripts/check.sh` final: **rc0**, `/tmp/pmw7b-check-final.log`;
configuración, fmt, check, tests completos (incluidos AAD/history/E2EE existente)
y clippy pasan. El digest snapshot y las aserciones no se relajaron.

RED ampliado final **sobre el mismo fixture de 16 tests**, producto exacto
11cfd5b: `/tmp/pmw7b-red-complete.log`, rc101, 1 PASS/15 FAIL conductuales,
incluidas las cuatro rutas de edición en ambos tamaños. Se restauraron los
dos archivos propios del producto y se compararon byte a byte con los archivos
verificados por check.sh antes de continuar. No se tocó otro worktree.
