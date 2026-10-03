# W2 — sincronización después de un purge

Fecha: 2026-10-03. Worktree exclusivo `.worktrees/w2-purge-sync`, rama
`codex/pm-w2-purge-sync`, base
`ee3c1fd31cad59060e4120f3e2518b1196a90c1a`.

**Estado de reanudación: implementación de opción A y verificación focalizada
GREEN; gates Linux completos y corrida macOS todavía pendientes.** El usuario
transmitió la decisión del orquestador del 2026-10-03 conforme a G5: root
paginado explícito v3, documentado en [G5 §9.1](../design/synchronization.md#91-tipos-y-autenticación-de-eventos).
No hay integración ni cambios de tickets.

La reanudación conservó el checkpoint documental `30398ae` y todos los cambios
sin commit de fase 2. Primero verificó ese código: 11 pruebas E2EE y el
reproductor pasaron en `/tmp/pmw2b-inherited-tests.log`. Al ampliar la prueba,
la selección con únicamente el purge pendiente falló con `Reduction(Integrity)`
en `/tmp/pmw2b-expanded-tests.log`; el fix incluye sus antecedentes aunque ya
tengan acuse. Ahora pasan 25 pruebas E2EE, el reproductor integrado y Clippy:

```sh
flock /tmp/pm-cargo-window.lock bash -c './scripts/cargo-local.sh fmt --all && ./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication --test shared_purge --locked --offline -- --nocapture && ./scripts/cargo-local.sh clippy -p pm-sync -p pm-vault --all-targets --locked --offline'
# rc 0; /tmp/pmw2b-green5-tests.log
```

Incluyen 259 revisiones/eventos con purge en otra página, rechazo atómico de
páginas incompletas o causales intercambiadas, firmas/`kind`/pertenencia,
publicación interrumpida y recepción cuyo marcador no puede hacer commit,
purga selectiva/replay, dos bóvedas reales con servidor TLS/RPK y la carrera
ADR0002 + purge terminal. Cada rechazo compara autoridad, contenido, outbox y
marcadores; varias negativas conservan además contenido válido independiente.
No se usa un test ignorado para ocultar el RED. `check.sh` descubre los tests
nuevos mediante `cargo test --workspace --all-targets`.

## Registro histórico de fase 1 (antes de seleccionar A)

El resto de este checkpoint conserva el informe inicial de `30398ae`. Sus
menciones de A/B pendientes, ausencia de implementación y siguiente selección
son históricas y quedan sustituidas por el estado de reanudación anterior.
Faltan todavía la comparación RED sobre la base, los gates completos y CI;
no se anuncia aceptación final por la suite focalizada.

## Contrato confirmado y formato disponible

La decisión del usuario del 2026-10-03 autoriza:

- Conservar y sincronizar los headers firmados, sus antecedentes y hashes;
  omitir exclusivamente contenido cuya purga quede probada.
- Purga offline sin esperar a vaciar el outbox. Recepción con firma humana y
  de dispositivo, autoridad confiable, pertenencia de cada revisión, cierre
  causal completo, lotes completos/ordenados y aplicación atómica.
- Rechazar explícitamente un `kind` faltante y retirar el `.or_else` que
  lo sustituye por el de otro grafo. No eliminar eventos firmados ni reconocer
  el outbox sin publicación real.

[G5 §§9.1–9.3](../design/synchronization.md#91-tipos-y-autenticación-de-eventos)
define `purge-item` / `purge-revisions`, sus objetivos y la conservación
permanente de headers después de retirar payloads. [G2 §9](../design/key-hierarchy.md#9-composición-completa-con-g5g6g7)
vincula las revisiones y partes. La
[spec §15](../../.scratch/passwordmanager/spec.md#15-estado-consolidado-acuerdos-cierres-de-diseño-y-validación)
conserva esos acuerdos y límites de evidencia. Los tickets
[16](../../.scratch/passwordmanager/issues/16-reductor-firmado-de-contenido-y-autoridad.md),
[17](../../.scratch/passwordmanager/issues/17-sync-autohospedado-y-emparejamiento-e2ee.md)
y [18](../../.scratch/passwordmanager/issues/18-historial-papelera-y-purga-humana.md)
siguen resueltos; sus casos no acreditan esta composición.

El formato **ya implementado** de paquete de sync es CBOR:

```text
[2, event_ciphertext_hashes[], graph_ciphertext_hashes[]]
```

Está en `pm-sync/src/lib.rs::{encode_descriptor,decode_descriptor}`. La
lista de eventos tiene hashes estrictamente ordenados, sin duplicados. Cada
lista admite como máximo 256 entradas. Cada evento sigue transportando el
sobre `SignedCausalEvent` completo; `purge-item` / `purge-revisions` ya existen
en la unión firmada. No hace falta inventar un header sustituto, `kind` ni
payload vacío. Dentro de un paquete, las listas independientes permiten
representar un header sin incluir su grafo: la recepción actual lo prohíbe,
pero el formato no exige un campo nuevo para expresar esa ausencia.

## Frontera concreta entre paquetes

Hechos inspeccionados en la base:

1. `CausalReducer::pending_outbox` elige por `event_digest`, `LIMIT 256`.
   Ese orden no es causal y no garantiza incluir el purge que justifica la
   ausencia de los payloads del paquete seleccionado.
2. `SyncReplica::push` publica un solo descriptor de esa selección y después
   reconoce únicamente sus eventos. `pull` descarga y aplica cada root
   independientemente mediante `apply_received_package`.
3. El descriptor no contiene referencia a otros paquetes, índice de página,
   cantidad total del grupo ni root de commit del grupo. No hay otro decoder
   de grupo paginado de eventos en `pm-sync`.
4. G5 §9.1 exige manifiesto paginado con partes autenticadas de hasta 256 KiB
   y commit de digest raíz para transacciones grandes. El contrato describe
   esa garantía, pero no fija los bytes de su composición con el descriptor
   de sync anterior. La paginación existente de **objetos/archivos** tiene
   otro schema y otra función; no constituye un grupo de eventos aplicable.
5. G4 §9 define `events_manifest_digest`, `event_count` y staging de comandos
   **humanos locales**. No es un formato de root que el receptor de sync
   actual acepte ni una regla de agrupación de roots de `sync.list`.

**Inferencia de diseño:** corregir únicamente el paquete pequeño puede hacer
pasar los cuatro eventos del reproductor y seguir fallando cuando el purge
y sus antecedentes estén en paquetes distintos. Agrupar por la respuesta de
`sync.list` no acredita por sí solo completitud: G5 §9.5 dice expresamente que
el cursor y el orden del servidor no son autoridad. Es necesario concretar
el cierre entre paquetes; no se lo implementó implícitamente para obtener un
GREEN parcial.

Opciones concretas pendientes del usuario/orquestador:

| Opción | Representación y comportamiento | Impacto |
| --- | --- | --- |
| **A — recomendada: root paginado explícito** | Conservar los sobres firmados y los descriptores de página existentes. Añadir una variante de root de transferencia que vincule páginas ordenadas por hash/índice y cantidad total de eventos. Publicar el commit root solo después de sus partes; recepción verifica todas las páginas y la prueba causal antes de activar o reconocer el grupo. | Cambia el wire del root; requiere elegir/documentar sus campos y versión. Clientes que no lo soporten deben rechazar explícitamente esa versión. Sin negociación alternativa ni fallback. Conserva los límites actuales por evento, parte, bloque y lote. |
| **B — conservar descriptor 2: recepción diferida por cierre causal** | Cada root sigue siendo un paquete independiente. Persistir recepción cifrada pendiente sin activar headers que carecen de payload; unirla con roots posteriores o evidencia local hasta verificar el purge y todos los antecedentes necesarios. Aplicar solo el conjunto probado. | No añade campos wire. Exige concretar el protocolo de pendientes, reanudación, acuses y qué define un lote completo entre roots; tiene más estado durable y complejidad de crash/backpressure. No permite declarar completo un grupo por haber terminado `list`. |

Estas son propuestas, no decisiones confirmadas ni código ejecutado. La
opción A define explícitamente el commit paginado pedido por G5. La opción B
puede aprovechar la indexación de antecedentes pendientes de G5, pero debe
separar recepción pendiente de autoridad activa y resolver los rechazos
adversarios solicitados. No se propone esperar a la red para purgar, ampliar
256 eventos, borrar outbox ni generar acks falsos.

## Método y RED observado

Prerrequisitos: Linux x86_64, Rust 1.98.1 compartido bajo `.toolchain/`,
dependencias locked/offline, binario `pm-sync` del mismo worktree y fixture
sintética del [método shared B](shared-fixes.md#b--reproducción-y-frontera-detenida).
Cwd siempre este worktree. Toda invocación Cargo/check/lab adquiere
`flock /tmp/pm-cargo-window.lock`, un bloque a la vez.

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh build \
  -p pm-sync --locked --offline
# rc 0; /tmp/pmw2-red-build.log

flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh run \
  -p pm-sync --example shared_purge_probe --locked --offline \
  -- target/debug/pm-sync
# rc 1; /tmp/pmw2-red-purge.log
```

Resultado observado sobre la base sin modificación:

```text
PRE push items=0 payloads=0 purge-markers=1 signed-headers=4 pending=4 revisions=2
PRE independent graphless-reception-accepted=false
POST push result=Err(Reduction(Storage(QueryReturnedNoRows))) pending=4 signed-headers=4 opaque-blocks=1 roots=0
RED pending purged revision headers must publish without deleted payloads
```

El reproductor usa `HumanVault::commit` real y servidor `pm-sync` real con
TLS/RPK; conserva los cuatro headers y pendientes y no da acks falsos.
**No es todavía el E2E de convergencia entre dos réplicas.** No se cambió el
reproductor ni se añadió un test ignorado para esconder el RED.

Se conserva además `/tmp/pmw2-prerequisite-missing-bin.log`: la primera
invocación compiló el ejemplo, pero el worktree nuevo no tenía todavía el
binario de servidor requerido y terminó rc101 al hacer spawn. Ese fallo de
prerrequisito **no cuenta como RED conductual**. Después de construir el
binario se ejecutó una vez el RED conductual anterior.

## Verificación necesaria después de elegir la transferencia

El encargo autoriza y define la extensión del método existente; no se exige
otra confirmación para los siguientes tests una vez cerrado el protocolo:

- Convertir el reproductor en integración ejecutada por `check.sh`, con
  outbox vacío solo tras publicación real y headers conservados. Probar
  publicación interrumpida y reanudación sin pérdida de antecedentes.
- Firmas ausente/ajena; revisión de otro ítem; purge de ítem desconocido;
  `kind` faltante; paquete/página incompleto, duplicado o reordenado; grupos
  mayores de 256 eventos con purge en otra página; replay y rollback
  respecto de una evidencia local posterior conservada. Cada rechazo
  compara autoridad, contenido válido, outbox y marcadores antes/después.
  El límite de rollback integral offline de G5 se conserva.
- Purga selectiva de historial: conservar ganador y contenido no purgado,
  rechazar purga causal de ganador, no reimportar objetivos purgados.
- Dos réplicas reales y servidor TLS/RPK: crear → editar offline → papelera
  → purge offline → push → pull; receptor converge sin contenido purgado,
  conserva headers, autoridad fijada y marcador, incluso después de restart.
- [ADR 0002](../adr/0002-borrado-frente-a-edicion-concurrente.md): trash
  concurrente con edición conserva el ganador LWW en papelera. Por separado,
  G5 §9.2 hace el purge-item terminal ante una edición concurrente, sin
  resurrección por restore/edición/replay. No confundir ambas operaciones.

Gates Linux pendientes, con los mismos oráculos, KDF, límites y deadlines:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
# Barrida secuencial de los 40 comandos exactos del baseline,
# desde este worktree, con logs /tmp/pmw2-*.log y:
# PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
# PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
# PYTHONDONTWRITEBYTECODE=1
```

Baseline leído directamente de `/tmp/pmrs-gate-results.json`: **40 casos,
38 rc0 y 2 rc1** (`lab-tui-operations`, `g7-matrix`). El RED de purge no
figura entre esos 40; debe añadirse como GREEN requerido, sin omitir los dos
FAIL conocidos ni convertirlos en PASS. La barrida W2 **NO se ejecutó**:
sin implementación no existe comparación nueva ni prueba de no regresión.

## CI macOS

Se leyó el [método CI nativo](native-ci.md). El dispatch autorizado corresponde
a la futura corrección final; **no se lanzó una corrida nueva** sobre este
commit exclusivamente documental. El presupuesto de una corrida permanece
sin consumir.

Referencia comprobada por GitHub API: [37110528957](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110528957),
`macOS custody acceptance`, SHA
`272aac8f7383464fd1e0448717110cccfab0fa9f`, `completed/failure`.
Logs leídos: `/tmp/pmw2-macos-reference.log`. La referencia y el
[informe de integración](integration-26-28.md#ci-nativa-y-publicación)
registran ambos CPU en `happy sync`, `durable=integrity`, cinco revisiones
pendientes sin payload y cero roots. No hay resultado W2 con el que comparar.

Después del código final: push normal a la rama W2, verificar el SHA remoto,
una corrida normal `macOS custody acceptance` sobre ese ref con
`pasteboard_diagnostic=false` y `final_phase_only=false`, comprobar head SHA
y esperar ambos jobs. Runners estándar/sintético, sin secrets, caches,
artifacts ni cambios de workflow. Registrar URL/SHA y distinguir happy sync
GREEN de fallos posteriores ajenos, sin anunciar aceptación Mac completa.

## Fallbacks encontrados y frontera de archivos

Se inspeccionaron y conservaron los siguientes comportamientos heredados:

| Ubicación | Cuándo activa | Qué sustituye u oculta |
| --- | --- | --- |
| `pm-vault/src/reducer.rs::apply_received_package`, `.or_else` | Falta el grafo de la revisión visible | Obtiene `kind` del primer grafo de otra revisión del ítem. Su cambio está autorizado, pero no se hizo una corrección parcial antes de resolver la transferencia. |
| `pm-sync/src/lib.rs::sync_stage` | `create_dir` encuentra `AlreadyExists` | Borra/recrea el staging en lugar de rechazar la colisión. No autorizado para modificación. |
| `pm-sync/src/lib.rs::ProcessTlsTransport::put` | Falla eliminar el temporal después del RPC | Descarta el error de cleanup; el caller solo recibe el resultado del RPC. No autorizado para modificación. |
| `pm-sync/src/lib.rs`, cleanup de stages/joined/descarga | Falla eliminar un recurso temporal | Varias llamadas `let _ = remove_*` ocultan el error. No se utilizaron para corregir W2. |
| `pm-vault/src/reducer.rs::decode_event` | El decoder primario de body falla | Intenta `decode_legacy_body` y acepta una representación heredada si valida allí. No autorizado para modificación. |
| `pm-vault/src/reducer.rs::open` | Falta el main vault | `rusqlite::Connection::open` puede crear SQLite nueva; frontera W3, sin cambio. |

Los `from_utf8_lossy` y fallbacks de provider ya inventariados en
[integración](integration-26-28.md#fallbacks-y-limitaciones-heredadas-conservadas)
no se tocaron. Ningún fallback nuevo se implementó.

Archivo tocado: únicamente `docs/verification/w2-purge-sync.md`. Sin conflicto
textual previsto con W1/W3/W4 por esta entrega. El futuro código de W2 afecta
`pm-vault/src/reducer.rs` y `pm-sync/src/lib.rs`; coordinar con W3 si cambia
aperturas/staging, y conservar los cambios independientes de listener de W4
en `pm-sync/src/main.rs`. No se modificaron TUI, custodia, provider, ramas
ajenas, worktree de integración, raíz sucia ni estados de tickets.

**Siguiente acción:** seleccionar A o concretar B con el orquestador. W2
permanece incompleto; después implementar TDD y ejecutar toda la verificación
anterior. No hay candidato de producto para integrar.
