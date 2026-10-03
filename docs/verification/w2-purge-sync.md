# W2 — sincronización después de un purge

2026-10-03. Worktree `.worktrees/w2-purge-sync`, rama
`codex/pm-w2-purge-sync`, base `ee3c1fd31cad59060e4120f3e2518b1196a90c1a`.
Sin integración, cambios de tickets, merge de PR ni cambios ajenos.

**Estado de fase 3: candidato en verificación; W2 NO terminado.** Se retoma
`1aff66ee0834d473438d8c269fae63b7c65fee6e`, limpio y publicado, con replay
legado corregido y RED de backup/restore. El encargo del 2026-10-03 amplía la
zona exclusivamente a `backup.rs::restore_graph_digest` y autoriza hasta
cuatro corridas adicionales de macOS sobre SHAs exactos, cada una con cambio
o hipótesis distinta. El fix mínimo y las dos comparaciones unitarias contra
el reductor pasan, junto con el RED PMB1/purge ahora GREEN. Gates completos y
aceptación nativa pendientes en este checkpoint; no se integra ni se cambian
tickets.

## Decisiones y formato exacto

Decisión del usuario del 2026-10-03: purge offline sin esperar al outbox;
conservar/sincronizar sobres firmados y antecedentes sin payload exclusivamente
cuando se acredita la purga; recepción atómica; `kind` ausente se rechaza;
retirar el `.or_else` que toma el `kind` de otra revisión; sin headers borrados
ni acks falsos.

Decisión del orquestador del 2026-10-03 conforme a G5: **opción A, root
paginado explícito**, concretada en
[G5 §9.1](../design/synchronization.md#91-tipos-y-autenticación-de-eventos).
Plaintext CBOR determinista:

```text
[3, event_count, [[index, page_ciphertext_sha256], ...]]
```

| Campo | Representación y validación |
| --- | --- |
| versión | uint `3`, rechazo explícito si desconocida |
| `event_count` | uint64 no cero; coincide con suma de eventos de todas las páginas |
| `index` | uint64 contiguo desde cero; orden vinculado por el root |
| `page_ciphertext_sha256` | bytes32, sin repetición; SHA-256 del ciphertext autenticado de la página |

Las páginas conservan `[2, event_ciphertext_hashes[], graph_ciphertext_hashes[]]`:
1–256 eventos, 0–256 grafos, hashes bytes32. Eventos estrictamente ordenados
sin duplicados. No se añade orden binario obligatorio a referencias de grafos
v2 históricas; el emisor actual las ordena. Páginas y root ≤256 KiB de
plaintext, bloques ≤512 KiB, recepción no verificada ≤256 MiB, inserción en
lotes ≤256 dentro de una transacción. Ningún parent del grupo puede estar en
una página posterior a su hijo. Se rechazan páginas/eventos/grafos repetidos,
incluso un evento firmado cifrado dos veces con hashes diferentes.

Root/páginas usan el pairing autenticado existente. El `root_hash` publicado
es SHA-256 del ciphertext completo del root; se publica después de todos sus
objetos. Las firmas bajo claves ya confiables conservan la autoridad. No se
negocia otra versión ni se intenta decoder v2 al fallar v3. El decoder v2
permanece para roots históricos; nuevos pushes siempre emiten v3.

La selección agrega el purge y todo su cierre causal, aunque esos antecedentes
ya tengan acuse, y ordena causalmente antes de paginar. Recepción verifica
firmas, DAG completo, pertenencia/ganador causal, grafos y prueba de omisión;
activa headers, retiro de payload y marcador de root en un commit. La evidencia
local posterior se conserva. Un grupo autenticado completo puede ignorar
payloads duplicados ya purgados sin reinsertarlos; el método legado de paquete
sin root conserva su rechazo explícito al payload purgado conocido. Replay de
headers sin payload sigue idempotente. No se cambia la aserción heredada de
`history_lifecycle` ni el conteo de pull de roots propios.

Estas reglas concretan el manifiesto G5 acordado, no reabren G2/G5 ni acreditan
seguridad general. Límites de rollback integral offline, copias externas,
cuota y actualidad del servidor se mantienen en [G5 §§9.2–9.5](../design/synchronization.md)
y [G2 §9](../design/key-hierarchy.md#9-composición-completa-con-g5g6g7).
[ADR0002](../adr/0002-borrado-frente-a-edicion-concurrente.md) separa trash
(conserva ganador LWW en papelera) de purge-item (terminal).

## Reconstrucción y método

Se preservaron `30398ae` (informe de fase 1) y los seis paths sin commit
recibidos al reanudar. `git status`, `git log ee3c1fd..HEAD` y diff confirmaron
ese estado. Se leyó el contrato W2 completo, [shared B](shared-fixes.md#b--reproducción-y-frontera-detenida),
[spec §15](../../.scratch/passwordmanager/spec.md#15-estado-consolidado-acuerdos-cierres-de-diseño-y-validación),
G2/G5, ejecución y tickets
[16](../../.scratch/passwordmanager/issues/16-reductor-firmado-de-contenido-y-autoridad.md),
[17](../../.scratch/passwordmanager/issues/17-sync-autohospedado-y-emparejamiento-e2ee.md),
[18](../../.scratch/passwordmanager/issues/18-historial-papelera-y-purga-humana.md).
Sus estados no se modificaron.

Prerrequisitos: Linux x86_64, Rust 1.98.1 compartido, locked/offline, servidor
`pm-sync` real con TLS/RPK, bóvedas y claves exclusivamente sintéticas. Cwd
siempre este worktree; toda invocación Cargo/check/lab adquiere
`flock /tmp/pm-cargo-window.lock`, un bloque a la vez.

El seed vacío se provisiona fuera de banda para fijar raíz y claves de ambos
dispositivos; no se copian SQLite/WAL entre réplicas durante las transferencias.
Mutaciones usan `HumanVault::commit` real. Las negativas comparan snapshots de
raíz/autoridad, ciphertext válido, outbox y marcadores, e incluyen contenido
válido independiente. Los tests nuevos se ejecutan automáticamente en
`check.sh` mediante `cargo test --workspace --all-targets`; ninguno es ignored.

## RED/GREEN por caso

GREEN del checkpoint (`G`), comando común ejecutado para todos los casos:

```sh
flock /tmp/pm-cargo-window.lock bash -c './scripts/cargo-local.sh fmt --all && ./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication --test shared_purge --locked --offline -- --nocapture && ./scripts/cargo-local.sh clippy -p pm-sync -p pm-vault --all-targets --locked --offline'
# /tmp/pmw2b-green-final-tests.log; rc 0; 27 E2EE + 1 probe
```

Comparación RED (`B`): árbol de producto de `git archive ee3c1fd` en
`/tmp/pmw2b-red-baseline`, con únicamente tests/probe del candidato. Se compararon
los bytes de `pm-sync/src/lib.rs` y `pm-vault/src/reducer.rs` con `git show`.
Target separado obligatorio; compilar y faltar prerrequisitos no son RED:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test \
  --manifest-path /tmp/pmw2b-red-baseline/Cargo.toml --target-dir /tmp/pmw2b-red-target \
  -p pm-sync --test e2ee_replication --test shared_purge --locked --offline \
  --no-fail-fast -- --nocapture
# /tmp/pmw2b-red-isolated-tests.log; rc 101; 14 PASS, 11 FAIL E2EE; probe FAIL
```

| Caso / test bajo `purge_sync::` | B → G y alcance |
| --- | --- |
| `offline_purge_publishes_headers_and_converges_after_restart` y `shared_purge_probe` | RED → GREEN: 4 headers, outbox 4→0 únicamente tras un root real, payloads 0 |
| `pending_purge_carries_previously_acknowledged_graphless_antecedents` | RED → GREEN: pendiente 1, grupo con los 4 headers, servidor fresco |
| `interrupted_publication_preserves_outbox_then_resumes_all_antecedents` | RED en reanudación → GREEN: falla antes del primer put, tras 2 puts o en publish; sin root/ack falso y luego converge |
| `signed_purge_rejects_missing_foreign_signatures_and_incomplete_proof_atomically` | Negativas ya PASS en base; siguen PASS: firma humana ausente/ajena, dispositivo ajeno, `kind` de evento ausente y purge faltante |
| `missing_device_signature_rejects_at_wire_boundary_without_mutation` | PASS; en base v3 ya es desconocida: no atribuirle una nueva validación de firma v3 |
| `purge_unknown_item_rejected` | RED acepta ítem desconocido → GREEN rechaza |
| `purge_revision_of_another_item_rejected` | Negativa ya PASS → PASS; incluye otra revisión real y todos los grafos válidos |
| `purge_causal_winner_rejected` | RED acepta paquete con purge inadmisible → GREEN rechaza |
| `missing_graph_kind_rejects_with_valid_payload_unchanged` | PASS heredado → PASS; no inventar RED: constraint ya rechazaba `kind` vacío |
| `duplicate_package_rejects_with_valid_payload_unchanged` | RED acepta evento repetido → GREEN rechaza, ciphertext completo válido |
| `duplicated_and_reordered_event_lists_reject_atomically` | PASS para hashes/eventos duplicados y lista de hashes reordenada; base rechaza v3 por versión, no por todas las reglas nuevas |
| `transfer_root_rejects_unknown_version_duplicate_reordered_and_missing_pages` | PASS v3: versión desconocida, hash de página repetido, índices reordenados, página inexistente, count imposible; base solo acredita rechazo de versión |
| `missing_parent_and_count_mismatch_reject_complete_wire_atomically` | PASS v3: partes presentes pero cierre causal o count incorrecto; misma limitación de evidencia B |
| `paginated_purge_verifies_all_pages_and_causal_order_before_activation` | RED en push → GREEN: 259 eventos, 2 páginas, purge en página posterior; falta de página o páginas causales intercambiadas no activa nada |
| `selective_purge_and_replay_preserve_newer_content_and_authority` | RED en push selectivo → GREEN; ajuste posterior conserva rechazo legado de payload antiguo, headers idempotentes y ganador nuevo |
| `reception_marker_failure_rolls_back_authority_payload_and_purge_then_resumes` | RED antes de recepción → GREEN: trigger de commit de marcador revierte todo; restart aplica una vez y conserva contenido independiente |
| `two_real_replicas_offline_edit_purge_converge_over_tls_rpk` | RED → GREEN, servidor real TLS/RPK, dos HumanVault reales, autoridad/digest iguales, headers conservados, contenido ausente, restart idempotente |
| `trash_and_terminal_purge_win_concurrent_edit_over_tls_rpk` | RED en publicación del purge → GREEN, trash conserva LWW y purge terminal converge ante edición concurrente |
| `historical_v2_graph_reference_order_remains_compatible` | GREEN en G: roots históricos con grafos en orden no binario siguen aceptados; push siempre v3 |

RED adicional específico de `.or_else`:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test \
  --manifest-path /tmp/pmw2b-red-baseline/Cargo.toml --target-dir /tmp/pmw2b-red-target \
  -p pm-sync --test e2ee_replication losing_graph_never_substitutes_kind_of_exact_local_winner \
  --locked --offline -- --nocapture
# /tmp/pmw2b-kind-red.log; rc 101
# GREEN mismo test en G; también /tmp/pmw2b-kind-green2.log, rc 0
```

La base sustituye el `kind` archivo del ganador local por nota del grafo
perdedor; W2 conserva el snapshot exacto. El ganador local completo y su `kind`
existente son evidencia válida; no se toma un valor de otra revisión.

La primera comparación de base `/tmp/pmw2b-red-baseline-tests.log` reutilizó
artefactos del target W2 y **se descarta como evidencia**, sin borrar su log.
Errores de compilación/lint de fixtures en `green2/green4`, `review-check`,
`clippy2`, `kind-green` y el primer `backup-export` tampoco son RED conductual.

## Regresión encontrada después del checkpoint

`/tmp/pmw2b-final-check.log`, rc 101, encontró la aserción intacta del test
`history_lifecycle::revision_and_item_purge_are_scoped_atomic_and_leave_only_replay_markers`:
«a signed old graph must not cross the terminal purge marker». El receptor
legado aceptaba sin reinsertar ese grafo. Se añadió rechazo explícito para
paquetes sin root con revisiones ya conocidas/purgadas, manteniendo grupos
cerrados autenticados idempotentes y sin resurrección. No se añadió fallback
ni se cambió la aserción ni el conteo de pulls de roots propios.

Verificación posterior rc 0 en `/tmp/pmw2b-replay-compatibility.log`:

```sh
flock /tmp/pm-cargo-window.lock bash -c './scripts/cargo-local.sh test -p pm-vault --test history_lifecycle --locked --offline -- --nocapture && ./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication selective_purge_and_replay_preserve_newer_content_and_authority --locked --offline -- --nocapture && ./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication trash_and_terminal_purge_win_concurrent_edit_over_tls_rpk --locked --offline -- --nocapture && ./scripts/cargo-local.sh clippy -p pm-sync -p pm-vault --all-targets --locked --offline'
```

Tres casos de lifecycle y ambos casos sync pasan, sin modificar tests heredados.
La primera variante que rechazaba también el root propio autenticado rompió
la carrera concurrente: `/tmp/pmw2b-replay-green.log`, rc101. La variante
correcta preserva la diferencia contractual entre paquete legado sin root y
grupo completo autenticado; `replay-green2` pasó todos los casos conductuales,
pero Clippy rechazó un tipo complejo. Se añadió un alias, sin suprimir el lint.

## Segundo defecto: backup/restore y sync

RED concreto reproducido en Linux, tras la corrida nativa fallida:

```sh
flock /tmp/pm-cargo-window.lock bash -c './scripts/cargo-local.sh fmt --all && ./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication backup_restored_streams_remain_bound_and_publish_with_offline_purge --locked --offline -- --nocapture'
# /tmp/pmw2b-backup-export2.log; rc 101
# restore/export 3 kind=item-revision failed: Integrity
```

La fixture combina PMB1 real, un archivo streaming de 2 MiB, restauración en la
misma bóveda y purge offline. `backup.rs::restore_graph_digest` usa siempre
`pm/staged-stream/v1`, incluso con cero streams. `reducer.rs::graph_digest`
usa para el grafo sin streams el formato inline `[package_bytes,
CBOR(attachments)_bytes]`. El header restaurado queda firmado contra otro
digest: su rechazo de integridad es correcto. No se cambian firmas/digests
históricos ni se prueba otro algoritmo tras un mismatch.

Fase 3: se revisó `/tmp/pmw2b-backup-digest-proposal.patch` contra los dos
productores y la topología PMB1. PMB1 restaura todos los adjuntos como streams;
cero filas staged significa lista vacía de adjuntos inline. Se aplica la
selección aprobada y además se mueve la inicialización streaming después de
ella, para seleccionar antes de hashear/firmar. El único cambio productivo en
`backup.rs` está dentro de `restore_graph_digest`:

```rust
if rows.is_empty() {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(2).unwrap().bytes(package).unwrap().bytes(&[0x80]).unwrap();
    return Ok(digest(&encoder.into_writer()));
}
```

`0x80` representa CBOR de la lista vacía de adjuntos, no un payload sustituto.
Las restauraciones ya firmadas contra el digest incorrecto siguen fallando
explícitamente; no se reescriben ni se les da un acuse falso.

Tests unitarios en `reducer.rs::restore_digest_tests`: sin streams y con dos
streams/dos chunks por stream, orden de fuentes diferente al de targets. Ambos
comparan directamente contra `reducer.rs::graph_digest`, sin duplicar su
algoritmo. Fixture SQLite en memoria y archivos privados sintéticos propios;
cleanup estricto. El RED unitario conserva 1 PASS streaming y 1 FAIL inline
por digest diferente, no por compilación o prerrequisitos:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault \
  --lib restore_graph_digest --locked --offline -- --nocapture
# /tmp/pmw2c-digest-red.log; rc 101 antes del fix
flock /tmp/pm-cargo-window.lock bash -c './scripts/cargo-local.sh fmt --all && ./scripts/cargo-local.sh test -p pm-vault --lib restore_graph_digest --locked --offline -- --nocapture && ./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication backup_restored_streams_remain_bound_and_publish_with_offline_purge --locked --offline -- --nocapture'
# /tmp/pmw2c-digest-green.log; rc 0, dos unitarios y PMB1/purge GREEN
```

El caso PMB1 sigue exigiendo 7 eventos push/pull, 3 elementos y 1 marcador de
purge con exportación íntegra de cada grafo. No se relajó ninguna aserción.

## Gates Linux frente al baseline

Se ejecutaron los 40 comandos exactos de `/tmp/pmrs-gate-results.json`, uno a
la vez bajo flock, con artefactos fijados, sin reintentos de cada lab ni cambios
de deadlines/KDF/oráculos. Runner propio `/tmp/pmw2b-gates.py`; logs
`/tmp/pmw2b-gate-*.log`, resultados `/tmp/pmw2b-gate-results.json`.

```text
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
PYTHONDONTWRITEBYTECODE=1
```

Resultado bruto: **40 casos, 37 rc0, 3 fallos** frente a baseline **38 rc0,
2 fallos**. Los 38 comandos de labs completaron sin regresión frente al baseline:
36 rc0, `lab-tui-operations` rc1 y `g7-matrix` rc1 heredados. El check adicional
falló en compilación del último fixture (corregido); no se oculta ni se cuenta
como PASS. Clean offline bruto rc0. La repetición de check después encontró el
replay legado anterior, y el nuevo RED backup/restore sigue pendiente de fix.
**No se ha alcanzado el gate final sin regresión.**

Checks finales ejecutados sobre el código posterior de replay:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
# /tmp/pmw2b-scope-check.log; rc 101, 27 PASS + único FAIL nuevo de backup/export
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
# /tmp/pmw2b-scope-clean.log; rc 0, build 41.57 s
```

Se ejecutaron ambos dentro del mismo bloque flock, preservando por separado sus
rc/logs en `/tmp/pmw2b-scope-gates.log`. El check final sigue rojo; no equivale a
38/40 rc0 ni a aceptación. El probe tiene GREEN en el checkpoint anterior y en
las corridas focalizadas posteriores de replay, pero `check.sh` corta antes de
su entrada cuando falla la prueba de backup. No se añade skip ni ignore.

Clippy de los nuevos paths pasó en `/tmp/pmw2b-replay-compatibility.log`.
`git diff --check` y todos los enlaces relativos de ambos documentos W2 pasaron.

## macOS: corrida terminada, no GREEN

[37124954337](https://github.com/SantanaJcp/passwordmanager/actions/runs/37124954337),
SHA `eae7d84abaccad9d3c01a9e62c57616fd41fbd3b`, `completed/failure`, ambos jobs
fallidos. Se aplicó [native-ci.md](native-ci.md): repo público comprobado, labels
estándar `macos-15` y `macos-15-intel`, flags `pasteboard_diagnostic=false` y
`final_phase_only=false`, sin cambios de workflow, secrets, caches ni artifacts.
Se esperó terminación y se descargaron logs/API a `/tmp/pmw2b-macos.log` y
`/tmp/pmw2b-macos.json`.

| CPU | Referencia 37110528957 | W2 37124954337 |
| --- | --- | --- |
| Apple silicon | `durable=integrity`, roots 0 | `durable=integrity`, bloques 154, roots 0 |
| Intel | `durable=integrity`, roots 0 | `durable=pushing` al timeout de observación, bloques 89, roots 0 |

La [referencia](https://github.com/SantanaJcp/passwordmanager/actions/runs/37110528957)
usó SHA `272aac8f7383464fd1e0448717110cccfab0fa9f`; logs/API nuevos en
`/tmp/pmw2b-macos-reference.log` / `.json`. No atribuir al Intel un fallo de
integridad que no emitió. Mayor número de bloques no prueba publicación ni
convergencia. El defecto PMB1 local explica un camino de integridad relevante,
pero no se declara causa nativa aislada sin otra corrida. La CI se lanzó antes
del ajuste posterior de replay; no acredita el SHA posterior. Una corrida extra
no se lanzará sin ampliar la autorización explícita de una corrida.

## Fallbacks conservados y frontera de entrega

Retirado con autorización: `.or_else` de `apply_received_package`, que
sustituía el `kind` ausente del ganador por el de otra revisión. No se añade
otro valor sustitutivo: `kind` ausente/corrupto se rechaza.

| Heredado, sin modificación | Activación y comportamiento |
| --- | --- |
| `pm-sync::sync_stage` | Colisión `AlreadyExists`: borra/recrea staging en vez de rechazarla |
| `ProcessTlsTransport::put` | Falla cleanup del input temporal: descarta ese error y devuelve resultado RPC |
| Cleanup de stages/joined/descarga | `let _ = remove_*` oculta fallos de limpieza |
| `decode_event` | Falla decoder primario: intenta `decode_legacy_body` heredado |
| `CausalReducer::open` / SQLite | Archivo ausente: apertura puede crearlo; frontera W3 sin cambio |
| TestDir y labs heredados | Limpieza best-effort puede ocultar residuos; no hubo sweep de `/tmp/pm-*` |
| `backup.rs::RestoreStager::finish` | Un error SQL al comprobar la revisión visible se convierte en `false` por `.unwrap_or(false)` y después en `Integrity`; oculta la categoría de almacenamiento |

`from_utf8_lossy` y fallbacks de provider/listener siguen en
[integración](integration-26-28.md#fallbacks-y-limitaciones-heredadas-conservadas),
sin modificaciones W2.

Archivos propios: `pm-sync/src/lib.rs`, `pm-vault/src/reducer.rs`,
`pm-sync/examples/shared_purge_probe.rs`, `pm-sync/tests/shared_purge.rs`,
`pm-sync/tests/e2ee_replication.rs` y su módulo `purge_sync.rs`,
`docs/design/synchronization.md`, este informe. No TUI W1, aperturas/custodia/staging
W3, listener/admisión/proveedor W4, raíz sucia ni worktree de integración.
`reducer.rs` puede dar conflicto textual con W3: conservar su política de
apertura y las verificaciones de W2. `pm-sync/src/lib.rs` puede compartir edición
con W4; su listener en `main.rs` no se tocó. El módulo nuevo al final de los
tests puede dar conflicto menor con otros añadidos. No se integra desde W2.

**Siguiente acción:** resolver la ampliación concreta de backup/CI, luego
GREEN del nuevo RED, check/clean finales y comparación sin regresión; publicar
el SHA final y pasar al merger. Mientras quede esa frontera, W2 es incompleto.
