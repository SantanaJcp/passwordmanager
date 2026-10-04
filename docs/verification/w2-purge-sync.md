# W2 — sincronización después de un purge

2026-10-03. Worktree `.worktrees/w2-purge-sync`, rama
`codex/pm-w2-purge-sync`, base `ee3c1fd31cad59060e4120f3e2518b1196a90c1a`.
Sin integración, cambios de tickets, merge de PR ni cambios ajenos.

**Estado actual de fase 4: corrección publicada, RED/GREEN y gates Linux sin
regresión (40 casos, 38 rc0). Happy sync TUI Intel confirmado dentro de 20 s;
ARM no ejecuta ese job por una colisión de backup previa, frontera W1. Las
cuatro corridas nativas terminaron; todos los workflows siguen failure.
W2 NO cerrado: falta aceptación del happy TUI en ambas CPU.**

**Registro de fase 3: Linux sin regresión; macOS incompleto.** Se retoma
`1aff66ee0834d473438d8c269fae63b7c65fee6e`, limpio y publicado, con replay
legado corregido y RED de backup/restore. El encargo del 2026-10-03 amplía la
zona exclusivamente a `backup.rs::restore_graph_digest` y autoriza hasta
cuatro corridas adicionales de macOS sobre SHAs exactos, cada una con cambio
o hipótesis distinta. El fix mínimo y las dos comparaciones unitarias contra
el reductor pasan, junto con el RED PMB1/purge ahora GREEN. El checkpoint
`fa8049e94d0c98b67ceca4fc59f5f19f1e1babb3` pasa los 40 gates Linux sin
regresión. macOS ya no observa el rechazo de integridad en ARM, pero ambas
CPU vencen en `pushing` sin publicar roots. Un diagnóstico nativo de volumen
publicado en `7b4b5f591470de8ffcb0ac39b5039163a3126af0` sí publica un root y
converge en ambas CPU; los 29 E2EE pasan nativamente. El happy sync de la TUI
sigue rojo. Se detiene ante la decisión de ampliar el diagnóstico hacia la
fixture que pertenece a W1 o cambiar la estrategia del cliente; no se integra
ni se cambian tickets. En aquel checkpoint quedaban dos de las cuatro
corridas autorizadas para fase 3; ese saldo no es el presupuesto de fase 4.

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

### Fase 3 — gates del digest corregido

Los mismos 40 comandos se ejecutaron una vez, serialmente, con los mismos
artefactos/lock/prerrequisitos, sobre el árbol de producto publicado en
`fa8049e`. Runner `/tmp/pmw2c-gates.py`, log `/tmp/pmw2c-gates.log`, resultados
`/tmp/pmw2c-gate-results.json`, logs `/tmp/pmw2c-gate-*.log`:

```text
SUMMARY cases=40 rc0=38 regressions=0
check.sh rc0 (89.071 s); clean-offline-build.sh rc0 (43.126 s)
```

`check.sh` ejecutó los dos unitarios de digest, los 28 casos E2EE incluido
PMB1/restore/purge y el probe; fmt/check/test/Clippy verdes. Los dos rc1 son
los mismos del baseline: `lab-tui-operations` vence al observar
`exact-duplicates=1` truncado en 80 columnas; `g7-matrix` conserva staging
streaming tras EIO/ENOSPC en `commit-outbox-audit`. No se cambian sus
aserciones ni se presentan como aceptación; corresponden a las fronteras
W1/W3. No se repiten labs para ocultar un fallo. La sección siguiente conserva
los resultados históricos rojos de fase 2.

### Fase 2 — evidencia histórica

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

## macOS: integridad corregida, happy sync todavía sin GREEN

### Método diagnóstico de fase 3

Tras `fa8049e`, la corrida 37127063353 ya no observa `Integrity` en ARM:
ambas CPU quedan en `pushing` al vencer la misma observación de 20 s, con
208/89 bloques y cero roots. Para distinguir subida de objetos de espera de
commit root, el segundo candidato habilita la suite E2EE de `pm-sync` en
macOS nativo: usa únicamente UnixStream, UID propio y TLS/RPK reales. Los
sockets macOS se provisionan en un path corto explícito de
`/private/var/tmp`, sin intentar otra ruta después de un fallo. No se toca
la TUI, el listener ni el workflow.

`restored_large_workload_measures_real_tls_root_publication` usa 16 notas,
un archivo de 16 MiB + 4096, PMB1 real, restore y purge offline: 39 eventos
y una sola página v3. Un wrapper del transporte real solo emite categorías,
contadores y milisegundos: cada 64 puts, antes/después de publish y después
de la convergencia. Exige un root real, outbox vacío después de publish,
39 eventos recibidos y 35 elementos más un marcador de purge. No hay skip,
deadline/KDF cambiado ni acuse fabricado. El tiempo total es diagnóstico,
**no sustituye** el happy sync de la TUI dentro de sus 20 s.

Comando local bajo el método W2, seguido del check completo antes de publicar:

```sh
flock /tmp/pm-cargo-window.lock bash -c './scripts/cargo-local.sh fmt --all && ./scripts/cargo-local.sh test -p pm-sync --test e2ee_replication restored_large_workload_measures_real_tls_root_publication --locked --offline -- --nocapture && ./scripts/check.sh'
# /tmp/pmw2c-workload-check.log
```

Local: ese bloque pasó. Para que CI conserve los contadores también cuando el
test pasa sin `--nocapture`, se escribe directamente a stdout únicamente el
schema fijo `PMW2_WORKLOAD`. El check posterior de esa variante también pasa:
`/tmp/pmw2c-workload-final-check.log`, 29 E2EE, unitarios/probe y Clippy.
Mide 271 puts, 272 gets, una página y un root; publish comienza a 10875 ms,
termina a 10895 ms y la réplica converge a 19200 ms. Son tiempos Linux,
no evidencia macOS ni cumplimiento de una latencia universal.
Clean offline del mismo candidato pasa en `/tmp/pmw2c-workload-clean.log`
(41.63 s). Solo se añadieron tests/diagnóstico/documentación desde el barrido
de 40 gates; el código productivo es idéntico al de `fa8049e`. No se repiten
los labs sin una nueva modificación productiva o preocupación pendiente.

Native CI sigue `native-ci.md`: mismo workflow/labels/flags, SHA exacto,
sin caches/artifacts/secrets. Solo una corrida con este nuevo diagnóstico;
su resultado no convierte el timeout anterior en PASS.

### Primera corrida de fase 3

[37127063353](https://github.com/SantanaJcp/passwordmanager/actions/runs/37127063353),
SHA `fa8049e94d0c98b67ceca4fc59f5f19f1e1babb3`, `completed/failure`.
Ambos tests unitarios de restore pasan en las dos CPU. Flags
`pasteboard_diagnostic=false`, `final_phase_only=false`, repo público y
labels estándar comprobados; workflow sin cambios, sin caches/artifacts/secrets.
Logs/API `/tmp/pmw2c-macos-run1.log` y `.json` (ARM además en `-arm.log`).

| CPU | Resultado al vencer observación de 20 s | Bloques | Roots |
| --- | --- | --- | --- |
| Apple silicon | `durable=pushing`, `screen=pushing`, mismo PID sync | 208 | 0 |
| Intel | `durable=pushing`, `screen=pushing`, mismo PID sync | 89 | 0 |

Se comprobó la fixture: `macos_tui_migration_lab.py` restaura PMB1 antes del
sync (restore en líneas 489–500, sync en 532–537). En ARM el rechazo de
integridad anterior desaparece después del fix; esto acredita ese avance,
no la terminación del sync. En Intel todavía no alcanza el root y por tanto
no se afirma que ya recorrió todas las revisiones restauradas.
Entorno observado: macOS 15.7.9/kernel 24.6.0, Rust 1.98.1 con hosts nativos
`aarch64-apple-darwin` y `x86_64-apple-darwin`.
ImageOS `macos15`; ImageVersion ARM `20260907.0337.1`, Intel
`20260824.0482.1`; usuario `runner`, UID 501. Labels `macos-15` y
`macos-15-intel`.

### Segunda corrida de fase 3 — diagnóstico nativo observado

[37128301263](https://github.com/SantanaJcp/passwordmanager/actions/runs/37128301263),
SHA `7b4b5f591470de8ffcb0ac39b5039163a3126af0`, `completed/failure`.
Mismos flags, workflow y entorno nativo observado que la primera corrida.
Logs/API `/tmp/pmw2c-macos-run2.log` y `.json`; labels comprobados por API en
`/tmp/pmw2c-macos-run2-labels.json`. Ningún cache/artifact/secret propio.
**29/29 E2EE pasan por CPU**, incluidos el RED PMB1/purge corregido y el caso
de 259 eventos/dos páginas con negativas de orden/omisión intactas. El happy
sync TUI posterior sigue fallido; el workflow conserva ese fallo.

Diagnóstico sobre el transporte real: 39 eventos, una página, 271 puts,
272 gets, un root publicado, 35 elementos más un marcador de purge,
outbox reconocido solo después de publish y convergencia real:

| CPU | Antes de publish | Publish completo | Coste de publish | Convergencia total |
| --- | --- | --- | --- | --- |
| Apple silicon | 15309 ms | 15342 ms | 33 ms | 27716 ms |
| Intel | 22082 ms | 22124 ms | 42 ms | 36387 ms |

En el happy TUI de esa misma corrida: ARM `pushing`, 198 bloques/0 roots;
Intel `pushing`, 119 bloques/0 roots, mismo PID en ambos, observación de 20 s
intacta. No se observó `Integrity` en ningún happy job de fase 3.

**Hechos:** el caso control publica roots con el código corregido en ambas
CPU; con una sola página ya puede tardar más de 20 s; el commit del root del
control tarda 33/42 ms, no decenas de segundos. No hay evidencia de bloqueo
del root ni de un fallo exclusivo de paginación. `ProcessTlsTransport::call`
crea un proceso por RPC; el control completa 271 puts y después 272 gets.

**Inferencia:** el volumen y coste acumulado de objetos/RPC, antes de publish,
es una explicación respaldada para el timeout TUI. No se atribuye todavía
ese coste al spawn, TLS, SQLite, I/O o scheduler de launchd por separado.
La fixture TUI tiene otro historial y corre bajo launchd; el control no es una
réplica exacta de su estado. `ProcessType=Background` existe en el plist,
pero no se midió su impacto ni se cambió ese perfil.

**Decisión fuera de la zona actual:** para aislar el siguiente cambio hacen
falta contadores/fases del happy job TUI exacto en
`macos_tui_migration_lab.py`, path actualmente editado por W1. Opciones:

1. **Recomendada:** el orquestador coordina con W1 una ampliación solo de
   diagnóstico: cantidad de eventos/grafos/páginas/puts previstos y completos,
   fase alcanzada y tiempos por categoría, sin IDs, contenidos, hashes ni
   cambio de plazos. Usar una de las dos corridas restantes para discriminar
   volumen real frente a coste por RPC/perfil launchd.
2. Seleccionar una nueva estrategia de cliente (por ejemplo, reducir procesos
   por RPC manteniendo TLS/RPK y request/backoff actuales) y definir su método
   de fallo/reinicio/compatibilidad antes de implementarla. Es propuesta;
   no se añadió un worker, protocolo, batching ni fallback a ciegas.

No se consume otra corrida idéntica ni se amplía el plazo del fixture.

### Corrida anterior de fase 2

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
no estaba autorizada en fase 2. La fase 3 amplió ese permiso a cuatro corridas.

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
| `backup.rs::RestoreCollector::finish` | Un error SQL al comprobar la revisión visible se convierte en `false` por `.unwrap_or(false)` y después en `Integrity`; oculta la categoría de almacenamiento |

`from_utf8_lossy` y fallbacks de provider/listener siguen en
[integración](integration-26-28.md#fallbacks-y-limitaciones-heredadas-conservadas),
sin modificaciones W2.

Archivos propios: `pm-sync/src/lib.rs`, `pm-vault/src/reducer.rs`,
`pm-vault/src/backup.rs` exclusivamente dentro de `restore_graph_digest`,
`pm-sync/examples/shared_purge_probe.rs`, `pm-sync/tests/shared_purge.rs`,
`pm-sync/tests/e2ee_replication.rs` y su módulo `purge_sync.rs`,
`docs/design/synchronization.md`, este informe. No TUI W1, aperturas/custodia/staging
W3, listener/admisión/proveedor W4, raíz sucia ni worktree de integración.
`reducer.rs` puede dar conflicto textual con W3: conservar su política de
apertura y las verificaciones de W2. `pm-sync/src/lib.rs` puede compartir edición
con W4; su listener en `main.rs` no se tocó. El módulo nuevo al final de los
tests puede dar conflicto menor con otros añadidos. No se integra desde W2.

En fase 3 se tocaron solo cinco paths: `backup.rs` (la función autorizada),
`reducer.rs` (unitarios al final), `e2ee_replication.rs` (habilitación macOS y
path corto de fixture), `e2ee_replication/purge_sync.rs` (diagnóstico) y este
informe. Verificada la rama W3: su hunk de backup está en `write_backup`,
no en el digest; composición de esta fase debería ser trivial. Sus hunks de
reducer están en apertura de bóveda/conexión, separados de los unitarios.
No hay paths nuevos compartidos con W1/W4. El merger deberá verificar la
composición de todos los commits W2 anteriores; no se simuló ni realizó merge.

**Siguiente acción de fase 3:** el orquestador decide la ampliación diagnóstica
acotada con W1 (recomendada) o concreta la estrategia/método del cliente.
El fix del digest, los gates Linux y el diagnóstico nativo están publicados;
no pasar W2 como cerrado al merger mientras el happy sync TUI siga rojo.

## Fase 4 — método de diagnóstico y regresión autorizado

El encargo amplía la zona a transporte/servidor sync, `sync_job.rs` y solo
instrumentación sync del fixture Mac. Hasta dos corridas diagnósticas y dos
de verificación sobre SHAs exactos; no modificar plazos, límites ni wire.
`PMW2_TIMING=1` se inyecta únicamente en los procesos propios del fixture.
Categorías fijas, contadores y microsegundos, sin IDs, hashes, rutas ni payloads.
El fixture agrega conteo, tiempo total y máximo por categoría y distingue
servidor de job; no imprime stderr arbitrario. Se observan spawn, preparación,
TLS por conexión, RPC por bloque, SQLite, exportación, fsync y backoff.
Comparar spawn/preparación/handshake/exchange con wall time del mismo job;
los scopes anidados no se suman como tiempos independientes. Al vencer 20 s
solo hay fases completadas, una cota parcial explícita. PID solo se compara
y se emite `same/missing/changed`; no se imprime.

Si se confirma reconexión por bloque, regresión Linux con servidor TLS/RPK
real: el workload restaurado de 39 eventos conserva todos sus objetos/RPCs,
root real y convergencia; exigir una creación de proceso/handshake para
la secuencia en una sesión autenticada. RED antes del fix, GREEN después.
Errores de transporte deben seguir visibles; ningún ack antes de publicación.
Ejecutar bajo flock los tests E2EE, check, clean offline y los mismos 40 gates
de `/tmp/pmw2c-gate-results.json`, sin repetir fallos para esconderlos.
Confirmar el happy TUI exacto dentro de 20 s en ambas CPU; un workflow puede
seguir fallido por otra matriz y se registra separado.

### Diagnóstico 1 observado y causa acotada

[37129675339](https://github.com/SantanaJcp/passwordmanager/actions/runs/37129675339),
SHA `d6acdb63d3333a167d5965b4e17f5924b3069d9b`, completed/failure.
Intel alcanza el happy job: 59 eventos seleccionados, 114 bloques/0 roots,
mismo PID al vencer. Muestra de 115 puts completados: temporal+fsync 8.376 s;
spawn 0.144 s; espera de procesos 8.782 s (incluye init/TLS/exchange/exit);
handshakes 115 / 0.166 s; intercambio 2.845 s; preparación cliente 0.285 s;
exportación 34 / 2.380 s; SQLite dispatch servidor 115 / 2.422 s y apertura
115 / 0.212 s. Sin backoff registrado. Job spawn 0.000243 s y status fsync
0.033 s incluyen también el rechazo de pin anterior: **no sumar como fases
exclusivas del happy job**. La siguiente medición usa offsets antes del happy
job para excluir ese antecedente. Es una muestra parcial al cutoff, no duración
completa ni prueba de que 115 sean todos los bloques necesarios.

ARM falla antes de sync, al desbloquear la TUI de `rejected_source` (fixture
1PUX), render=password-prompt. No permite atribuir una latencia W2 a ARM;
no se cambia esa frontera de W1 ni se consume otra corrida idéntica.
Logs `/tmp/pmw2d-macos-diagnostic1-{arm,intel}.log`, metadata `.json`.
Repo público/labels estándar, flags false/false y workflow intactos; coste
según [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
Los dos dispatch por SHA recibieron HTTP422 y **no crearon runs**; el dispatch
por rama resolvió el SHA anterior y se verificó por API.

**Causa con evidencia Intel:** trabajo por bloque en el adaptador de proceso,
no el handshake en sí: fsync del temporal y arranque/espera repetidos. La
reconexión también ocurre una vez por RPC, pero el handshake medido es menor
que esos costes. Sin evidencia de backoff ni relanzamiento launchd. El fsync
del temporal no es el fallback heredado de cleanup; ese fallback se conserva.

### Corrección y método GREEN

`ProcessTlsTransport::authenticated_session` conserva el cliente separado y
reutiliza un único TLS1.3/RPK autenticado. Se envían los mismos JSON/framing y
métodos, una solicitud a la vez, sin batching ni otro wire/root. IPC al cliente
transporta únicamente ciphertext bajo frame ≤1 MiB; deadline absoluto 30 s
para escribir petición/leer respuesta, antes de aceptar respuesta. Ningún
replay interno: un fallo se devuelve y solo el retry/backoff ya existente de
la réplica puede iniciar otro intento. El proceso se cierra/recolecta antes
de marcar el job exitoso; una limpieza fallida se informa. TLS, pin, ALPN,
ACL por RPC y hashes/límites siguen exigidos. El servidor Unix acepta frames
sucesivos bajo esa conexión; listener/admisión/proveedor no cambian. Windows
conserva el camino existente, sin afirmar esta optimización validada allí.

Los puts de sesión envían el ciphertext ya disponible, sin fabricar un
archivo durable auxiliar por bloque. No se elimina fsync de estado durable,
SQLite, staging ni outbox. La modalidad de proceso por RPC y su cleanup
heredado permanecen intactos; no se elige como alternativa tras fallar sesión.

RED Linux `/tmp/pmw2d-session-red.log`, rc101: workload completo publica y
converge (271 puts/272 gets), pero un wrapper que ejecuta el binario real
cuenta 546 ejecuciones frente a 1 requerida. GREEN inicial mismo workload:
1 ejecución, publish 3.269 s frente a 10.143 s y convergencia 4.163 s frente a
18.051 s. Oráculos previos intactos. Ese primer bloque tuvo Clippy rojo por
estilo (`collapsible_if`), no es gate completo. Se añaden negativas reales de
ACL retirada entre RPCs, hash/tamaño inválidos y conexión perdida sin replay
interno; también se conservan tests TLS del cliente por RPC legado.

Check posterior `/tmp/pmw2d-session-check2.log` rc0: 31 E2EE, dos negativas IPC
(frame sobredimensionado/truncado y deadline ya vencido), suite completa y
Clippy. Se extrajo el setup del contador del workload sin suprimir lints.
`git diff --check` y AST de ambos fixtures pasan. El fixture conserva modos
diagnóstico/final-phase anteriores: opt-in W2 solo en normal Full25. Se
comparan separadamente los PIDs del custodio y servidor antes/después del
happy job; no se imprimen. Se medirá también wall time observado por la TUI.
No se afirma que el PID server de la primera muestra pruebe continuidad del
PID del custodio; sus métricas indican dos launches contando el wrong-pin
anterior, pero no se tomó ese segundo PID explícito en diagnóstico 1.

### Verificación 1: publicación recuperada, convergencia TUI pendiente

[37131160116](https://github.com/SantanaJcp/passwordmanager/actions/runs/37131160116),
SHA `0bd0721d4d5610c184e9fde26edd77f64651c1c7`, completed/failure.
31/31 E2EE y las negativas IPC pasan por CPU. Control de 39 eventos:
ARM publish 7.518 s/convergencia 10.505 s; Intel 9.986/13.084 s,
frente a 15.342/27.716 y 22.124/36.387 s de fase 3. Un solo proceso,
271 puts y 272 gets conservados. No sustituye la fixture TUI exacta.

Intel happy: 287 bloques/1 root al cutoff, `pulling`, custodio y servidor
ambos con PID estable. 59 eventos/1 página; push completo 12.769 s,
287 puts 7.343 s, 287 gets completados 1.222 s, publish 0.002139 s,
59 exportaciones 4.249 s, fsync joined 0.306 s y ack 0.178 s.
Un handshake 0.032160 s y spawn 0.000857 s; ningún fsync de temporal put
ni backoff registrado. El tiempo de pull/activación no había terminado
cuando se leyó la muestra: no inventar su duración.
ARM falla antes del sync en `diagnose_agent_accept_lane`, password-prompt;
no es fallo W2 medido ni evidencia de aceptación TUI.

Método adicional acotado: probar con servidor real que una sesión no fuerza
cierre/checkpoint de WAL después de cada put. RED: WAL ausente después de
un put confirmado; GREEN: WAL presente con commit, lectura válida, y cierre
real del servidor seguido de reapertura conserva bloque/root. Mantener una
conexión SQLite abierta durante TLS, sin transacción lectora retenida, cambios
synchronous, deshabilitar checkpoint ni agrupar commits. SQLite documenta
checkpoint al cerrar la última conexión y FULL conserva sync por commit:
[WAL §3.1 y §2.3](https://www.sqlite.org/wal.html). Si no mejora el job dentro
20 s, registrar el fallo y el siguiente cuello sin ampliar plazos. Añadir scopes
solo de download y activación para discriminar la recepción pendiente.

WAL RED `/tmp/pmw2d-wal-red.log` rc101: falta WAL inmediatamente después del
primer put real. GREEN `/tmp/pmw2d-wal-green-check.log` rc0: WAL/commit durables,
reapertura después de parar el servidor, 32 E2EE y check/Clippy completos.
Una conexión de servidor se mantiene abierta sin transacción lectora;
`Connection::close` se comprueba explícitamente al finalizar el canal. No se
cambia `synchronous`, autocheckpoint ni commit por put. El efecto funcional
está confirmado; la reducción de coste nativo queda por medir, no se atribuye
una mejora Linux significativa al keeper (control focalizado 3.309/4.208 s).

Primer barrido del fix de sesión en `0bd0721`: `/tmp/pmw2d-gate-results.json`,
40 casos/38 rc0/0 regresiones; check 56.925 s y clean 41.115 s. Los rc1
siguen en TUI operaciones y matriz G7, misma razón que el baseline. Tras el
nuevo cambio productivo SQLite se exige otro barrido completo, logs
`/tmp/pmw2d-wal-gate-*.log`, resultados `...-results.json`, sin sobrescribir
ninguna evidencia previa. Próxima corrida: diagnóstico 2 con hipótesis distinta
(checkpoint por último close y scopes de recepción/activación); quedan luego
hasta una verificación adicional dentro de las cuatro autorizadas.

Fallbacks heredados adicionales observados y conservados: `serve_one` convierte
error de parser/dispatch a `{"ok":false}` genérico; `sync_job::record_journal_failure`
ignora el error secundario de persistencia de su estado de emergencia mientras
expone JournalFailure en memoria. No son la causa medida y no se modifican.

### Diagnóstico 2: happy Intel completo dentro del plazo

[37132696664](https://github.com/SantanaJcp/passwordmanager/actions/runs/37132696664),
SHA `1b1df0663bd1d786bcb9b72575a6a9e154fd4086`, completed/failure.
32 E2EE pasan en cada CPU. Intel happy `succeeded`, 287 bloques/1 root,
job 15.725 s y observación TUI 18.328 s, dentro del plazo original de 20 s.
PIDs de custodio/servidor iguales, un proceso/un handshake, 59 eventos/1 página:

| Fase Intel | Cantidad | Tiempo acumulado |
| --- | --- | --- |
| Preparación job / spawn de hilo | 1 / 1 | 2.773 / 0.116 ms |
| Preparación push | 1 | 66.866 ms |
| Exportación de grafos | 59 | 4.518 s |
| RPC put | 287 | 7.247 s |
| Publish | 1 | 0.949 ms |
| Ack local | 1 | 179.034 ms |
| Push completo | 1 | 12.971 s |
| RPC get | 287 | 1.049 s |
| Descarga de grafos | 29 | 2.286 s |
| Fsync de archivos descargados | 36 | 209.662 ms |
| Activación atómica de grupo | 1 | 278.691 ms |
| Pull completo | 1 | 2.633 s |
| Handshake TLS / spawn cliente | 1 / 1 | 36.139 / 0.952 ms |
| Cierre cliente / journal fsync | 1 / 4 | 15.273 / 106.470 ms |
| SQLite dispatch / apertura servidor | 576 / 1 | 6.666 s / 1.841 ms |

Scopes anidados: no sumar export/RPC, download/get/fsync y sus fases totales.
Sin temporal por put ni backoff. El workflow después falla en la aserción
visual intacta `pushed=/pulled=`: el estado durable es exitoso; no se relaja
ni se toca la TUI W1. ARM vuelve a fallar antes del job (password-prompt).
Control 39 eventos: ARM publish/convergencia 5.255/6.910 s; Intel
16.141/20.102 s. La variabilidad Intel es visible frente a la corrida previa;
**no se atribuye una reducción nativa aislada al keeper**. Su RED/GREEN prueba
el checkpoint por último close y durabilidad, mientras la corrección conjunta
acredita la conclusión acotada del happy Intel.

Segundo barrido sobre `1b1df06`: `/tmp/pmw2d-wal-gate-results.json`,
40/38 rc0/0 regresiones; check 60.001 s, clean 46.275 s. Mismos dos fallos
heredados, sin nuevos skips/retries/deadlines. Producto permanece intacto en
la última verificación: únicamente se devuelve el fixture al plist normal y
el opt-in `PMW2_TIMING=1` pasa a ser explícito. Hipótesis final: discriminar
instrumentación de los fallos ARM pre-sync. No se cambia ninguna aserción;
se emiten también los contadores del registro durable válido, sin su ID.

### Verificación 2 final: plist normal, Intel confirmado y ARM bloqueado antes de sync

[37133730351](https://github.com/SantanaJcp/passwordmanager/actions/runs/37133730351),
SHA `4282843c3cc9acb4fdda893d23f56b68f5e4b893`, completed/failure en ambas CPU.
Labels estándar `macos-15` y `macos-15-intel`; repo público, flags false/false,
sin secrets, caches ni artifacts. Los 32 E2EE pasan por CPU. `PMW2_TIMING`
está ausente: plist original y sin redirección de timing del custodio. El
producto es idéntico al SHA `1b1df06` del segundo barrido Linux; este checkpoint
solo cambia fixtures/documentación. No se consume otra corrida.

Intel alcanza el happy sync exacto en **18.054 s** observados por la TUI:
`durable=succeeded screen=succeeded`, `pushed=59 pulled=59`, 287 bloques y
1 root. Custodio y servidor mantienen sus PIDs. Después falla la misma
aserción visual intacta de `macos_tui_migration_lab.py:585`, que exige
`pushed=/pulled=` en la pantalla capturada. El diagnóstico lee únicamente
contadores del registro PMSS1 validado y no sustituye esa aserción. Hay dos
éxitos acotados del motor/job Intel, con y sin perfilado; el workflow no pasa.

ARM llega a `full25-local=observed` y falla en
`macos_tui_migration_lab.py:558`, `expect_output_collision(..., "backup", ...)`:
`result=unclassified destination=same`. La espera de error visual vence antes
del happy sync. Ese job es **NOT_RUN**, no un timeout de transporte W2. La
colisión y su fixture son de W1; no se cambian. Quitar la instrumentación
permite avanzar más que los anteriores fallos password-prompt, pero las
corridas no aíslan causalmente esos fallos: no atribuirlos al timing ni
declararlos corregidos. Logs `/tmp/pmw2d-macos-verification2-{arm,intel}.log`;
metadata final `/tmp/pmw2d-macos-verification2.json` confirma ambos completed.

### Comparación final y límites de la evidencia

Control E2EE real, mismo escenario de 39 eventos en una página, 271 puts y
272 gets. Tiempos desde el inicio del push, no latencia exclusiva de publish:

| CPU | Fase 3: raíz publicada / convergencia | Verificación 2: raíz publicada / convergencia |
| --- | --- | --- |
| ARM | 15.342 / 27.716 s | 4.851 / 6.965 s |
| Intel | 22.124 / 36.387 s | 10.226 / 12.817 s |

El control no sustituye el happy TUI, cuyo workload tiene 59 eventos y 287
bloques. Para Intel, antes: cutoff 20 s, 0 roots y pushing; después: motor
15.725 s y TUI 18.328 s perfilados, TUI 18.054 s con plist normal. Los scopes
de push/pull/fsync/SQLite constan en la tabla de diagnóstico 2. Para ARM no
hay desglose del job TUI exacto, antes ni después: las cuatro corridas de fase
4 se detienen antes de él. No se extrapolan las latencias Intel al ARM.

Latencias por RPC Intel (muestra parcial inicial de 115 puts, frente al job
final completo de 287 puts, 287 gets, publish y list; scopes anidados):

| Medición | Antes: media / máximo | Después: media / máximo |
| --- | --- | --- |
| Temporal+fsync por put | 72.831 / 113.097 ms | 0 temporales auxiliares |
| RPC put, sin el temporal previo | 77.774 / 277.604 ms | 25.251 / 119.656 ms |
| RPC get | No alcanzado | 3.656 / 15.439 ms |
| Publish / list | No alcanzado | 0.949 / 0.845 ms, un RPC cada uno |
| TLS exchange | 24.736 / 173.517 ms | 13.135 / 112.355 ms |
| SQLite dispatch | 21.057 / 158.215 ms | 11.572 / 106.381 ms |

Antes hubo 115 procesos/handshakes en la muestra, después 1 para 576 RPCs.
El handshake pasó de 0.166 s acumulados parciales a 0.036 s por sesión; no
era el coste dominante. El RED de WAL confirma el checkpoint por cierre de
última conexión, pero no hay una medición nativa aislada de su mejora.
Los commits permanecen FULL y por put; sin eliminación de fsync durable.
No se registró backoff en los happy jobs medidos. No hubo cambio de PID al
final del job; no se acredita ausencia de todos los eventos internos de
launchd. La diferencia entre observación TUI y motor perfilado (2.603 s)
incluye interacción/consulta y no se atribuye a launchd. Las esperas de
arranque de servicios del fixture preceden al job y no forman parte de
estos scopes. El protocolo, deadlines y límites permanecen intactos.

| Corrida de fase 4 | SHA exacto | Resultado acotado |
| --- | --- | --- |
| [Diagnóstico 1](https://github.com/SantanaJcp/passwordmanager/actions/runs/37129675339) | `d6acdb63d3333a167d5965b4e17f5924b3069d9b` | Intel 0 roots/cutoff; ARM pre-sync |
| [Verificación 1](https://github.com/SantanaJcp/passwordmanager/actions/runs/37131160116) | `0bd0721d4d5610c184e9fde26edd77f64651c1c7` | Intel 1 root/pull pendiente; ARM pre-sync |
| [Diagnóstico 2](https://github.com/SantanaJcp/passwordmanager/actions/runs/37132696664) | `1b1df0663bd1d786bcb9b72575a6a9e154fd4086` | Intel happy succeeded; ARM pre-sync |
| [Verificación 2](https://github.com/SantanaJcp/passwordmanager/actions/runs/37133730351) | `4282843c3cc9acb4fdda893d23f56b68f5e4b893` | Intel 59 pushed/pulled; ARM colisión backup previa |

Todas completed/failure; dos diagnósticos y dos verificaciones, sin repeats
idénticos. Ninguna acredita Full25 completo ni aceptación global. Gates
finales: check y clean offline PASS, barrido 40 casos/38 rc0/0 regresiones
frente a `/tmp/pmw2c-gate-results.json`. Se conservan los rc1 de
`lab-tui-operations` (truncación exact-duplicates a 80 columnas) y `g7-matrix`
(staging retenido en commit-outbox-audit EIO/ENOSPC). Sin nuevos skips,
reintentos, aserciones o plazos. Todo cargo/check/lab local se ejecutó con
`flock /tmp/pm-cargo-window.lock`; ningún lock retenido esperando CI.

### Archivos de fase 4 y entrega al orquestador

Nueve paths desde `8c17220`: `crates/pm-sync/src/{lib.rs,main.rs,session.rs,timing.rs}`,
`crates/pm-sync/tests/e2ee_replication/purge_sync.rs`,
`crates/pm-custody/src/sync_job.rs`,
`crates/pm-custody/tests/{macos_lab.py,macos_tui_migration_lab.py}` y este informe.
El transporte de sesión está seleccionado explícitamente en Unix y no se
prueba Windows nativo aquí. Listener/admisión/proveedor y TUI no se modifican.
Instrumentación de staging se limita a tiempos; sus fallbacks conservados
no son la causa medida y no se alteran. No se integra ni se cambian tickets.

W1 comparte ambos fixtures Mac: preservar sus hunks de backup y los nuestros
de sync/opt-in/counters al componer; el footer/aserción visual también queda
en su frontera. Inspección de refs publicados W3 `e0eec49` y W4 `549c512`:
sin paths productivos compartidos nuevos de fase 4. Los conflictos posibles
de `backup.rs`/`reducer.rs` de fases anteriores con W3 siguen requiriendo
composición del orquestador. Esta revisión no equivale a un merge probado.

**Siguiente acción:** el orquestador compone la corrección W1 de colisión
ARM/presentación con los checkpoints W2 y verifica el happy TUI en ambas CPU.
Las cuatro corridas W2 autorizadas se agotaron: una nueva aceptación nativa
requiere autorización adicional y un cambio verificable, no repetir este SHA.
W2 entrega la corrección y su evidencia; permanece abierto por ese gate.

## Fase 5 — método autorizado y discriminantes

Base `1d270ad`, fast-forward y push ordinario de W2 desde la integración 4.
El wire G5 §9.5 permite un bloque por put; G4 prohíbe batches. No se añade
batch ni se aumenta ningún límite. La optimización propuesta comparte la
verificación completa del DAG y de purgas durante la exportación de una
página, en una única snapshot SQLite de lectura, cerrada antes del transporte.
Conserva fsync de cada fichero, digest de cada grafo, límites y commit/ack.
RED Linux: cuatro revisiones reales, cuatro exportaciones en una página,
contador por hilo de verificaciones completas del ledger: exigir una, observar
cuatro antes del fix. GREEN exige una y los mismos grafos, más rechazo de
corrupción/firma/payload y todas las negativas de purga/recepción existentes.
Control TLS restaurado de 39 eventos: medir puts/gets y tiempo hasta root y
convergencia, sin variar sus oráculos. Registrar fsync por escenario mediante
interposición local categórica, sin rutas, descriptores ni bytes.

Unlock Mac: medir prompt y envío→Unlocked sin alterar wait8s. Ante FAIL,
muestrear después del gate los procesos propios TUI/custodio; emitir sólo
presencia de KDF, unlock, protección, fsync, SQLite y lecturas. La muestra
posterior no sustituye tiempos ni demuestra que una fase acabó dentro del
plazo. Hasta cinco runs exactos, nunca idénticos sin cambio/hipótesis nueva;
Full25 normal y final/cleanup obligatorios en ambas CPU, plazos originales.
Barrido local: los 52 casos de `/tmp/pmint6-gates-local-results.json`,
49 rc0 y tres RED conocidos; W4 concurrency fuera de gates. Todo cargo/lab
bajo `flock /tmp/pm-cargo-window.lock`; logs `/tmp/pmw2e-*`.

Fallback heredado adicional conservado: `sync_stage` en pm-sync/src/lib.rs,
cuando ya existe su ruta calculada, elimina ese staging y lo recrea en lugar
de rechazar la colisión. No se cambia ni se usa como optimización.

Diagnóstico W2 nativo 1: el script de laboratorio habilita las fronteras
`macos-ticket26-diagnostics` ya existentes para Full25 normal; no ejecuta el
modo `--diagnostic` ni omite ninguna matriz. `PM_MACOS_TICKET26_DIAGNOSTIC`
se inyecta exclusivamente en el daemon propio; su stderr va al log W2, no
al log del modo diagnóstico. Antes de cada TUI se toma offset y al acabar
su wait8 se filtran exclusivamente categorías/tiempos de unlock admitidos.
El código productivo de unlock/KDF es idéntico; no hay otra autenticación.
La siguiente verificación retirará esta instrumentación para discriminar su
impacto y confirmar el plist normal. No se cambia el workflow ni sus inputs.

RED `/tmp/pmw2e-export-red.log`: rc101, grafos4/verificaciones4 frente a1.
GREEN `/tmp/pmw2e-export-green-check.log`: rc0, grafos4/verificaciones1 y
check completo. Control TLS bajo interposición: antes publicación3.462s /
convergencia4.341s; después2.914 /3.785s. Puts271/gets272 en ambos;
fsync426/fdatasync0 en el proceso de prueba en ambos, incluye setup y
recepción, no es total del servidor remoto. Los fsync no se eliminan.

Corridas consumidas hasta el diagnóstico nativo:

- [37175688148](https://github.com/SantanaJcp/passwordmanager/actions/runs/37175688148),
  `7f4709687ff85f36c7a8e7937781472f493fa89c`: **completed/cancelled**,
  ambos jobs cancelados. Se publicó por error antes de inspeccionar el último
  preflight: la negativa nueva usó `slice::repeat` sobre un tipo Clone que no
  es Copy. No es RED de comportamiento ni aceptación; consume un dispatch.
- [37175725951](https://github.com/SantanaJcp/passwordmanager/actions/runs/37175725951),
  `aac3d4429ea68c4758d23d97aee0bcb66baa9376`: diagnóstico 1, pendiente de
  completar. Construcción de página negativa corregida, preflight focalizado
  rc0 (`/tmp/pmw2e-native-profile-preflight3.log`).

El primer check del barrido rc101 por Clippy `too_many_lines` en el test
ampliado, después de pasar tests; clean offline rc0. No se presenta como gate
PASS. La fuente permanece congelada durante los 52 casos; después se extraerá
un helper de negativas sin relajar el lint ni las aserciones y se repetirá
check. Logs originales conservados, ningún ticket cambia estado.

Diagnóstico 1 ARM (job111357812404) terminado **failure**: nueve unlocks
observados con wait1.084–5.772s; KDF0.820–5.415s. En la entrada Full25:
wait4.927s, KDF4.707s, servidor unlock4.747s, SQLite/config≤1ms.
Ningún unlock alcanza8s ni muestra error de protección; no se ejecutó sample
porque el gate no falló. Esto no prueba la causa del fallo histórico ARM ni
excluye congestión anterior al handler. La variabilidad de KDF es real pero
atribuirle el timeout histórico sigue siendo **inferencia, no causa probada**.

Backup feliz ARM6.883s; después FAIL en el wait8s original de restore,
`before-ui=unclassified after-ui=unclassified delta-items=0 authority=same`.
Full25/sync/final no terminan; sync **NOT_RUN**. Control TLS39 eventos:
publicación4.660s/convergencia6.323s, puts271/gets272. No sustituye la TUI.
La segunda hipótesis nativa retirará el perfil de unlock/feature diagnóstico,
conservando solamente scopes sync y tiempos de observación del fixture.

### Diagnóstico 1 Intel y siguiente RED permitido

Diagnóstico1 terminado: Intel PASS completo, ARM FAIL restore; workflow FAIL.
Intel happy wait15.363s/submit1.701s/total17.064s; margen4.637s (23.2%).
Exportación1/0.888212s frente a59/4.518s en fase4; push10.724549s,
pull4.191001s, job15.048742s. Put287/8.270936s, get287/1.490303s;
server dispatch576/7.630256s; download fsync36/0.586470s,
joined fsync5/0.425102s, status fsync4/0.128198s. Sin backoff;
PIDs estables y pushed59/pulled59. Scopes anidados, no sumar con fases.
KDF Intel0.605–5.504s; ninguno de los15 unlocks vence8s.

Método siguiente: TLS/RPK real, secuencia16 puts+16 gets+publish+list,
32 respuestas de bloques y root durables comprobadas por conexión RO antes
cerrar TLS. Contar aperturas SQLite del dispatch; RED34 frente a1.
GREEN reutiliza sólo la conexión propia de cada TLS, sin transacción retenida
ni agrupar commits; ACL/hash/límites por RPC, FULL/WAL/autocheckpoint y cierre
comprobado intactos. El camino Windows no cambia. Repetir los52 casos tras
el nuevo cambio productivo, logs `/tmp/pmw2e-session-*`.

SQLite RED `/tmp/pmw2e-sqlite-red.log` rc101: secuencia real intacta,
34 aperturas frente a1. GREEN `/tmp/pmw2e-sqlite-green-check.log`:
34 RPCs durables/una apertura, control TLS2.851s publicación/3.729s
convergencia; puts271/gets272 y fsync426 del proceso de prueba conservados.
El check de ese bloque tuvo dos `needless_borrow` tras extraer las negativas;
no es gate PASS. Se corrigen sin allow y se conserva ese log rojo.

Se reutiliza la conexión SQLite propia del TLS Unix en el dispatch, sin
transacción entre RPCs, autorización cacheada ni cambios de synchronous,
checkpoint o commit. `OpaqueSyncStore` conserva el modo explícito de conexión
por llamada para sus consumidores, incluido Windows; un error al abrir la
sesión Unix falla, no elige ese modo como alternativa. El cierre de la sesión
se comprueba antes de devolver el handler. Se retira el build/inyección del
perfil de unlock; quedan los scopes sync y observaciones del fixture.

Fallback heredado adicional inspeccionado y conservado: `optional_field`
(pm-sync/src/main.rs) devuelve None para valor con escape/newline/CR. En el
cursor opcional de list eso se trata como parámetro ausente y comienza en0,
concebiblemente ocultando un cursor suministrado inválido. Es inferencia de
código; no se modifica el parser ni se usa para validar esta corrección.

Check final del segundo cambio `/tmp/pmw2e-sqlite-check3.log` rc0, suite y
Clippy completos. El log check2 rc101 conserva el cast de longitud de log
señalado por Clippy; se sustituyó por conversión comprobada. Sin lints
suprimidos para los errores observados. Primer barrido52:48 rc0/tres RED conocidos/un FAIL Clippy del
nuevo test; escenarios funcionales y negativos esperados conservados.
El segundo barrido completo corresponde al nuevo servidor persistente.

### Verificación 1: servidor persistente, ARM PASS / Intel restore FAIL

[37176973454](https://github.com/SantanaJcp/passwordmanager/actions/runs/37176973454),
`d199ada5ce33002742c878052f1d58702aa22f45`, completed/failure.
ARM PASS completo: happy wait7.390s, envío0.869s, total8.259s;
margen12.610s/**63.1%**. Job7.064155s, push5.283153s/pull1.698172s;
exportación1/0.245667s; put287/4.385954s, get287/0.622633s;
dispatch576/3.940343s, apertura real SQLite1; fsync download36/0.045292s,
joined5/0.105334s y status4/0.045680s. PIDs estables, pushed59/pulled59,
root1 y bloques287, fase final y cleanup completos. Backup0.912s frente a
6.883s anterior; **backup no cambió**, no atribuir esa variación al fix.

Intel FAIL restore8s antes de sync; unlocks1.090–6.195s observados y backup
2.667s. Snapshot después del wait mantiene diagnóstico de restore sin
aceptación; sync/final NOT_RUN. Control39: ARM publicación5.895s /
convergencia7.962s; Intel publicación17.993s/convergencia22.354s. La variabilidad está presente.

Segundo barrido `/tmp/pmw2e-session-gates-results.json`:52 casos,49 rc0,
tres RED conocidos (g7-matrix/g7-extra-bootstrap/g7-extra-vault), cero
regresiones. W4 concurrency se ejecutó sólo como observación. Check22.609s,
clean47.626s, tiempos wall que pueden incluir espera del flock. Wayland real
wayland-1 desde el inicio; ninguna repetición por entorno. Fuente congelada.

Siguiente diagnóstico autorizado: sample nativo1s en TUI/custodio propios
**después** de un fallo restore8s, sólo booleanos KDF/restore/backup/SQLite/
protección/lectura/fsync. Conservar el FAIL original y su snapshot; no usar
respuesta tardía como PASS. Se eliminan las hooks temporales de KDF ya
retiradas del build; scopes sync siguen activos para medir Intel si alcanza
happy. La corrida final retirará también scopes/plist y confirmará el perfil
normal. Sin producto nuevo tras el barrido52.
