# Integración local exacta — 2026-10-14

**Resultado: ISSUES.** Medido: kitchen rc0, check completo rc0, clean/offline rc0;
barrida histórica **42/52 rc0, 10 rc1**. Diecisiete comprobaciones focalizadas
nuevas pasan; G7 conserva fallos. No aceptación de producto, master/PR, nativos,
tickets o revisión formal Astra35. Principios: `prove`, `truthful-state`,
`isolate`, `root-cause`, `evidence`, `small-owned`, `no-fallbacks`, `handoff`.

## Binding y procedencia

Workspace propio: `/home/santana/.t3/worktrees/passwordmanager/t3-0eed2d3d`.
Rama de método/informe: `t3/chef-integration-tests`; HEAD inicial exacto
`31b48ace181512d273738ff3b344201be8e8f08b`.
Fuente read-only: `/home/santana/Documents/ChatGPT/passwordmanager/.worktrees/chef-finish-20261014`.
Medido: `d4b1be662a1b8766eff54c2b8269ef4c94770c54` es ancestro de la base;
diff de crates/scripts/manifests/lock/workflows/toolchain entre ambos vacío.
La base posterior aporta el ledger, sin otra versión de código.

Compuesto producido por kitchen: **`8cd45529b062506a2cbe0c567538d3999ac8a2b6`**.
Está retenido en el clon propio `.scratch/chef-integration-20261014/run1/clone`,
ref local `chef/exact-integration-20261014`; no se fusionó en esta rama de método.
Vector, en orden:

1. daemon: `894aa3600610e23a1834d831668bf66dc2bb7112`
2. crypto + SID: `a900a69f0a57e4ff09baa458dae69f278d29b250`
3. SSH: `15bfaa248cf4950f5c8a3bf99dccc869791f3227`
4. CLI humano: `4c3a90c8e3c5ceac229060e66f551012e88c46dd`
5. Windows diagnóstico: `6a2a81fa76023c28e6b7e4a6d8282820c4e09fdc`
6. macOS diagnóstico: `837f5564b14f5b6f8a058b21304dfbd5d7ef1fb7`
7. sync probe: `5e26f3b4d4813c4e606339353e67e82ede4dcdf5`
8. G7 probe: `0eff9d93b97abefd8048d16236cf674601af0a41`
9. guía: `9de9aa99347cc2b3300190601ba00c568f22aa86`

Medido: nueve merges sin conflictos; todos los siblings son ancestros del compuesto.
`2801c4893b1a1e1870479eb692b120929518c8a4` y
`e18cf389c91623072d7e8584860e9ca85a6f5356` no son ancestros (rc1).
6728 está únicamente dentro del rango corregido `ecc2e9d..894aa360`; nunca se
integró aislado. No commits extra, archivos nativos uncommitted ni nueva guía.
[Ancestry receipt](../../.scratch/chef-integration-20261014/run1/ancestry.json).

Inferido de los triages fijados: D1/D2 Claude R2 source PASS en 894;
crypto/SSH R1 y CLI/SID R1 sin P0/P1. Son revisiones de fuente, no tests ejecutados
por revisores, aceptación nativa o revisión35. Se leyeron AGENTS, CONTEXT,
decisions, spec11/15, reglas issue/domain, límites native-ci, ledger/tasks/results,
triages y los informes de cada candidato mediante objetos Git. Rol de este
encargo: integrador/ejecutor único, sin revisión independiente ni delegación.

## Método ejecutado y retención

[Entrypoint propio](../../scripts/chef-integration-20261014.sh), helpers y
[vector histórico recuperado](../../scripts/chef-integration-20261014/historical-cases.json).
Repetición local con una ruta NUEVA propia:

```sh
bash scripts/chef-integration-20261014.sh /tmp/pm-chef-new-owned-run
python3 scripts/chef-integration-20261014/sweep.py /tmp/pm-chef-new-owned-run
python3 scripts/chef-integration-20261014/affected.py /tmp/pm-chef-new-owned-run
python3 scripts/chef-integration-20261014/memory_red.py /tmp/pm-chef-new-owned-run
```

Los dos primeros comandos de verificación de la barrida son los mismos runs
check/clean contabilizados, nunca un segundo check completo. `stage.py` ejecutó
`git diff --check` después de cada merge y `scripts/check.sh` UNA VEZ al noveno.
Por eso kitchen PASS acredita ese subconjunto explícito; no incluye G7/52/UI.
No `--recorded`, configuración global, cambio de modelos/base o gate desactivado.

Kitchen execution digest: `457bd3fd26cba5d05107d398912df5765bf70ef1c11e0ff7b4c3ad83339e32d2`.
Check-command SHA256: `faef251face53ecd6b49452c1410b5b6300360a76ae4bb11a3b1690d3ae86d0c`.
Check-script SHA256: `3247187d0d828c16015f8a4bf94037581cc4da5851a3934e2e1fcf6653f8c6d6`.
Los hashes de stage/integrate son idénticos antes/después del run.
[Request/command/vector](../../.scratch/chef-integration-20261014/run1/request.json),
[kitchen receipt](../../.scratch/chef-integration-20261014/run1/kitchen-record.json),
[check receipt](../../.scratch/chef-integration-20261014/run1/combined-check.json).

Inspección de kitchen: `lib/kitchen/integrate.py` hace `shutil.rmtree(workdir,
ignore_errors=True)` en finally. El primer check trasladó el clon kitchen-owned
fuera de ese workdir y dejó un symlink, que rmtree no siguió. Logs originales
kitchen y copia privada conservados; clon/targets/evidencia no se borraron.

Cada Cargo/build/lab usa **blocking flock `/tmp/pm-cargo-window.lock`**;
helpers inspeccionados sin adquisición anidada. Toolchain único inmutable
`/home/santana/Documents/ChatGPT/passwordmanager/.toolchain`, symlink explícito
propio en el clon, homes rustup/cargo de esa raíz, PATH cargo/bin,
`RUSTUP_AUTO_INSTALL=0`, locked/offline. No instalación ni descarga.
`CARGO_TARGET_DIR` siempre coincide con el target/debug propio que ejecutan los
wrappers. Clean empezó con target NUEVO vacío; el target del check se retuvo
como target-check. Nunca se usó binario o target de un sibling.

Incidente medido: `/tmp` agotó cuota tras clean rc0; cinco builds rc101 y la
escritura del resultado siguiente fallaron con os122. Es infraestructura, no
RED del producto. Se conservaron logs/JSON truncado y se trasladó únicamente
la raíz propia al disco del workspace, con symlink en la ruta /tmp original.
La barrida retomó los labs con logs `*-resumed`, reutilizando los dos runs
check/clean ya medidos; no retry de login ni cambio de deadline.
[Recibo del incidente](../../.scratch/chef-integration-20261014/run1/quota-interruption.json).

## Barrida histórica completa

Recuperación acotada de stdout del runner en JSONL suministrado, línea40,
rollout `01a1060f-6f38-7d82-b1e9-d211c5905672`; sólo el runner quedó archivado.
La lista mantiene 26 wrappers ordenados, tres modos publicación, todos los
G7/inflight/canaries/trace, concurrencia, purge y restore. El runner histórico
excluía concurrencia de su exit agregado; aquí se cuenta como fallo. Expected1
histórico conserva procedencia, **no convierte un RED en PASS ni exit0**.

[52 resultados: comandos, digests, rc y logs](../../.scratch/chef-integration-20261014/run1/52-resumed-results.json),
[resumen](../../.scratch/chef-integration-20261014/run1/52-summary.json),
[manifiesto íntegro de fuentes](../../.scratch/chef-integration-20261014/run1/source-manifest.json).
Todos los casos, sin omisiones:

| # | Caso | rc | expected histórico |
| --- | --- | --- | --- |
| 1 | final-check | 0 | 0 |
| 2 | final-clean | 0 | 0 |
| 3 | lab-1pux-import | 0 | 0 |
| 4 | lab-adapter-protected-frame | 0 | 0 |
| 5 | lab-attempts | 0 | 0 |
| 6 | lab-authorization | 1 | 0 |
| 7 | lab-backup | 0 | 0 |
| 8 | lab-cleanup-fault | 0 | 0 |
| 9 | lab-content | 1 | 0 |
| 10 | lab-csv-import | 0 | 0 |
| 11 | lab-custody | 0 | 0 |
| 12 | lab-custody-protected-input | 0 | 0 |
| 13 | lab-fault-safety | 0 | 0 |
| 14 | lab-github-bearer | 0 | 0 |
| 15 | lab-history | 0 | 0 |
| 16 | lab-human-transaction | 1 | 0 |
| 17 | lab-passkey | 1 | 0 |
| 18 | lab-passkey-login | 1 | 0 |
| 19 | lab-recovery | 0 | 0 |
| 20 | lab-rpc-cleanup-fault | 0 | 0 |
| 21 | lab-ssh | 0 | 0 |
| 22 | lab-storage-fault | 0 | 0 |
| 23 | lab-sync | 0 | 0 |
| 24 | lab-token-exchange | 1 | 0 |
| 25 | lab-tui-access | 0 | 0 |
| 26 | lab-tui-content | 0 | 0 |
| 27 | lab-tui-operations | 0 | 0 |
| 28 | lab-web-auth | 0 | 0 |
| 29 | publication-backup | 0 | 0 |
| 30 | publication-plaintext | 0 | 0 |
| 31 | publication-attachment | 0 | 0 |
| 32 | custody-audit | 0 | 0 |
| 33 | sqlite-sync | 0 | 0 |
| 34 | bootstrap-completed | 0 | 0 |
| 35 | g7-matrix | 1 | 1 |
| 36 | g7-inflight-result-sync | 0 | 0 |
| 37 | g7-inflight-bootstrap | 0 | 0 |
| 38 | g7-inflight-audit | 0 | 0 |
| 39 | g7-inflight-crash | 0 | 0 |
| 40 | g7-canaries | 0 | 0 |
| 41 | g7-extra-vault-completed | 0 | 0 |
| 42 | g7-extra-inflight-vault | 0 | 0 |
| 43 | g7-extra-inflight-live-bootstrap | 0 | 0 |
| 44 | g7-extra-inflight-live-audit | 0 | 0 |
| 45 | g7-extra-inflight-live-vault | 0 | 0 |
| 46 | g7-extra-matrix-trace | 0 | 0 |
| 47 | g7-extra-bootstrap | 1 | 1 |
| 48 | g7-extra-vault | 1 | 1 |
| 49 | concurrency | 1 | 0 |
| 50 | purge-probe | 0 | 0 |
| 51 | purge-sync-tests | 0 | 0 |
| 52 | restore-digest-tests | 0 | 0 |

Fuentes medidas idénticas al finalizar también los probes adicionales.
SSH/web, backup/importación/recovery, TUI access/content/operations, sync,
publicación y controles de fallos que tienen rc0 no certifican seis targets.
Los cleanups heredados con ignore_errors tampoco ganan prueba independiente
por rc0; ese límite permanece visible en los informes candidatos.

## Fallos adicionales y migraciones de callers

Medido: siete casos antes expected0 ahora rc1. Inferido: las fixtures ordinarias
anteriores no provisionan el registro 1A; el handler de `linux.rs:4217` cierra
agente sin registro, sin fallback de pin único. No se editaron esos callers.

| Caller exacto | Primer fallo medido | Delta mínima que corresponde a su owner |
| --- | --- | --- |
| `crates/pm-custody/tests/authorization_lab.py:104` | A discovery rc4 CUSTODY_UNAVAILABLE | Después de setup, migración explícita con pares A/B; reinicio sobre snapshot instalado/chroot propio; mantener rotación/revocation assertions. |
| `crates/pm-custody/tests/linux_lab.py:273` (content/human-transaction) | probe agente rc4 | Autoridad humana antes del probe delegado, registro explícito y reinicio en raíz confiable. Mantener controles de identidad y CRUD. |
| `crates/pm-custody/tests/passkey_lab.py:238` | Native Messaging NOT_ALLOWED en vez de waiting | Registrar bridge-RPK/UID y segundo agente tras setup/restart; no habilitar cualquier UID ni cambiar waiting. |
| `crates/pm-web-auth/tests/passkey_login_lab.py:302` | no request ID en dataset | Setup en :280 todavía sin registro; mismo bridge binding explícito. La causalidad completa de ese timeout no está medida por una repetición de este caller. |
| `crates/pm-web-auth/tests/token_exchange_lab.py:492` | ordinary cancel-start no rc0 | Cambio a serve-vault en :487 necesita 1A y configuración 2A del adaptador real; no instalar controlled.external ni sustituir provider. |
| `crates/pm-custody/tests/concurrency_lab.py:96` | discovery rc4 | Registro A/B después de :95 y raíz propia; preservar cuotas. |
| `crates/pm-custody/tests/tui_access_lab.py:161` | cleanup tmux rechazó missing-socket stderr | Concurrencia falló antes de crear tmux. Su owner debe separar precreación de cierre verificado; no silenciar cleanup. |

El wrapper propio `owned_root.py` demuestra una migración concreta del caller
CLI nuevo sin cambiar sus acceptance assertions: detener tras autorización,
`migrate-agent-registry` explícito para segundo RPK/UID3, reiniciar y ejecutar
el mismo recorrido. Custodio/provisión en UID0 chroot, binarios frescos copiados
+ libs públicas; clientes/PTY real fuera, sin mounts del host o mknod sustituto.
No alias UID=agente ni owner aprendido desde `/`.

Guía fijada también requiere delta posterior de su owner:
`docs/user/evaluacion-linux.md:51` aún dice que pm tui no existe y devuelve
UNAUTHORIZED. Medido ahora el comando humano público funciona; cambiar sólo
esa afirmación/ejemplo por el recorrido probado. No se incorporó ninguna guía
nueva ni se editó README/docs-user en este encargo.

## Flujos focalizados sobre el compuesto

[Comandos/env/digests/rc](../../.scratch/chef-integration-20261014/run1/affected-results.json).
Medido: primeros17 rc0: memoria3, wire SSH2, G7-prepared/W7/lifecycle34,
CLI/MCP, build ejemplo, registry, adapter, admission y ocho reconciliaciones,
más TUI pública (algunos son agrupaciones de tests).

Registry: A+B mismo daemon y TUI abierta; UID/RPK cruzados/unknown y root agente
rechazados; grants vigentes, hot revoke en canal persistente, migración,
corrupción/replacement/owner/modos. Admission: UID separados y compartido,
A4+B4, quinta de cada RPK denegada, quinta A sin magic cerrada antes de leer
aplicación, release/disconnect/revoke y stop/restart sin permisos obsoletos.
Reconciliación: socket, config-remove/config-replace, registry-remove,
bootstrap-mode/audit-mode, indeterminate-socket y ssh-socket: no terminal falso,
un solo login, reanudación/restart y ownership/cancel conservados.
Adaptador real pm-web-auth contra TLS sintético, no GitHub/SSH externo real.
Inferido: RPKs con UID compartido conservan presupuesto nativo compartido antes
de TLS; estas pruebas no acreditan aislamiento OS entre procesos de ese UID.

TUI pública: prompt/enmascarado, unlock nativo, search, organization commit,
lock/exit0 y comparación termios/restauración pantalla/cursor. Agente con PTY,
UID/key cruzados, RPK/peer/pin incorrectos, recursos ausentes y --json no abren
sesión humana. CLI JSON antes/después intacto; MCP humanos negados por tests.
[Captura de UI real y ledger](../../.scratch/chef-integration-20261014/run1/human-ui/resources.json)
y [pantallas](../../.scratch/chef-integration-20261014/run1/human-ui/human-screens.txt).

Memoria: los MISMOS tests independientes copiados como helpers nuevos a un
worktree baseline propio exacto d4b1be66 producen **3 fallos conductuales, rc101**:
Ok(signature)/Ok(grant) con RLIMIT_MEMLOCK0 frente a ResourceUnavailable.
El compuesto da **3/3 rc0**, incluidos RFC8032/grant positivos y negativas de
lock. No se editaron fuentes productivas del baseline ni del compuesto.
[RED](../../.scratch/chef-integration-20261014/run1/memory-baseline-red.json),
[GREEN](../../.scratch/chef-integration-20261014/run1/focused-memory.log).

## G7 sigue bloqueado: evidencia y límites

Tres comandos originales rc1: matrix, bootstrap y vault. Matrix original y
probe counts adicional conservan la aserción `g7_fault_matrix.py:155`.
Medido en la observación: índice3/control=staging con1/1/17, muestra actual=wal
con0/0/0; falla antes de una frontera comparable. No es reproducción del
antiguo commit-fsync8 ni un GREEN. [Conteos](../../.scratch/chef-integration-20261014/run1/g7-matrix-counts.log).
Inferido: deriva de ordinal físico entre bóvedas nuevas; el oráculo de selección
requiere una correspondencia lógica más fuerte, sin retirar casos ni assertions.
No auditoría global de verify-skill: no existe carpeta verify-* local y no se
modificó el verificador. No cambio de esquema/retención para lograr GREEN.

Probe adicional fijo: una vez cada una de las ocho fronteras/error originales,
con exercise/assertions intactos; captura excepción por caso para no ocultar
los posteriores, pero conserva salida global1. **6 PASS de esas assertions,
2 ProductRed**. EIO y ENOSPC en fsync5/staging: rc4, authority-atomic1,
prepared/streams/chunks **1/1/17**, reinicio retiene streams/chunks1/17;
cleanup errors0. En esta corrida commit8 dio assertions PASS y staging0;
no se atribuye un fix ni equivalencia con el witness histórico de índice8.
[Ocho resultados](../../.scratch/chef-integration-20261014/run1/g7-boundary-results.json),
[comando/digest/rc1](../../.scratch/chef-integration-20261014/run1/g7-boundaries-command.json),
[log](../../.scratch/chef-integration-20261014/run1/g7-boundaries.log).

Bootstrap y vault con witness original: ambos rc1, audit10→12, prefijo cifrado
idéntico y todas las filas de las11 tablas de autoridad/receipt idénticas;
INDETERMINATE, provider calls1, replacement0, admission closed1, cleanup0.
No evidencia de mutación de autoridad por ese conteo. Los probes preservan
las aserciones y sus rc1; no autorizan borrar prepared, cambiar schema ni
reclasificar G7 como aceptado.
Los snapshots before/after no prueban todos los instantes intermedios ni
descifran el significado de las dos filas nuevas de auditoría.
[Bootstrap](../../.scratch/chef-integration-20261014/run1/g7-witness-bootstrap.log),
[vault](../../.scratch/chef-integration-20261014/run1/g7-witness-vault.log).

Intento auxiliar fallido retenido: matrix-owned-root rc1, interposer child120,
no /proc/self/fd dentro del chroot sin mounts (`sqlite_sync_interposer.c:25`).
Es fallo de precondición del helper, no ProductRed. Ledger/root retenidos y
log conservado. El método final enruta syscall matrix por matrix_counts.py
fuera del chroot; no montó proc del host ni relajó la política de raíz.

## Artefactos y límites finales

[Hashes/orígenes exactos de binarios](../../.scratch/chef-integration-20261014/run1/binary-origins.json)
incluyen pm, custody, web-auth, SSH, sync y ejemplo, todos target/debug propio.
Clon, target-check, target, baseline/target, logs, recibos kitchen, VT y ledgers
sintéticos se conservan. Helper chroot daemon original limpia su raíz propia
mediante rmtree estricto como parte de acceptance; su salida completa y hashes
persisten. No limpieza manual de artefactos ajenos. El directorio .scratch del
run es evidencia privada LOCAL y queda fuera del commit; report/método nuevos
son los únicos archivos comprometidos.

Inferidos y conservados: startup omite recover al fallar vault-open;
handler/worker/settle/recovery ignoran errores genéricos, poolfull cierra;
CLI UnavailableEngine/env/MCP vacío y JSON exit masking. Ubicaciones/categorías
constan en los informes exactos [daemon](../../.scratch/chef-integration-20261014/run1/clone/docs/verification/chef-daemon-admission-20261014.md),
[CLI](../../.scratch/chef-integration-20261014/run1/clone/docs/verification/chef-cli-human-entry-20261014.md), [memoria](../../.scratch/chef-integration-20261014/run1/clone/docs/verification/chef-protected-memory-20261014.md)
y [adaptadores](../../.scratch/chef-integration-20261014/run1/clone/docs/verification/chef-adapter-memory-20261014.md) del clon compuesto. No se
corrigieron ni añadieron alternativas. Esos informes candidatos no están
importados a la rama de método; los enlaces son válidos en el clon compuesto.

NOT_RUN: Windows/macOS nativos, otras CPU, proveedor externo/GitHub real,
reboot/FDE, instalación/paquetes/firma, aceptación humana final/Astra35.
Decisión3 sigue sin aprobación; perfil/availability Windows P1 excluido y
no cerrado. Decisión4 durable-intent sigue sin aprobación; G7 no cerrado.
Plazos8/15/20/30s, wire/KDF/replay/receipts y límites4/16/128 conservados.
No push, PR, master merge, release, CI dispatch, gasto, credenciales reales,
publicación externa, tickets ni registries del parent modificados.
