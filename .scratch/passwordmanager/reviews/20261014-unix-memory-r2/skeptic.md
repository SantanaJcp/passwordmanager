# Skeptic R2: re-revisión de D1 y D2 sobre `894aa36`

**Veredicto de fuente: PASS.** En `894aa3600610e23a1834d831668bf66dc2bb7112` ya no queda ninguno de los dos P1 de R1. No abro hallazgos nuevos. No ejecuté nada: ni Cargo, ni labs, ni archivos temporales.

Hice estas comprobaciones de solo lectura con `git -C <worktree>` (medido):
- Los tres SHAs resuelven con `rev-parse --verify`.
- `7b7026e` es ancestro de `894aa36` y hay un único commit correctivo entre ambos.
- `7b7026e..894aa36` toca 10 archivos, +777/−44, sin tocar `lib.rs` ni ramas hermanas. `ecc2e9d...894aa36` toca 13 archivos, +2353/−33.
- `pm-vault` no cambia desde `ecc2e9d`: `git diff --stat` sale vacío.

Las cifras RED→GREEN, rc0 y "una llamada" son del autor, no mías.

## Standards

- **`truthful-state` y `no-fallbacks`:** el informe `chef-daemon-admission-20261014.md:3` declara **ISSUES** para el paquete y GREEN solo para las dos correcciones locales. Marca como NOT_RUN Windows, macOS, el proveedor real y el SSH real (`:150`). No sube evidencia parcial a PASS.
- No hay fallback genérico nuevo. El nuevo diagnóstico (`linux.rs:3710-3722`) emite una sola línea por cambio de categoría, con un código local fijo y sin texto del proveedor. Sin hallazgo.

## Request

- **D2, "una reconciliación desconocida nunca pasa a terminal sin el proveedor o sin una cancelación o revocación autoritativa": cumple.** Lo inferí leyendo el código. Repasé cada ruta de `run_provider_once` (`linux.rs:3624-3687`) con un lease `reconciliation_only`:
  - **Custodia no verificada o registro ausente** (`:3646-3649`): pasa por `local_provider_failure` y queda en `Indeterminate`.
  - **`select` falla o la config falta** (`:3697`, `:3700`): queda en `Indeterminate`.
  - **El socket falla al conectar** (`:3818`): devuelve `Err(())` y sigue en `Indeterminate`, igual que antes.
  - **SSH en reconciliación** (`:3875-3878`): devuelve `WaitingForHuman` sin conectar con el adaptador.
  - **Únicos caminos a `Failed` en reconciliación:** `AUTHORITY_REVOKED` (`:3663-3673`), que es la revocación autoritativa y ya existía, o un estado que devuelva el propio adaptador (`:3854-3866`).
  - **Leases nuevos (`created`):** siguen con el `Failed` explícito (`:3729`).
  - **Por qué no queda atascado:** en pm-vault, `settle(Indeterminate)` deja `terminal_at_us=NULL` (`attempts.rs` en `894`, `settle`). `claim(true)` vuelve a recoger `indeterminate` pasados 100 ms, así que al restaurar se reconcilia con el opcode 2 y sin un login nuevo.
- **D1, "4 por cada RPK probada, y un pre-auth finito": cumple.** Lo inferí leyendo el código:
  - **Presupuesto nativo:** `RegisteredConnections::new` (`connection_dispatch.rs`) da a cada UID 4 × (RPKs registradas con ese UID). Es inmutable y sale solo del registro validado (`linux.rs:1025-1034`). Un UID desconocido se rechaza antes del handshake.
  - **Presupuesto por RPK:** `admit_agent_tls` (`linux.rs:4397-4431`) completa TLS y comprueba ALPN, `admission.verify()` y el par (RPK observada, UID). Reserva el permiso de esa RPK **antes** de leer el magic (`:4339-4350`).
  - **Liberación:** el permiso dura todo `handle_connection` y el permiso nativo vive dentro del closure del worker. Ambos se liberan por `Drop`, también ante un pánico, y el reap sigue siendo fatal.
  - **Total:** 4N, con N ≤ 339 por el límite del registro.
  - **UIDs distintos:** A no puede consumir el presupuesto nativo de B.
  - **Revocación en caliente:** `[5]` sale solo de `AgentRevoked` (`agent_wire.rs:370`). Los éxitos empiezan con 0 y el resto de errores son otros códigos de un byte, así que cerrar en `[5]` (`agent_wire.rs:83`) no corta respuestas válidas.

## Design

- **D1 · cerrado.** La secuencia de R1 era: A ocupa los 4 slots y B queda denegado antes del handshake. Ya no puede darse con UIDs distintos, porque cada uno tiene su propio presupuesto nativo. Con UID compartido, A sí recibe un quinto permiso nativo de 8, pero tras TLS su RPK no tiene permiso libre, así que la conexión se cierra antes del magic y B sigue entrando.
  - **Residual dentro del alcance aprobado:** con UID compartido, A podría mantener handshakes lentos que gotean bytes; `IO_TIMEOUT` es de 15 s **por lectura**. Así ocuparía los 8 permisos nativos de su propio UID. No lo levanto: antes de TLS el UID es la única identidad, y dos procesos con el mismo UID forman un mismo principal nativo, que es la separación aceptada en el triage. Entre UIDs distintos, el pre-auth es finito.
- **D2 · cerrado.** El lab `chef_runtime_reconciliation.py:42-46` espera 1 s, más que el reclaim de 100 ms, y exige `terminal_at_us IS NULL`. Si se revierte el arreglo, el estado pasa a `failed` con `terminal_at_us` fijado y la aserción falla. Es una prueba de comportamiento, no un fixture que se valida a sí mismo.
  - Detalle menor, no bloqueante: el lab acepta `running` como estado observado.
  - Efecto aceptado: si la caída ocurre en WAITING, el reto del humano se ve como INDETERMINATE hasta restaurar. El estado no es terminal y no se repite el login.
- **Tests de Rust nuevos (`connection_dispatch.rs`, módulo `registered::tests`):** usan esperados independientes (capacidad 8, 4 por RPK, liberación tras un pánico). No son tautológicos. La regresión de punta a punta sigue dependiendo de los labs del autor.

## Cobertura no ejecutada (NOT_RUN)

Todo se ejecuta dentro del namespace subuid/subgid del ticket 03, como root y bajo `flock /tmp/pm-cargo-window.lock`:
- `scripts/cargo-local.sh test -p pm-custody --locked --offline`, que incluye `registered::tests`.
- `CHEF_RECONCILIATION_CASE={socket,config-remove,config-replace,registry-remove,bootstrap-mode,audit-mode,indeterminate-socket,ssh-socket} python3 crates/pm-custody/tests/chef_runtime_chroot.py …`
- `chef_runtime_admission.py`, con UID compartido y con UIDs separados.
- `scripts/check.sh` una vez sobre los SHAs hermanos exactos ya compuestos; la integración sigue pendiente.

Siguen NOT_RUN: Windows, macOS, el proveedor real, el SSH real y G7. Este PASS es de fuente y solo para aceptar el merge de D1 y D2 en `894aa36`. No es una certificación nativa ni de seguridad, y no sustituye ejecutar las repros.
