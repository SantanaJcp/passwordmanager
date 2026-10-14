# Despacho paralelo — 2026-10-14

## Encargo y cierre

El propietario pidió explícitamente continuar la implementación pendiente en chef-mode, con el máximo paralelismo sin interferencias y orientado a un producto usable. Esto autoriza trabajo local enfocado; no autoriza publicación, reducción de alcance o garantías, cambios unilaterales de contratos, credenciales reales, instalaciones o gates simulados.

Base de código candidata: `d4b1be662a1b8766eff54c2b8269ef4c94770c54`. Coordinador: `chef/pm-finish-20261014`, worktree `/home/santana/Documents/ChatGPT/passwordmanager/.worktrees/chef-finish-20261014`. La raíz histórica y todos los worktrees anteriores se conservan intactos. Este documento registra asignaciones, no sustituye estados de tickets, contratos ni spec §15.

Cierre: cada candidato tiene RED conductual y GREEN del mismo caso cuando modifica comportamiento, evidencia de flujos afectados, diff revisado y composición comprobada en SHAs exactos. Los tickets 26–28 no se cierran por checkpoints; 29–35 conservan sus dependencias y puertas externas/humanas. La revisión global final no se adelanta.

Autonomía efectiva: `propose`, comprobada en `origin/master:AGENTS.md` sin línea `Autonomy`. No push, PR, merge del PR #1, release, gasto, secretos, alteración de protecciones ni dispatch hospedado en este despacho. Revisor configurado: Claude Opus 5.5, esfuerzo high, tier standard; revisiones de candidatos en otro modelo, máximo dos rondas.

## Frentes y propiedad exclusiva

Cada escritor obtiene un worktree T3 hijo desde el commit local del coordinador y puede añadir únicamente su informe nuevo `docs/verification/chef-<frente>-20261014.md`. Los globs siguientes no se solapan. Una dependencia de otro frente se reporta, no se modifica.

| Frente | Resultado acotado | Archivos autorizados |
| --- | --- | --- |
| sync-windows | Diagnóstico y corrección mínima de coste/transportes del sync Windows, sin ampliar 15 s ni cambiar wire/semántica | `crates/pm-sync/src/**`, `crates/pm-sync/tests/**`, `crates/pm-sync/examples/**` |
| windows-acceptance | Reconciliar cleanup W1 heredado sobre código actual y discriminar RETIRE durable; follow-up diagnóstico del observer SQLite sin alterar su oráculo | `crates/pm-native-channel/examples/**`, `crates/pm-native-channel/tests/**`, `scripts/test-windows-custody-lab.ps1`, `scripts/test-windows-storage-diagnostics.ps1`, `crates/pm-custody/examples/windows_human_tui_seed.rs`, nuevo `crates/pm-custody/examples/windows_human_tui_seed/**` |
| macos-stability | Eliminar causas reproducidas de observación parcial/streaming en las fixtures macOS, sin cambiar producto/plazos | `crates/pm-custody/tests/macos*`, `scripts/test-macos-custody-lab.sh`, `scripts/verify-macos-custody-ci-config.sh` |
| vault-g7 | Discriminar/corregir fallos de staging y pérdida de custodia/auditoría preservando commit, replay y receipt | `crates/pm-vault/src/**`, `crates/pm-vault/tests/**`, `crates/pm-vault/examples/**` |
| protected-memory | Completar riesgos propios reproducibles de memoria protegida/nativos sin modificar APIs ajenas | `crates/pm-crypto/src/**`, `crates/pm-crypto/tests/**`, `crates/pm-native-channel/src/**` |
| adapter-memory | Cerrar exposiciones propias reproducibles de adaptadores HTTP/browser/SSH, sin simular proveedores reales | `crates/pm-web-auth/src/**`, `crates/pm-web-auth/tests/**`, `crates/pm-ssh-client/src/**`, `crates/pm-ssh-client/tests/**` |
| daemon-readiness | Repro ordinario A/B y mapa concreto de provisión/configuración; conserva su alcance de prueba | Solo nuevos `crates/pm-custody/tests/chef_daemon_*.py`; producto read-only |
| daemon-implementation | Implementar 1A y 2A aprobadas; follow-up corrige admisión/concurrencia G4 y atiende findings acotados | `crates/pm-custody/src/**` **excepto `lib.rs`** transferido tras finalizar el candidato Unix; nuevos `crates/pm-custody/tests/chef_runtime_*.py`, nuevos `crates/pm-custody/examples/chef_runtime_*`, informes exclusivos `chef-daemon-implementation-20261014.md` y nuevo `chef-daemon-admission-20261014.md` |
| cli-human-entry | Exponer `pm tui` ya confirmado, solo entorno humano y sin ampliar MCP ni permisos | `crates/pm-cli/src/**`, nuevos `crates/pm-cli/tests/chef_human_*`, únicamente `crates/pm-custody/src/lib.rs` para bridge público fijo a la TUI existente; nuevo `docs/verification/chef-cli-human-entry-20261014.md` |
| user-guide | Instrucciones Linux reproducibles para evaluación sintética, con límites y prerrequisitos explícitos | `README.md`, nuevos `docs/user/**` |
| verification-map | Recuperar método observable exacto y vector de candidatos; no revisar formalmente ni cambiar verificadores | Read-only; resultado por respuesta del agente |

Los frentes sensibles usan Sol medium, Standard; documentación mecánica Luna max, Standard. No reasignar modelos configurados mediante fallback.

## Método de trabajo y exclusión de recursos

1. Leer chef-mode/PRINCIPLES, AGENTS, CONTEXT, spec §15 y ejecución; leer `feature-xray` y `find-the-cause` antes de cambiar áreas desconocidas o defectuosas. No investigación general ni reapertura de acuerdos cerrados.
2. Nombrar forma de datos, reproducir el fallo real, conservar RED, corregir causa mínima dentro de allowlist y repetir el mismo caso más flujos afectados. Compilación fallida no es RED conductual.
3. Todo Cargo/build/lab usa `flock /tmp/pm-cargo-window.lock`; toolchain única inmutable en la raíz `.toolchain/`; `CARGO_TARGET_DIR` propio por hijo. No `cargo clean` sobre targets compartidos, instalaciones, matar procesos ajenos ni limpieza de raíces ajenas. Fmt de un paquete no reescribe otros archivos.
4. Check local escrito: `scripts/check.sh`; clean/offline y barrida secuencial se reservan al integrador después de composición. No repetir 52 casos en cada escritor sin necesidad. Runners nativos y límites: `docs/verification/native-ci.md`; no dispatch/publicación autorizado aún.
5. Prohibido editar tickets, spec, ejecución global, este plan, Cargo manifests/lock, workflow, build config o documentos heredados de otros frentes. Informes nuevos exclusivos. Commits locales solo de archivos propios; no merge de ramas antiguas completo ni modificaciones al checkout raíz.
6. Inspeccionar core diff/evidencia al retorno, revisión cruzada acotada por riesgo y `kitchen integrate` sobre siblings exactos antes de atribuir PASS al lote. Los tres RED G7 heredados no se convierten en éxito por ser conocidos.
7. Registrar checkpoints con `kitchen log`. Reportar PASS, ISSUES o BLOCKED; distinguir medido, inferido y no ejecutado. Un candidato local sin nativo no certifica macOS/Windows.

Coordinación de seams sin segundo escritor: el owner de protected-memory implementa en `pm-native-channel/src/windows.rs` el constructor agent con lista SID validada y el accessor del SID observado por impersonación. Daemon-implementation consume únicamente el SHA comprometido y cruza ese SID con RPK TLS y autoridad vigente. El contrato sigue fijando 4 conexiones/agente, no se atribuye prueba de aislamiento por identidad al dispatcher global actual. El bound existente de configuración 16 KiB se comprueba con bytes serializados reales, no estimaciones.

## Puertas concretas pendientes

El propietario confirmó «1 A» y «2 A»: registro local confiable RPK→principal nativo con migración explícita y configuración instalada de adaptadores. La decisión y sus fronteras verificables están en [decisions.md](../../decisions.md). Un nuevo escritor exclusivo de producto custody implementa ambas en orden, sin solaparse con el agente de probes ni las fixtures macOS/Windows.

**Decisión 3 pendiente:** publicar solo candidatos exactos y ejecutar los workflows gratuitos existentes, con máximo tres Windows y dos macOS (3A recomendada), o permanecer local con aceptación nativa pendiente (3B). «1 A / 2 A» no autoriza 3A.

**Decisión 4 pendiente:** separar intención preparada cifrada durable de temporales recuperables con lifecycle explícito, preservando retry/receipt (4A recomendada), o abortar definitivamente y requerir nuevo prepare/firma (4B, reduce comportamiento acordado). El probe G7 no autoriza borrar payload ni cambiar esquema/contrato. Plazos y KDF se conservan.

Hallazgo y correctivo comprobado por autor: `6728bbd` aprendía el owner observado de `/`; candidato **no aceptable aislado**, nunca integrar ese checkpoint. `7b7026e` retira esa ampliación y conserva ROOT/current con RED→GREEN de filesystemroot de agente; fixture propia usa chroot UID0 y TUI externa real. No reescritura de historia. La revisión usa el diff combinado `ecc2e9d..7b7026e`.

La política de ancestros Windows procede del TCB administrativo ya confirmado (security-operations §1 y distribution mantenimiento): SYSTEM/Administrators/TrustedInstaller/servicio exacto para control de componentes existentes; archivo y directorio privado exactos servicio/SYSTEM. No aprender cualquier owner/installer SID. Implementación nativa aún NOT_RUN. No modificar padres ajenos para adecuar fixtures.

`pm tui` está confirmado en spec §11 y agent-identity, no es una nueva puerta de elección de nombre. Nuevo escritor exclusivo expone la entrada humana mediante código existente, sin shell/PATH/role flag ni permisos nuevos; no toca daemon fuera del bridge `lib.rs`. El owner daemon continúa admisión G4 (4 conexiones/agente, no global4) en sus propios archivos. Revisores Claude R1 read-only inspeccionan SHAs fijados, no archivos en vivo. Firmas reales, plataformas ausentes y aceptación humana siguen siendo externas.

## Checkpoint de revisiones y candidatos

- Daemon correctivo `894aa360`: Skeptic/Architect R2 **PASS de fuente** sobre D1/D2; última ronda permitida. RED→GREEN local del autor, no ejecutado por revisores. [Triage R2](reviews/20261014-unix-memory-r2/triage.md). No integración exacta aún.
- Entrada humana `4c3a90c8`: GREEN Linux local y Claude R1 sin P0/P1. Nativos NOT_RUN. SID `f56c993b` también sin P0/P1 en revisión de fuente; epoch depende de una conexión/instancia actual.
- Config instalada `2801c489`: primitiva comprometida y resultado terminal recibido. R1 deja riesgo inferido de ACL stock ProgramData frente a política de ancestros y gaps de corpus inicial. [Triage kernel/CLI R1](reviews/20261014-kernel-cli-r1/triage.md).
- Follow-up nativo `e18cf389` completado y resultado recibido: SID round-trip/release checked, corpus native inicial estable y ancestros propios, docs rename-lock/layout corregidas; shared Linux6/6/fmt/clippy0. Windows build/runtime/RED→GREEN **NOT_RUN**, hipótesis ProgramData aún abierta.
- Distribución fija ProgramData **datos**, no la nueva config administrativa pública. Corrección técnica acotada al mismo owner: propuesta explícita de PUBLIC cfg/fixture protegida ProgramFiles/config, sin mover datos/código, aprender owners, ampliar ACLs o fallback de ubicación. Corregir afirmación share-lock, corpus initial-open, SID round-trip e invariant de conexión. Medición nativa sigue pendiente de permiso 3; no cerrar riesgo por defaults supuestos.

No batch PASS, cambios de tickets, master/PR/publicación/instalación ni CI. Puertas 3 y 4 siguen sin respuesta. `kitchen integrate`, clean/52 y caller Windows permanecen pendientes. Follow-up de implementación `native-profile-proof-r3` no es tercera revisión.

## Continuación local sin espera del propietario

El propietario corrigió la espera innecesaria («que esperass?»). `owner-attention`/`prove`: puertas 3 y 4 bloquean **solo** publicación/dispatch nativo y cambio durable/retention respectivamente, no composición ni documentación local. Los nuevos registros codifican `requiresOwnerDecision: []` para esas tareas.

Despachados desde `31b48ace`: integrador aislado del vector exacto de nueve siblings (API config2801/e18 excluida), método/check/52 y flujos nuevos; escritor aislado de guía README/docs-user; tres lentes Claude R1 read-only de los cuatro candidatos de diagnóstico/probes restantes. Integrador único ejecutor de builds bajo flock; guía/revisores no compiten por Cargo ni archivos. Guía nueva se compondrá aparte, no mutará el vector en vuelo.

No resultado de ejecución recibido al despacho, no PASS nuevo ni cierre nativo/G7. Sin publicación/CI/instalación/schema ni aceptación implícita de 3A/4A.

Architect/Minimalist evidencia R1 recibidos: ambos sin P0/P1; P2 real en gate TLS que exige ineficiencia actual. Parent trazó fuente y despachó corrección aislada test-only, prueba RED→mismoGREEN sin producción nueva; se compondrá después, no cambia vector en vuelo. PID-reuse cleanup Windows es falsoRED fail-closed para corpus nativo, no se relajan guards. G7 witness read-only/aserción añadida no es observador puro; layout/oráculos se coordinan con decisión4. [Triage evidencia R1](reviews/20261014-evidence-r1/triage.md). Skeptic cobertura incompleta no se vuelve PASS por consenso.

## Seguimiento

Los taskIds, clientRequestIds y resultados del despacho se guardan en el registro JSON adyacente `parallel-run-20261014.tasks.json`, propiedad exclusiva del coordinador. No son estados duplicados de los tickets.
