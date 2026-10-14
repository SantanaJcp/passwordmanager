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
| windows-acceptance | Reconciliar cleanup W1 heredado sobre código actual y discriminar RETIRE durable | `crates/pm-native-channel/examples/**`, `crates/pm-native-channel/tests/**`, `scripts/test-windows-custody-lab.ps1`, `scripts/test-windows-storage-diagnostics.ps1` |
| macos-stability | Eliminar causas reproducidas de observación parcial/streaming en las fixtures macOS, sin cambiar producto/plazos | `crates/pm-custody/tests/macos*`, `scripts/test-macos-custody-lab.sh`, `scripts/verify-macos-custody-ci-config.sh` |
| vault-g7 | Discriminar/corregir fallos de staging y pérdida de custodia/auditoría preservando commit, replay y receipt | `crates/pm-vault/src/**`, `crates/pm-vault/tests/**`, `crates/pm-vault/examples/**` |
| protected-memory | Completar riesgos propios reproducibles de memoria protegida/nativos sin modificar APIs ajenas | `crates/pm-crypto/src/**`, `crates/pm-crypto/tests/**`, `crates/pm-native-channel/src/**` |
| adapter-memory | Cerrar exposiciones propias reproducibles de adaptadores HTTP/browser/SSH, sin simular proveedores reales | `crates/pm-web-auth/src/**`, `crates/pm-web-auth/tests/**`, `crates/pm-ssh-client/src/**`, `crates/pm-ssh-client/tests/**` |
| daemon-readiness | Repro ordinario A/B y mapa concreto de provisión/configuración; implementación de autoridad detenida hasta decisión | Solo nuevos `crates/pm-custody/tests/chef_daemon_*.py`; producto read-only |
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

## Puertas concretas pendientes

Se tramitan con dos opciones estructuralmente distintas, sin frenar frentes independientes: binding confiable RPK→principal nativo versus nueva versión de enrolamiento; configuración instalada de adaptadores versus procesos supervisados por daemon; cleanup/recovery durable si la corrección cambia el contrato de prepared/replay. Plazos, KDF y alcance se preservan. Firmas reales, plataformas ausentes y aceptación humana siguen siendo externas.

## Seguimiento

Los taskIds, clientRequestIds y resultados del despacho se guardan en el registro JSON adyacente `parallel-run-20261014.tasks.json`, propiedad exclusiva del coordinador. No son estados duplicados de los tickets.
