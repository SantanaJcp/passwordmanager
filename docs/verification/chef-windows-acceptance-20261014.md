# Windows acceptance — reconciliación W1, 2026-10-14

Resultado: **ISSUES**, candidato local; RETIRE durable sin causa demostrada.
No resuelve [27](../../.scratch/passwordmanager/issues/27-custodia-y-canal-humano-windows.md),
ni acredita Windows integral, carga70, revisión Astra35 o aceptación humana.

Medido: worktree y binding T3 `/home/santana/.t3/worktrees/passwordmanager/t3-424546e4`,
rama `t3/reconcile-windows-retire-observer`, base exacta
`ea57a7173424a7c607376ff5e0b49d2a19bc334f` (baseline de código indicado:
`d4b1be662a1b8766eff54c2b8269ef4c94770c54`). HEAD entregable: commit que añade este informe.

## Cambio propio y límites

Medido: aplicado únicamente el diff de `scripts/test-windows-custody-lab.ps1`
entre base y W1 `ea4c3584f77e846e782cddead6562e0eb73f196b`.
Script final byte-idéntico al W1: blob `0019a07d366b6b3d7abcda0f46229b61a22d00ce`,
SHA256 `30335bf8e552f71645e52b96ccd7281f825aca4e953a8470c48dd7649748931f`.
Sin merge de rama histórica. Sin cambios a Rust productivo, fixture ConPTY,
W7, storage diagnostics, manifiestos, workflows o estados.

Inferido del diff: ledger de PIDs SCM propios; inventario de staging sólo tras
STOP/PID ausente, gramática cerrada y rechazo de reparse/owner ajeno/child inesperado;
cleanup continúa con fallo agregado si SYNC aceptado dejó stages. Se conservan
15s, parser VT estricto, salida del hijo y fracaso primario/cleanup.
Los tests nativos reconciliados comprueban owned/foreign-owner/unexpected-child
y successful-sync residue; su DACL adicional sólo corresponde a una fixture sintética.

## Evidencia histórica recuperada, no ejecución del candidato

Medido mediante `gh run view <id> --repo SantanaJcp/passwordmanager --log`
y `--json headSha,conclusion,url`, lectura sin dispatch:

- [RED histórico 37182761489](https://github.com/SantanaJcp/passwordmanager/actions/runs/37182761489),
  `d034c31974cc72ee10762ccac6803c6145a73269`: cleanup rechaza `.pm-sync-stage-<PID>-<digest>`
  no inventariado, raíz propia restante; SYNC falla, RETIRE TUI NOT_RUN.
- [37188616185](https://github.com/SantanaJcp/passwordmanager/actions/runs/37188616185),
  `a479bbbfa8e530d92d4c1cbd499e1d73b407c764`, conclusion failure:
  cuatro controles cleanup PASS; inventario final directories=0/files=0 y
  owned-resources=absent. SYNC36 TUI PASS, wait14494ms; durable154blocks/1root.
  RETIRE TUI PASS08:28:58Z, observer falla08:28:59Z con
  `WINDOWS_HUMAN_FIXTURE_FAILED`. Agregado: local-operations,device-retire-durable.

No es un RED→GREEN nuevo del mismo caso en esta base: carga y producto difieren;
el control nativo positivo usa staging sintético, no prueba limpieza integral de70.
El FAIL histórico de organización precede la corrección W7 actual; no se reimplementa.

## RETIRE: seam exacto y discriminante pendiente

Inferido: observer fuera de allowlist en
`crates/pm-custody/examples/windows_human_tui_seed.rs:648–687`, main:9–13.
Medido: `git diff a479bbb ea57a717 -- crates/pm-custody/examples/windows_human_tui_seed.rs`
vacío; el ejemplo del run histórico es idéntico al de esta base.
Abre SQLite READ_ONLY, consulta exactamente un `device-retire` de sujeto28×16,
cierra conexión comprobada. Open/query/count!=1/close colapsan a
`Failure::Unavailable`; el log no permite distinguirlos.
El harness detiene SCM y abre ACL del directorio y archivo principal antes
de llamar al observer; no abre expresamente ACL de WAL/SHM para esa lectura.
No cambiar esa ACL por sospecha ni introducir immutable/copia/checkpoint como fallback.

Hipótesis pendientes, no causas: (1) open/query falla por acceso SQLite/sidecars;
(2) conteo real0 o>1; (3) close falla. La prueba local de SQL no discrimina
DACL/SCM/SQLite Windows ni demuestra evento firmado, roster o efecto productivo.
Medido: el SELECT actual funciona con el schema actual y sujeto sintético exacto;
queda refutada una incompatibilidad intrínseca de esa consulta con ese schema.
No refuta incompatibilidad del archivo histórico, fallo de acceso ni conteo real distinto.
Próximo seam: asignar al dueño del ejemplo una traza acotada open/query/count/close,
código SQLite y conteo, sin rutas/IDs/payload. Conservar el error primario y el
de cierre; no repetir RETIRE, relajar count==1 ni ampliar deadline. Sólo después
del diagnóstico y autorización nativa corresponde clasificar producto versus observer.

## Verificación local

Prueba nueva: `flock /tmp/pm-cargo-window.lock python3 crates/pm-native-channel/tests/chef_retire_observer_probe.py`.
Usa schema y SELECT actuales sobre SQLite sintético READ_ONLY: cero eventos,
uno exacto, otro sujeto, otro kind, duplicados. No es RED conductual de RETIRE;
no declara seguridad de firmas ni ejecución Windows. Medido: **5/5 PASS**, rc0,
0.015s de tests (espera de lock separada); fixtures propios removidos por TemporaryDirectory.

Medido: `scripts/check.sh` **rc0**, una sola ejecución bajo
`flock /tmp/pm-cargo-window.lock bash -c '<exports>; ./scripts/check.sh > "$CARGO_TARGET_DIR/check.log" 2>&1; result=$?; tail -n 8 "$CARGO_TARGET_DIR/check.log"; exit "$result"'`.
Exports exactos: RUSTUP_HOME=`/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/rustup`,
CARGO_HOME=`/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/cargo`,
CARGO_TARGET_DIR=`/home/santana/.t3/worktrees/passwordmanager/t3-424546e4/target-chef-windows-acceptance`,
RUSTUP_AUTO_INSTALL=0, PATH=`$CARGO_HOME/bin:$PATH`.
Config, fmt, check/test/clippy locked/offline pasaron en Linux.
Log local `target-chef-windows-acceptance/check.log`; target generado conservado,
sin stage ni commit, no se cambió `.gitignore` fuera de allowlist.
Check Linux no compila/ejecuta cfg Windows ni parsea PowerShell.
`git diff --check` rc0; PowerShell no disponible (`command -v pwsh` sin resultado).
No nuevo dispatch, instalación, clean, barrida52, push o PR. Windows nativo actual
**NOT_RUN**; no se eleva el sweep heredado52/49/tres G7 RED a suite verde.

## Fallbacks/omisiones heredadas

Inferido, sin modificaciones ni propuesta de cambio: `pm-sync/src/lib.rs:760,846`
ignora remove_dir_all(stage) al terminar eventos; :955,1009 ignora remove_file(joined).
Activan al fallar borrado y ocultan su error. `pm-native-channel/src/windows.rs:848,1389`
ignora CloseHandle en Drop de pipes; :1487 ignora LocalFree del output DPAPI;
:1532 ignora DestroyWindow en Drop. Ocultan fallos al liberar recursos por esas rutas.
`test-windows-storage-diagnostics.ps1` convierte body/cleanup a booleanos y prioriza
cleanup al fallar ambos, ocultando causa primaria. No atribuir RETIRE a estas omisiones.

No puerta de una vía ejecutada ni cambio contractual propuesto. Recomendación:
integrar sólo este diff enfocado mediante el coordinador, luego asignar el seam
observer fuera de allowlist; aceptación nativa requiere autorización independiente.
Principios: `small-owned`, `isolate`, `root-cause`, `prove`, `truthful-state`, `no-fallbacks`.
