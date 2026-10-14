# Alineación documental de la guía Linux — 2026-10-14

Estado: PASS documentación solamente. El artefacto está verificado en los límites de esta tarea; no es aceptación del producto.

## Base y archivos

- Base de este worktree: 31b48ace181512d273738ff3b344201be8e8f08b.
- Commit original incorporado por cherry-pick limpio: 9de9aa99347cc2b3300190601ba00c568f22aa86; commit local de incorporación: 6e5fbee0.
- Fuentes de código consultadas solo como objetos Git fijados: base d4b1be662a1b8766eff54c2b8269ef4c94770c54; CLI 4c3a90c8e3c5ceac229060e66f551012e88c46dd; daemon 894aa3600610e23a1834d831668bf66dc2bb7112, rango ecc2e9d390b780223dfdf1322288762f87af891c..894aa3600610e23a1834d831668bf66dc2bb7112; guía original 9de9aa99347cc2b3300190601ba00c568f22aa86.
- Archivos modificados o añadidos por esta alineación: README.md, docs/user/evaluacion-linux.md y este informe. El informe original chef-user-guide-20261014.md permanece intacto como evidencia histórica.

## Cambios

- Se actualizó la guía para presentar pm tui como la entrada pública humana confirmada, con el parser Linux y los seis flags obligatorios en el orden fijado. Se conserva que --help no existe y que pm tui --json falla como UNAUTHORIZED/3.
- Se separaron los comandos administrativos de custodia del bridge público de TUI y de las operaciones delegadas CLI/MCP. Los ejemplos solo usan rutas y perfiles sintéticos; no contienen credenciales ni material de clave.
- Se documentaron las cabeceras binarias PMAR1 y PMAC1, las rutas laterales de vault, los comandos de migración/provisión y sus límites: binding RPK→UID y vault/device/server key, grants humanos vigentes, revocación, worker externo, endpoint exacto y ausencia de fallback de laboratorio.
- Se distinguió la fixture local con chroot UID 0 y TUI externa de una instalación ordinaria. Se registra que faltan un instalador, el ciclo de vida de servicio del sistema y un procedimiento aceptado para establecer propietarios, rutas y recursos nativos del host.
- Se sustituyó el estado histórico por la aceptación parcial del coordinador: composición exacta no ejecutada, Windows/macOS NOT_RUN, consumidor Windows incompleto, hipótesis de ACL/configuración sin medición nativa, y decisiones del propietario 3 y 4 pendientes.

## Evidencia y clasificación

- Inferido de la fuente CLI fijada: crates/pm-cli/src/lib.rs:45-65 despacha el prefijo exacto tui a human_tui; crates/pm-custody/src/tui.rs:690-723 exige profile, private, socket en Unix y los tres flags de tiempo en orden; crates/pm-custody/src/lib.rs:111-146 devuelve UNAUTHORIZED/3 si la entrada humana recibe --json.
- Inferido de la fuente daemon fijada: crates/pm-custody/src/installed_unix.rs:13-129 define PMAR1, PMAC1, sidecars junto a la bóveda, validación de permisos/owner/ancestros y límites; :228-269 migra el bootstrap verificado y requiere el sidecar previo .audit-custody; :272-472 valida y publica adaptadores. crates/pm-custody/src/linux.rs:451-491 y :761-814 expone migrate-agent-registry, provision-adapters y serve-vault con los flags citados.
- Medición atribuida al worker CLI, no repetida aquí: el informe chef-cli-human-entry-20261014.md en el objeto CLI registró prompt, unlock, búsqueda, commit de organización, lock/exit y restauración de terminal; nueve tests CLI y una ejecución de check.sh terminaron en código 0. En ese corte de candidato, Windows/macOS y la composición exacta seguían NOT_RUN; el estado de composición posterior queda registrado abajo.
- Medición atribuida al worker daemon: chef-daemon-implementation-20261014.md y chef-daemon-admission-20261014.md en el objeto daemon describen fixtures locales de registry/adapters y recuperación/revocación con procesos y UIDs sintéticos. El resultado del paquete siguió ISSUES y no certifica instalación ordinaria ni soporte de otras plataformas.
- Snapshot inicial de `.scratch/passwordmanager/parallel-run-20261014.results.json`, leído desde la base `31b48ace181512d273738ff3b344201be8e8f08b` antes de que el integrador regresara: `batchAccepted=false` e `integrationExecuted=false`. Es evidencia histórica de ese momento, no el estado actual; la lectura posterior queda registrada al final. Esa lectura inicial no se convirtió en PASS del lote.

## Verificación de esta tarea

- Medido: el validador de documentación comprobó 17 enlaces relativos en README.md, la guía y este informe, incluidos tres anchors; los destinos y fragments existen.
- Revisado contra objetos CLI/daemon fijados: los flags, su orden, IDs de cabecera y nombres de comandos coinciden con los parsers citados. No se ejecutaron esos comandos ni el fixture.
- Medido: el escaneo acotado a cuatro formas comunes de credencial halló cero coincidencias en los tres archivos; revisión textual confirmó que los ejemplos usan rutas/perfiles sintéticos y solo nombran archivos de clave, no su contenido.
- Medido: git diff --check terminó con código 0; git status mostró únicamente los tres paths asignados como cambios documentales; este informe tiene contenido no vacío.
- No ejecutados por autorización de alcance: Cargo, build, check.sh, tests, laboratorios, CI/nativos, revisión cruzada, delegación o composición de hermanos.

## Gaps restantes

- **Inferido de spec §15:** el diseño de distribución/formato G8 está confirmado; su implementación y entrega siguen pendientes. No hay instalación/provisión ordinaria verificada de custodio, propietarios, ciclo de servicio, perfil humano y sockets. La migración también necesita `.audit-custody` previo; `serve-vault` lo carga o crea, pero la secuencia aceptada de inicializar, autorizar humanamente, migrar, provisionar adaptadores y gestionar el servicio no está documentada como instalación ordinaria.
- **Inferido del informe de integración y la comparación de SHAs:** el compuesto privado exacto de CLI `4c3` y daemon `894` existe con estado ISSUES (42/52 casos con rc0); no está en esta rama. Esta guía en `e1307808be9b88a77cc3a9725356b7281f4bb49f` y la corrección posterior de sync tampoco están en ese compuesto, por lo que requieren otra composición exacta después de las migraciones de callers. No hay aceptación global.
- Windows/macOS nativos no ejecutados. El consumidor Windows ordinario de registry/adapters sigue incompleto. La compatibilidad del perfil ACL/configuración y cualquier propuesta de ubicación bajo ProgramFiles siguen sin prueba nativa.
- G7 conserva pendiente la intención preparada durable y esquema (decisión del propietario 4); aceptación nativa hospedada requiere la decisión del propietario 3. No se cierran tickets ni se declara producto listo o certificado.

Principios aplicados: owner-attention y no-fallbacks mantienen separadas la TUI humana y la administración; truthful-state, prove y evidence separan mediciones de workers de instalación y composición pendientes; small-owned limita los cambios a las rutas documentales asignadas.

## Seguimiento posterior de composición y comandos — 2026-10-14

- Medido en el snapshot posterior del coordinador, leído en la rama padre `chef/pm-finish-20261014` (HEAD `166669b945e89ae5705f4c1c7e2cbf7679b6f299`): `batchAccepted=false`, `integrationExecuted=true`, `integrationSubsetStatus=PASS kitchen combined-check only; complete52 ISSUES`; el lane de integración conserva `ISSUES measured — kitchen/check/cleanPASS subset; 42/52 suite`. El archivo privado `.scratch/passwordmanager/parallel-run-20261014.results.json` tenía SHA-256 `5af9e1251ad88b82235614fc4ff2d0f8fdbc9f91cd55fadc9810791ff15d3e90` al consultarlo.
- Medición atribuida al informe de integración en el commit `0a11733ffc784e80cb75c8df01d2cdcf34862d7e`: nueve heads compuestos en `8cd45529b062506a2cbe0c567538d3999ac8a2b6`; kitchen, check completo y clean/offline rc0; barrida de 52 casos con 42 rc0 y 10 rc1. Diecisiete flujos focalizados agrupados pasaron, incluidos TUI humana pública, registry/admission, ocho reconciliaciones y tres comprobaciones de memoria RED en baseline/GREEN en el compuesto. Los diez rc1 son siete fixtures ordinarias sin migración 1A/2A y tres casos G7. Resultado global ISSUES; no es PASS de 52 casos, aceptación de producto ni certificación nativa.
- **Inferido por comparación de SHAs y el estado del coordinador:** el compuesto `8cd45529b062506a2cbe0c567538d3999ac8a2b6` no incluye el head documental actual `e1307808be9b88a77cc3a9725356b7281f4bb49f` ni la corrección posterior de sync; esos cambios esperan una composición nueva después de las migraciones de callers. Windows/macOS, el consumidor Windows ordinario, el instalador/ciclo de servicio y G7 permanecen sin cambio de estado.
- **Medido por lectura de la fuente fijada y revisión textual:** `crates/pm-custody/tests/chef_runtime_chroot.py` en daemon `894aa3600610e23a1834d831668bf66dc2bb7112` no adquiere un lock interno. Los ejemplos de build/check/lab y los dos invocadores Python usan ahora `flock -x /tmp/pm-cargo-window.lock` bloqueante; la fixture especial mantiene `CARGO_TARGET_DIR` privado y deriva `BIN` del mismo target. No se ejecutaron esos comandos en este seguimiento.
- **Medido tras esta edición:** los enlaces/anchors, el diff y la clasificación del nuevo estado se volvieron a comprobar; no se ejecutaron Cargo, builds, tests, laboratorios, CI, revisión, delegación ni instalación.

Principios aplicados en el seguimiento: `truthful-state` y `evidence` reemplazan el snapshot inicial obsoleto con procedencia posterior; `no-fallbacks` mantiene fallido el toolchain ausente y no inventa una instalación; `small-owned` limita el cambio a la guía y este informe; `prove` deja la verificación en los artefactos documentales sin afirmar ejecución del producto.
