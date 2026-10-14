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
- Medición atribuida al worker CLI, no repetida aquí: el informe chef-cli-human-entry-20261014.md en el objeto CLI registró prompt, unlock, búsqueda, commit de organización, lock/exit y restauración de terminal; nueve tests CLI y una ejecución de check.sh terminaron en código 0. Windows/macOS y la integración exacta quedaron NOT_RUN.
- Medición atribuida al worker daemon: chef-daemon-implementation-20261014.md y chef-daemon-admission-20261014.md en el objeto daemon describen fixtures locales de registry/adapters y recuperación/revocación con procesos y UIDs sintéticos. El resultado del paquete siguió ISSUES y no certifica instalación ordinaria ni soporte de otras plataformas.
- Estado leído de .scratch/passwordmanager/parallel-run-20261014.results.json y sus triages: batchAccepted=false e integrationExecuted=false; la aceptación general sigue parcial. No se convirtió esa lectura en PASS del lote.

## Verificación de esta tarea

- Medido: el validador de documentación comprobó 17 enlaces relativos en README.md, la guía y este informe, incluidos tres anchors; los destinos y fragments existen.
- Revisado contra objetos CLI/daemon fijados: los flags, su orden, IDs de cabecera y nombres de comandos coinciden con los parsers citados. No se ejecutaron esos comandos ni el fixture.
- Medido: el escaneo acotado a cuatro formas comunes de credencial halló cero coincidencias en los tres archivos; revisión textual confirmó que los ejemplos usan rutas/perfiles sintéticos y solo nombran archivos de clave, no su contenido.
- Medido: git diff --check terminó con código 0; git status mostró únicamente los tres paths asignados como cambios documentales; este informe tiene contenido no vacío.
- No ejecutados por autorización de alcance: Cargo, build, check.sh, tests, laboratorios, CI/nativos, revisión cruzada, delegación o composición de hermanos.

## Gaps restantes

- No hay instalación/provisión ordinaria verificada de custodio, propietarios, service lifecycle, perfil humano y sockets. La migración también necesita .audit-custody previo; serve-vault lo carga o crea, pero la secuencia aceptada de inicializar, autorizar humanamente, migrar, provisionar adaptadores y gestionar el servicio no está documentada como instalación ordinaria.
- No hay composición del CLI 4c3 con daemon 894 en esta rama ni aceptación global; la interfaz medida por el worker no demuestra un build integrado.
- Windows/macOS nativos no ejecutados. El consumidor Windows ordinario de registry/adapters sigue incompleto. La compatibilidad del perfil ACL/configuración y cualquier propuesta de ubicación bajo ProgramFiles siguen sin prueba nativa.
- G7 conserva pendiente la intención preparada durable y esquema (decisión del propietario 4); aceptación nativa hospedada requiere la decisión del propietario 3. No se cierran tickets ni se declara producto listo o certificado.

Principios aplicados: owner-attention y no-fallbacks mantienen separadas la TUI humana y la administración; truthful-state, prove y evidence separan mediciones de workers de instalación y composición pendientes; small-owned limita los cambios a las rutas documentales asignadas.
