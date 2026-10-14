# Evidencia de la guía Linux

## Alcance y origen

Cambio solo documental en `README.md` y `docs/user/evaluacion-linux.md`; este informe registra la verificación. Rama `t3/linux-user-guide`, worktree `/home/santana/.t3/worktrees/passwordmanager/t3-51840432`. Base exacta: `ea57a7173424a7c607376ff5e0b49d2a19bc334f`. SHA de código indicado para la asignación: `d4b1be662a1b8766eff54c2b8269ef4c94770c54`. No hay cambio de comportamiento: RED/GREEN no aplica.

## Evidencia medida

- Toolchain local Rust 1.98.1. `flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh build --workspace --locked --offline` terminó correctamente en el target aislado `target-chef-user-guide`.
- `scripts/check.sh`, con el mismo toolchain y target aislado y bajo el mismo candado, terminó con código 0. El script ejecuta verificadores de configuración/entradas, `fmt --check`, `check`, todos los tests y `clippy` del workspace con `--locked --offline`.
- El binario dio `passwordmanager 0.1.0 (libsodium 1.0.22)` para `pm --version`. `pm --help` respondió `INVALID_ARGUMENT` con código 2. `pm tui --json` respondió `UNAUTHORIZED` con código 3.
- Una solicitud MCP `tools/list` con JSON-RPC sintético, sin servicio ni credenciales, anunció exactamente `get_capabilities`, `discover_credentials`, `start_authentication`, `get_authentication` y `cancel_authentication`.
- La validación final de enlaces relativos pasó: 16 destinos existentes entre README, guía e informe.

## Límites y fallbacks observados en el código

- **Inferido del código, no una prueba de servicio:** en `crates/pm-cli/src/lib.rs:95-120`, si no hay perfil explícito ni configuración válida en el entorno, el CLI delegado usa `UnavailableEngine`; oculta la causa concreta y devuelve `CUSTODY_UNAVAILABLE` (código 4). En `:584-620`, MCP sustituye la configuración ausente por una configuración de transporte vacía: `tools/list` sigue siendo estático y las operaciones delegadas responden `CUSTODY_UNAVAILABLE`, sin revelar la causa de configuración. La guía exige custodio previamente provisionado y no presenta esos caminos como provisión funcional.
- **Inferido del código:** `crates/pm-custody/tests/linux_lab.py:541-542` limpia el temporal con `shutil.rmtree(..., ignore_errors=True)`. Un error de borrado se suprime; por eso el código de salida no basta para acreditar limpieza. No se modificó este fallback.
- **Medido en la interfaz CLI:** la spec nombra `pm tui`, pero el binario actual rechazó esa forma como `UNAUTHORIZED`. El comando implementado está en `pm-custody tui` y requiere perfil, clave y socket ya autorizados; no se inventó un alias ni se cambió la spec.

## No ejecutado y estado externo

- No se ejecutó el laboratorio de custodia: su wrapper lee `target/debug/pm-custody`, incompatible con el target aislado obligatorio de esta tarea. Tampoco se ejecutó el laboratorio TUI de contenido: usa `wl-copy`/`wl-paste` del portapapeles real de Wayland.
- No se hizo instalación, `sudo`, configuración de servicio, reboot, acceso a credenciales ni prueba de aceptación nativa. El preflight Linux disponible demuestra mecanismos en un host, no aceptación del producto.
- La guía cita el corte de código `2272a1f446fb80cf35566b2b4406338a61e4f1dd`: barrido local 52 casos (49 códigos 0, tres RED conocidos de G7); Windows pasó operaciones locales pero falló sincronización al límite original de 15 s, RETIRE quedó NOT_RUN y cleanup falló; macOS Intel pasó, mientras ARM falló antes de W7 en la observación del prompt y tuvo timeout de 30 s en `human-streaming-file`. Referencia: [evidencia W7](w7-vault-org.md). Ese estado no se reejecutó en esta tarea.

## Puerta de decisión no cruzada

La spec mantiene `pm tui` como comando humano y el código solo implementa `pm-custody tui --profile ... --private ... --socket ...`. Dos formas estructuralmente distintas de cerrar esa diferencia son: **(A)** añadir una ruta/alias en el CLI público `pm` que delegue a la TUI humana, preservando el contrato de la spec; **(B)** confirmar que la superficie pública debe ser `pm-custody tui` y cambiar el contrato de comandos y sus criterios de aceptación. No se tocó código ni spec en esta tarea. **Recomendación inferida:** si `pm tui` sigue siendo el acuerdo confirmado de la spec, resolver con A; requiere autorización y aceptación del dueño del CLI antes de implementarse.

## Resultado

**Documentación verificada localmente; producto no declarado listo.** Las pruebas de build/workspace pasaron para esta revisión, pero no sustituyen los laboratorios omitidos, la aceptación Linux nativa en x86_64/AArch64, el trabajo de paquetes/actualizaciones del ticket 29 ni la revisión formal final del ticket 35. El próximo paso es cerrar esas puertas en sus frentes autorizados; este cambio solo hace explícitas las instrucciones y límites actuales.
