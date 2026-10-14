# Entrada humana pública `pm tui` — 2026-10-14

Estado: **PASS local Linux x86_64** para este correctivo. Revisión independiente y
composición con los otros workers: pendientes del integrador. macOS/Windows:
**NOT_RUN**. No declara soporte completo, cierre de tickets ni producto listo.

## Binding y alcance

Medido desde shell: worktree
`/home/santana/.t3/worktrees/passwordmanager/t3-4c708b7c`, branch
`t3/4c708b7c`, base `2f818c7dff7dcc20f227fbe1d1f7c60a9544d00b`.
El árbol inicial estaba limpio. La autorización actual permite únicamente esta
entrada existente; [decisions.md](../../decisions.md) 1A/2A no concede autoridad UI.
Contrato: [spec §11/§15](../../.scratch/passwordmanager/spec.md),
[identidad §7](../design/agent-identity.md#7-wireclimcp-v1) y
[aislamiento](../design/isolation.md).

Cambios exclusivos: `crates/pm-cli/src/lib.rs`, nuevos
`crates/pm-cli/tests/chef_human_entry.rs` y `chef_human_entry_lab.py`, únicamente
`crates/pm-custody/src/lib.rs` como puente, y este documento. Ningún manifiesto,
lockfile, archivo vecino del custodio, crypto/native-channel, CLI/MCP compartido,
spec, decisión, ticket o guía anterior se modifica. Sin push, PR, instalación,
descarga, runner hospedado, servicio externo ni credencial real.

## Causa y correctivo

**Medido:** antes del cambio, una bóveda sintética, perfiles/claves válidos y
custodio ordinario ya activos no bastan: el comando público humano con PTY termina
en exit 3, `error: UNAUTHORIZED`, antes de `Password required`.

**Inferido del código:** `pm_cli::run` enviaba `tui` a `delegated`, donde se
rechazaba incondicionalmente. No era un fallo de compilación ni un error de clave.
Hipótesis discriminadas: dispatch incorrecto (confirmada); fixture inválido y
TUI inaccesible (refutadas por el mismo recorrido después del cambio).

`pm_cli::run` reconoce solo el prefijo exacto `tui`. API aditiva:
`pm_custody::human_tui(&[OsString]) -> Result<(), HumanTuiError>`;
`HumanTuiError::exit_code()` y `Display` exponen categorías fijas, conservando
`CLEANUP_FAILED` cuando el fallo original contiene limpieza fallida.
El puente construye internamente el comando fijo `tui` y llama al entrypoint
nativo existente en el mismo proceso. No acepta elegir un comando de custodia,
ni busca/ejecuta otro binario, shell, PATH o alternativa de transporte.

**Inferido y conservado:** hardening Unix antes de leer claves; configuración
macOS del entrypoint; parser TUI original con orden/límites exactos; lectura de
perfil humano instalado y clave privada con ownership/permisos; TTY nativo;
verificación bilateral UID/SID, RPK y ALPN; desbloqueo y operaciones humanas del
custodio; guard de restauración terminal. Los argumentos nombran recursos, no
confieren rol. La selección del canal nunca copia un secreto.
`--json` en la entrada humana devuelve `UNAUTHORIZED`/3 antes del TUI; argumentos
inválidos devuelven `INVALID_ARGUMENT`/2 sin pasar al delegado. No se añadió help
ni se reescribió el parser/transporte.

Uso Linux/macOS existente, con valores ilustrativos **sintéticos** (todos los
pares son obligatorios y van en este orden):

```text
pm tui --profile /synthetic/human.profile --private /synthetic/human.key --socket /synthetic/human.sock --idle-seconds 300 --reveal-seconds 15 --copy-seconds 30
```

El parser Windows existente usa `--vault-id` en vez de `--socket`; no se ejecutó
en esta entrega. Los máximos siguen 300/15/30 y el mínimo 1 segundo, sin relajarlos.

## Evidencia conductual

**Medido:** harness final idéntico sobre binarios propios del base y del candidato:

- RED: exit 1 del harness, assertion `('Password required', 3, 'error: UNAUTHORIZED…')`.
  No fallo de build. El CLI base fue preservado desde el build previo al cambio,
  dentro del fixture propio `/tmp/pm-chef-human-8t41jz_8/pm`.
- GREEN: exit 0; PTY 80×24 observa prompt real de contraseña enmascarada, desbloqueo
  humano TLS/RPK, búsqueda nativa, `Organization committed` por teclado, lock y
  salida 0. Compara termios antes/después y observa salida de pantalla alterna y
  restauración del cursor. No sustituye UI por CRUD.
- Agente real UID 3 con perfil/clave propios y TTY: exit 4, sin prompt humano.
  UID agente + perfil humano público + clave propia: prompt pero ningún unlock,
  exit 4. UID humano + RPK agente: ningún unlock, exit 4.
- Perfil con UID servidor equivocado, pin servidor equivocado, perfil/clave
  ausentes y endpoint ausente: cierre por categoría fija, sin sesión desbloqueada.
  Las fallas posteriores a abrir el terminal también restauran termios/pantalla.
- Configuración humana correcta + `--json`: stdout vacío, `UNAUTHORIZED`/3.
- CLI delegado antes/después: discovery, status/cancel de ID inexistente por canal
  nativo mantienen exactamente JSON/exits. Capabilities mantiene salida idéntica;
  **inferido:** esa operación ya es estática en `AgentEngine::call`, no acredita
  conexión nativa. El error JSON `NOT_FOUND` conserva el exit/stderr heredado 4.
- Nuevas pruebas Rust: argumentos humanos inválidos, JSON en ambas posiciones,
  reveal/export/sign rechazados y llamadas MCP a operaciones humanas `NOT_FOUND`.
  Las pruebas existentes conservan las cinco tools, JSON, version y vault create/open.

No se usó clipboard, Wayland real, navegador ni terminal del propietario. El
harness crea un namespace multi-UID y devpts/PTY privados; borra variables de
desktop del entorno de sus procesos. Capturas VT acotadas a 256 KiB por terminal,
con texto sintético; el lector de pantalla decodifica cursor/repaint para las
assertions, sin atribuirle cobertura de emulador general.

## Comandos y resultados

Todo Cargo/build/lab bajo `flock /tmp/pm-cargo-window.lock` bloqueante. Toolchain
fijo del root y target exclusivamente propio; `--locked --offline`, sin clean.

```bash
export RUSTUP_HOME=/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/rustup
export CARGO_HOME=/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/cargo
export PATH="$CARGO_HOME/bin:$PATH"
export RUSTUP_AUTO_INSTALL=0
export CARGO_TARGET_DIR="$PWD/.scratch/chef-cli-human-entry/target"
flock /tmp/pm-cargo-window.lock cargo build -p pm-cli -p pm-custody --locked --offline
flock /tmp/pm-cargo-window.lock cargo test -p pm-cli --locked --offline
flock /tmp/pm-cargo-window.lock sh scripts/check.sh
flock /tmp/pm-cargo-window.lock unshare --user --mount \
  --map-users 0:1000:1 --map-users 1:100000:65535 \
  --map-groups 0:1000:1 --map-groups 1:100000:65535 \
  env PYTHONDONTWRITEBYTECODE=1 python3 crates/pm-cli/tests/chef_human_entry_lab.py \
  "$CARGO_TARGET_DIR/debug/pm-custody" "$CARGO_TARGET_DIR/debug/pm" \
  "$PWD/.scratch/chef-cli-human-entry/replay-unique"
```

**Medido:** build exit 0; `cargo test -p pm-cli` 9 tests PASS; `scripts/check.sh`
ejecutado una vez, exit 0 (config/build-input gates, fmt, check, tests y clippy).
Las cifras de este check no acreditan los laboratorios completos 52 ni composición
de hermanos. Para RED se ejecutó el mismo comando de namespace con los binarios
propios `/tmp/pm-chef-human-8t41jz_8/{pm-custody,pm}`. El directorio de evidencia
debe ser nuevo en cada ejecución; no se sobrescribe.

Evidencia local no versionada en `.scratch/chef-cli-human-entry/`:
`red-complete.log`, `red-complete/resources.json`, `green-complete.log`,
`green-complete/{human.vt,human-screens.txt,terminal-*.vt,resources.json}` y
`check.log`. Los ledgers registran hashes de los binarios usados y retención
de fixtures sintéticos. GREEN: custodio SHA256
`9a5c642cbff472053d5ce5fa95ccbd26d08e0d0fee2490fc478ecfd9694e0d29`,
CLI `15444dd3885a80b186687b3f4f4811fd98ba003b78d1862cfff400398d0c004e`.
RED CLI `97a0644d1309b72edc25e6ff321be9c280649826903043653e8c276bc73350d8`.

Recursos propios: target/logs permanecen en ese worktree. Los fixtures se retienen
en `/tmp/pm-chef-human-*` según los ledgers; daemons detenidos y PTYs cerrados en
RED/GREEN finales. El primer intento de retención falló por rename entre
filesystems después de detener el daemon; su raíz propia
`/tmp/pm-chef-human-j30_o48m` también se conserva. No se eliminó ni sobrescribió
un artefacto ajeno. La comprobación final de procesos con prefijo propio no
encontró procesos activos. Un intento temprano ya abrió la TUI pero no pudo
cambiar ownership del PTY del host; el devpts privado corrigió el fixture sin
relajar identidad del producto.

## Inventario heredado y límites

**Inferido, sin modificar:** `crates/pm-cli/src/lib.rs:97–102`, `delegated()` usa
`UnavailableEngine` cuando faltan las tres variables `PM_PROFILE/PM_PRIVATE/PM_SOCKET`
o tienen rutas vacías. Oculta la causa concreta bajo `CUSTODY_UNAVAILABLE`.
`AgentEngine::call` convierte errores de `agent_rpc` en la misma categoría;
`delegated()` además devuelve exit/stderr 4 para cualquier error JSON y siempre
para modo no JSON, incluso tras un RPC exitoso. Esta entrega conserva ese comportamiento.
`run_mcp():591–593` construye configuración vacía si falla el entorno, retrasando
el fallo de las operaciones delegadas. Ninguna de esas rutas se usa como alternativa
cuando falla `pm tui`. Capabilities estáticas no certifican disponibilidad nativa.

**NOT_RUN:** macOS, Windows, otras CPU, instalación, FDE/reboot, entorno humano
real, fault injection de todas las limpiezas y recorridos UI completos. La revisión
Claude y la composición exacta con el daemon/otros workers pertenecen al parent.
Los tests no certifican resistencia contra un agente que ya pueda leer archivos,
memoria o escritorio del humano: sigue vigente el perfil de aislamiento contratado.
Principios aplicados: `small-owned`, `root-cause`, `prove`, `no-fallbacks`,
`truthful-state`, `isolate`, `handoff`.
