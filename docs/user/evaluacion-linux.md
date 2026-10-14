# Evaluación local en Linux

Esta guía es solo para desarrollo y evaluación con datos sintéticos. No uses contraseñas, claves, cuentas ni archivos personales. No conectes agentes a este equipo durante la evaluación.

## Qué hay en este árbol

El código contiene una bóveda cifrada local, una TUI humana, un CLI y un adaptador MCP stdio para cinco operaciones delegadas: consultar capacidades, descubrir credenciales habilitadas y comenzar, consultar o cancelar un intento de autenticación. El agente no recibe los secretos guardados. La bóveda no gestiona las sesiones externas posteriores.

Este checkout no incluye una instalación ordinaria y autorizada del custodio. Aunque el binario `pm-custody` contiene comandos internos de servicio y provisión, no son una receta de instalación. No los ejecutes con `sudo` ni conviertas este laboratorio en un servicio persistente. Los paquetes y su mantenimiento siguen pendientes en el [ticket 29](../../.scratch/passwordmanager/issues/29-paquetes-tuf-mantenimiento-y-fuente-correspondiente.md); la aceptación Linux de instalación, reboot y volumen cifrado sigue pendiente en el [ticket 30](../../.scratch/passwordmanager/issues/30-evidencia-nativa-linux-en-dos-arquitecturas.md).

## Aislamiento y requisitos

El perfil de diseño separa tres entornos: propietario humano, proceso custodio y agente. Una cuenta distinta por sí sola no demuestra separación. Cada agente necesita su propia identidad y clave privada protegida en su entorno; no se comparte entre registros. El agente no debe leer la bóveda humana, claves maestras/de contenido/recuperación, perfiles del propietario o custodio, la TUI, el terminal humano ni su portapapeles, ni poder modificar el binario o la configuración del custodio. Este repositorio no configura ni demuestra ese aislamiento; por eso esta evaluación no conecta agentes. Consulta el [contrato de aislamiento](../design/isolation.md).

Para compilar offline se necesita el toolchain Rust 1.98.1 y las dependencias fijadas ya disponibles en el `.toolchain` compartido por la raíz Git. [`scripts/cargo-local.sh`](../../scripts/cargo-local.sh) selecciona ese toolchain local; `--locked --offline` evita cambiar el lockfile o descargar dependencias. Si el toolchain o su caché no existen, detente: esta guía no instala paquetes ni descarga artefactos.

La evidencia de laboratorio disponible es Linux x86_64. Para ejecutar el laboratorio de custodia hacen falta user namespaces habilitados, rangos `subuid` y `subgid` asignados, `unshare` y Python 3. No necesita `sudo`, Docker, cuentas nuevas ni unidades de servicio. El [preflight Linux](../verification/linux-lab-preflight.md) demuestra viabilidad de mecanismos en un host concreto; no es aceptación del producto ni un perfil de producción.

## Compilar y comprobar

Desde la raíz del checkout, con el toolchain y las dependencias ya provisionados:

```sh
./scripts/cargo-local.sh build --workspace --locked --offline
./scripts/check.sh
```

`check.sh` valida entradas de build y ejecuta `fmt`, `check`, tests y `clippy` en modo bloqueado y offline. Un resultado verde de ese comando no significa que los laboratorios de producto, la aceptación nativa o la revisión final estén verdes.

El CLI no implementa `--help`: `pm --help` devuelve `INVALID_ARGUMENT`. Para comprobar que el binario arranca sin abrir una bóveda ni usar credenciales:

```sh
./target/debug/pm --version
```

## Superficies que reconoce el código

El CLI acepta `pm vault create <archivo>` y `pm vault open <archivo>`. Son operaciones interactivas: creación solicita una contraseña maestra, muestra un código de recuperación y pide volver a introducirlo; no uses una contraseña real ni una bóveda personal para probarlas. El código de recuperación debe guardarse fuera del equipo. No lo guardes en logs, chats o documentación.

El CLI delegado reconoce `pm capabilities`, `pm credentials list`, `pm auth start`, `pm auth status`, `pm auth cancel` y `pm mcp`; admite `--json`. Las operaciones distintas de MCP aceptan referencias al perfil del agente, a su clave privada y al socket del custodio mediante `--profile`, `--private` y `--socket`. `pm mcp` obtiene esas referencias de `PM_PROFILE`, `PM_PRIVATE` y `PM_SOCKET`. Son recursos de una identidad de agente previamente autorizada; nunca pases el contenido de una clave como argumento o valor de entorno. No hay un procedimiento de provisión de producción en este árbol, así que esta guía no inventa uno ni ofrece comandos `auth` que aparenten completar una autenticación.

MCP funciona por stdin/stdout y anuncia cinco tools. Puedes comprobar únicamente el listado local con una solicitud JSON-RPC sintética; esta prueba no contacta un custodio ni demuestra que una operación delegada funcione:

```sh
pm="${CARGO_TARGET_DIR:-target}/debug/pm"
env -i PATH=/usr/bin:/bin "$pm" mcp <<'JSONL'
{"jsonrpc":"2.0","id":"synthetic-list","method":"tools/list","params":{}}
JSONL
```

La TUI existe en el binario custodio como `pm-custody tui --profile <perfil-humano> --private <clave-humana> --socket <socket-humano>`. Requiere los tres recursos de una instalación autorizada. La spec nombra `pm tui`, pero el CLI actual rechaza esa forma como `UNAUTHORIZED`; el código actual no ofrece un alias. La discrepancia se deja registrada para resolverla en el frente dueño del contrato CLI, fuera del alcance documental de esta guía. No ejecutes la TUI contra perfiles o claves personales.

## Evaluar solo con laboratorios existentes

El laboratorio existente de custodia usa un user namespace descartable y datos sintéticos:

```sh
./scripts/test-linux-custody-lab.sh
```

Lee [el contrato y la evidencia del ticket 03](../verification/ticket-03.md) antes de interpretar su salida. El runner crea temporales bajo `/tmp`; su cleanup actual usa `shutil.rmtree(..., ignore_errors=True)`, por lo que su código de salida no demuestra por sí solo que la limpieza terminó. Comprueba el prefijo temporal del laboratorio antes de considerar limpio el entorno. El script usa `target/debug/pm-custody` aunque Cargo compile a otra ruta: ejecútalo solo con el target predeterminado en un checkout desechable, sin override de `CARGO_TARGET_DIR`.

El laboratorio de contenido TUI [`test-linux-tui-content-lab.sh`](../../scripts/test-linux-tui-content-lab.sh) usa Wayland real, `wl-copy` y `wl-paste`. Puede modificar el portapapeles de la sesión; ejecútalo solo en una sesión desechable, nunca en un escritorio con datos personales. No lo necesitas para el smoke check sintético de MCP anterior.

## Backup y recuperación

- En la TUI, `b` abre el menú: `1` crea un backup nativo cifrado, `2` exporta texto legible, `3` restaura, `4` rota la contraseña maestra y `5` rota el código de recuperación. No copies la base SQLite ni sus archivos WAL/SHM como método de backup.
- El export plaintext es una copia persistente legible; protégela y elimínala explícitamente cuando corresponda. La limpieza no equivale a borrado seguro certificado.
- La restauración incorpora IDs y claves nuevos y conserva la autoridad vigente del destino. Un backup no prueba que sea el más reciente ni incluye cambios que no llegaron a ese equipo.
- Cambiar la contraseña o el código de recuperación no invalida backups antiguos ni copias expuestas. Si se pierde la vía válida de recuperación o el backup utilizable, no hay bypass.

El contrato y el alcance implementado están en los tickets [21](../../.scratch/passwordmanager/issues/21-backup-pmb1-pmf1-y-exportacion-humana.md) y [22](../../.scratch/passwordmanager/issues/22-recuperacion-rotacion-de-vias-y-compromiso.md), y en el [diseño de claves y backup](../design/key-hierarchy.md).

## Límites de la evidencia actual

El último barrido local documentado sobre `2272a1f446fb80cf35566b2b4406338a61e4f1dd` fue de 52 casos: 49 terminaron con código 0 y tres conservaron RED conocidos de G7. No es una suite verde. En el último corte nativo W7 del mismo SHA, Windows pasó `local-operations`, falló sync al plazo original de 15 s, no llegó a RETIRE y reportó fallo de cleanup; macOS Intel pasó, mientras ARM falló antes de la edición W7 durante la observación del prompt de contraseña y tuvo un timeout de 30 s en `human-streaming-file`. Los detalles y logs están en [W7](../verification/w7-vault-org.md).

Faltan los paquetes/actualizaciones, la aceptación Linux nativa en x86_64 y AArch64 y la revisión formal final; consulta los tickets [29](../../.scratch/passwordmanager/issues/29-paquetes-tuf-mantenimiento-y-fuente-correspondiente.md), [30](../../.scratch/passwordmanager/issues/30-evidencia-nativa-linux-en-dos-arquitecturas.md) y [35](../../.scratch/passwordmanager/issues/35-revision-unificada-y-cierre-verificable-de-la-especificacion.md). El código o un laboratorio local no equivalen a producto listo para producción.
