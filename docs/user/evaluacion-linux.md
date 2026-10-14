# Evaluación local en Linux

Esta guía describe una evaluación de desarrollo con datos sintéticos. No uses credenciales, claves, cuentas ni archivos personales. No conectes agentes a un equipo donde puedan leer la TUI, el terminal humano, el portapapeles, la bóveda o las claves locales.

## Qué hay en este árbol

El producto separa la bóveda cifrada, las operaciones humanas y el uso delegado por agentes. El CLI público ofrece **pm tui** exclusivamente para el propietario humano. CLI/MCP delegados exponen cinco operaciones de agente; no entregan secretos guardados ni administran las sesiones externas posteriores.

La implementación Linux fijada para esta alineación añade dos archivos locales protegidos junto a la ruta de la bóveda:

| Archivo lateral | Cabecera | Se crea con | Vínculo que valida |
| --- | --- | --- | --- |
| `<vault>.agent-registry` | Binaria **PMAR1** | **migrate-agent-registry** | Bóveda, dispositivo, clave pública exacta del servidor y pares RPK→UID |
| `<vault>.adapters` | Binaria **PMAC1** | **provision-adapters** | Bóveda, dispositivo, clave pública exacta del servidor, integración, versión, perfil, método, endpoint y UID del adaptador |

El registro local vincula una clave RPK con el principal nativo UID de Linux. No reemplaza la concesión humana vigente ni la revocación: el daemon vuelve a validar ambas durante el uso. La configuración del adaptador se resuelve desde el estado local instalado según integración, perfil/destino y método; el agente no entrega una configuración alternativa en su solicitud. El worker externo conserva su propio perfil y ciclo de vida. El daemon no crea ni supervisa el proceso del adaptador.

Estos archivos no son texto para editar a mano. El parser fija los encabezados, los campos y los flags. La lectura valida su identidad, permisos, propietario, tamaño máximo serializado de 16 KiB y estabilidad; los padres solo se aceptan bajo la cadena confiable de root o del custodio actual, con la excepción acotada del ancestro root-owned sticky. No se aprende un propietario desde / ni se añade una excepción para UID 65534. La ausencia, retirada o invalidez de configuración no activa un proveedor de laboratorio, un binding por UID solamente ni otra ruta delegada.

Este árbol todavía no proporciona una instalación ordinaria completa y verificada: no define una distribución/instalador, el ciclo de vida de un servicio del sistema ni el procedimiento aprobado para establecer la cadena de directorios y recursos nativos de un host normal. Las capacidades de provisión del binario no sustituyen esos pasos.

## Requisitos de evaluación

El perfil de diseño separa al propietario humano, al proceso custodio y al agente. Una cuenta distinta por sí sola no demuestra separación. Cada agente debe tener su identidad y clave privada protegida en su entorno, sin compartirla entre registros. El agente no debe leer la bóveda humana, claves maestras/de contenido/recuperación, perfiles del propietario o custodio, la TUI, el terminal humano ni su portapapeles, ni poder modificar el binario o la configuración del custodio. Este árbol no configura la instalación ordinaria ni demuestra ese aislamiento; la evaluación local no conecta agentes fuera de fixtures propios. Consulta el [contrato de aislamiento](../design/isolation.md).

Para compilar offline se necesita el toolchain Rust 1.98.1 y las dependencias fijadas ya disponibles en el directorio .toolchain compartido por la raíz Git. **scripts/cargo-local.sh** selecciona ese toolchain; **--locked --offline** evita cambiar el lockfile o descargar dependencias. Si el toolchain o su caché no existen, detente: esta guía no instala paquetes ni descarga artefactos.

Los laboratorios Linux documentados usan user namespaces, rangos subuid y subgid ya asignados, unshare y Python 3. El [preflight Linux](../verification/linux-lab-preflight.md) demuestra viabilidad de mecanismos en un host concreto; no es aceptación del producto ni un perfil de producción. No cambies ownership de mounts o directorios ajenos, ACLs del host ni crees un servicio privilegiado para ejecutar esta guía.

## Compilar y comprobar

Desde la raíz del checkout, con el toolchain y las dependencias ya provisionados:

    ./scripts/cargo-local.sh build --workspace --locked --offline
    ./scripts/check.sh

check.sh valida entradas de build y ejecuta fmt, check, tests y clippy en modo bloqueado y offline. Un resultado verde no significa que los laboratorios completos, la aceptación nativa, la composición exacta de candidatos o la revisión final estén verdes. Esta actualización documental no ejecuta Cargo ni laboratorios.

El CLI no implementa **--help**: **pm --help** devuelve INVALID_ARGUMENT con código 2. Para comprobar que el binario arranca sin abrir una bóveda ni usar credenciales:

    ./target/debug/pm --version

El CLI también reconoce **pm vault create <archivo>** y **pm vault open <archivo>**. Son operaciones interactivas: la contraseña maestra se lee desde el prompt, la creación muestra un código de recuperación y pide reintroducirlo. Usa únicamente rutas y datos sintéticos; guarda el código de recuperación fuera del equipo de prueba. No lo pongas en argv, logs, chats o documentación.

## Entrada humana con pm tui

La entrada pública acordada es **pm tui**, según [spec §11](../../.scratch/passwordmanager/spec.md#11-tui-importación-exportación-y-recuperación) y el [contrato de identidad/comandos](../../docs/design/agent-identity.md#9-cierre-de-comandos-humanos-y-autoridad-distribuida); no hace falta invocar **pm-custody tui**. El perfil humano, el archivo de clave privada protegida y el endpoint Unix humano deben existir y estar provisionados previamente. El orden y los flags Linux del parser son:

    pm tui --profile /synthetic/human.profile --private /synthetic/human.key --socket /synthetic/human.sock --idle-seconds 300 --reveal-seconds 15 --copy-seconds 30

Las rutas son marcadores sintéticos y el comando es una muestra de sintaxis, no un archivo de instalación. Los seis flags son requeridos en ese orden por el parser Linux fijado; los límites máximos de los tres tiempos son 300, 15 y 30 segundos. **--private** nombra un archivo protegido: nunca pongas el contenido de la clave, la contraseña maestra ni el código de recuperación en argv, variables de entorno, logs o documentación. La contraseña maestra se introduce en el prompt interactivo. El perfil debe tener rol humano, y el pin del servidor debe coincidir con el endpoint seleccionado; los flags no conceden rol ni autorización.

**pm tui --json** devuelve UNAUTHORIZED con código 3, también con recursos humanos válidos. No se expone una TUI humana por MCP ni por el modo JSON del CLI delegado. Si faltan perfil, clave, socket o identidad verificada, corrige el paso de provisión que falta: no elimines flags ni uses valores por defecto.

**Medición atribuida al worker CLI, no repetida aquí:** el harness Linux sintético observó prompt enmascarado, desbloqueo, búsqueda, commit de organización, bloqueo, salida y restauración del terminal. El worker registró nueve tests del CLI y una ejecución de check.sh con código 0. La fixture no equivale a aceptación de instalación ordinaria ni a una TUI ejecutada sobre datos reales. El informe anterior [de la guía Linux](../verification/chef-user-guide-20261014.md) mide un CLI previo que rechazaba pm tui; esa observación es histórica y no describe el candidato CLI fijado ahora. Ver [esta alineación documental](../verification/chef-guide-alignment-20261014.md).

En Windows, el parser heredado también admite **--console-diagnostics <archivo>** después de los flags comunes de TUI. El código escribe métricas/indicadores, no texto de celdas; Windows no se ejecutó para esta validación y esta nota no es evidencia nativa. Ese flag no aplica a Linux.

## Registro y adaptadores instalados

El flujo de provisión de los candidatos Linux debe distinguirse de la entrada humana. Las formas que reconoce el parser fijado son:

    pm-custody migrate-agent-registry --bootstrap /synthetic/bootstrap --vault /synthetic/vault.sqlite3 --device 11111111111111111111111111111111 --agent-public /synthetic/agent-B.pub --agent-uid 1202

La migración incorpora el par RPK/UID ya confiable del bootstrap y, opcionalmente, pares adicionales mediante argumentos repetidos **--agent-public** y **--agent-uid**. Verifica bóveda, dispositivo, clave pública exacta del servidor y que cada agente conserve una identidad/concesión humana actual. También requiere que ya exista el sidecar protegido **<vault>.audit-custody**; serve-vault lo carga o crea al arrancar, pero la migración no lo crea. Publica el registro una sola vez y no reactiva agentes revocados ni sobrescribe un archivo existente.

Después de crear el registro se puede fijar una ruta de adaptador con la forma:

    pm-custody provision-adapters --bootstrap /synthetic/bootstrap --vault /synthetic/vault.sqlite3 --device 11111111111111111111111111111111 --integration github-rest-bearer --profile github-assigned-issues/1 --method bearer --endpoint /synthetic/github-adapter.sock --adapter-uid 1203

Los valores identifican una integración/perfil/método sintéticos; no son credenciales. La versión de integración que serializa este parser es 1; no se pasa un flag de versión. El endpoint debe ser absoluto y pertenecer al UID del adaptador. El UID del adaptador no puede reutilizar el principal humano, el agente bootstrap ni otro UID de agente. El daemon valida el endpoint y su peer nativo antes de enviar una operación; la ruta no inicia el proceso externo.

El uso normal requiere, además, que el propietario de la instalación prepare de forma segura bootstrap, bóveda, dispositivo, registro, grants, perfiles y claves, rutas de sockets y ciclo de vida del servicio. El parser del servicio Linux **serve-vault** requiere, en este orden, **--bootstrap**, **--agent-socket**, **--human-socket**, **--vault** y **--device**, pero este árbol no ofrece un servicio del sistema o instalador aceptado que establezca esos recursos y sus propietarios. Por ello, los ejemplos anteriores documentan el parser y los límites de configuración; no son instrucciones para ejecutar con sudo en un host personal. No afirmes que el bootstrap único A+B deja listos el registro por agente y los adaptadores: la migración verificada y la provisión de cada adaptador son pasos distintos.

## CLI delegado y MCP sintético

El CLI delegado reconoce **pm capabilities**, **pm credentials list**, **pm auth start**, **pm auth status**, **pm auth cancel** y **pm mcp**. Las operaciones CLI aceptan referencias al perfil del agente, su clave privada y el socket custodio mediante **--profile**, **--private** y **--socket**; pm mcp obtiene esas rutas desde **PM_PROFILE**, **PM_PRIVATE** y **PM_SOCKET**. Son rutas a recursos de una identidad previamente autorizada, no el contenido de una clave. Estas referencias de transporte no sustituyen el registro instalado RPK→UID, los grants humanos ni la revocación.

MCP funciona por stdin/stdout y anuncia cinco tools. Esta consulta JSON-RPC sintética solo lista la superficie local; no contacta un custodio ni prueba una operación delegada:

    pm=./target/debug/pm
    env -i PATH=/usr/bin:/bin "$pm" mcp <<JSONL
    {"jsonrpc":"2.0","id":"synthetic-list","method":"tools/list","params":{}}
    JSONL

La respuesta contiene **get_capabilities**, **discover_credentials**, **start_authentication**, **get_authentication** y **cancel_authentication**. No publiques ni solicites tools administrativas o humanas por MCP.

## Laboratorios sintéticos

El laboratorio existente de custodia usa un user namespace descartable y datos sintéticos:

    ./scripts/test-linux-custody-lab.sh

Lee el [contrato y la evidencia del ticket 03](../verification/ticket-03.md) antes de interpretar su salida. El wrapper usa target/debug/pm-custody; ejecútalo solo con el target predeterminado en un checkout descartable y sin override de CARGO_TARGET_DIR. El test histórico limpia algunos temporales con ignore_errors=True, así que su código de salida no acredita por sí solo la limpieza.

El laboratorio de contenido TUI **scripts/test-linux-tui-content-lab.sh** usa Wayland real, wl-copy y wl-paste, y puede modificar el portapapeles de la sesión. No lo ejecutes en un escritorio con datos personales.

**Fixture nueva 1A/2A, evidencia atribuida al worker daemon:** los casos registry y adapter del runner **crates/pm-custody/tests/chef_runtime_chroot.py** se ejecutaron dentro de un namespace UID-mapped propio, con custodia en un chroot UID 0 propio y cliente/TUI humano fuera en PTY. Cuando los archivos de los candidatos fijados estén presentes en el checkout, el runner se puede repetir con binarios propios, un target privado y los prerrequisitos del preflight:

    export CARGO_TARGET_DIR="$PWD/target-chef-daemon-implementation"
    export RUSTUP_AUTO_INSTALL=0
    flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh build -p pm-custody -p pm-cli -p pm-web-auth --example chef_runtime_open_channel --bins --locked --offline
    BIN="$CARGO_TARGET_DIR/debug"
    python3 crates/pm-custody/tests/chef_runtime_chroot.py registry "$BIN/pm-custody" "$BIN/pm" "$BIN/pm-web-auth"
    python3 crates/pm-custody/tests/chef_runtime_chroot.py adapter "$BIN/pm-custody" "$BIN/pm" "$BIN/pm-web-auth"

El runner debe ejecutarse dentro de un namespace UID-mapped propio con los rangos ya asignados que exige el [preflight Linux](../verification/linux-lab-preflight.md). La fixture crea su chroot de evaluación; no es un instalador, servicio normal, aceptación de sistema de archivos raíz productivo ni evidencia de que la instalación cotidiana esté lista. No cambies ownership ni ACL de mounts del host. Esta actualización documental no compiló ni ejecutó estos comandos.

## Backup y recuperación

- En la TUI, **b** abre el menú: **1** crea un backup nativo cifrado, **2** exporta texto legible, **3** restaura, **4** rota la contraseña maestra y **5** rota el código de recuperación. No copies la base SQLite ni sus archivos WAL/SHM como método de backup.
- El export plaintext es una copia persistente legible; protégela y elimínala explícitamente cuando corresponda. La limpieza no equivale a borrado seguro certificado.
- La restauración incorpora IDs y claves nuevos y conserva la autoridad vigente del destino. Un backup no prueba que sea el más reciente ni incluye cambios que no llegaron a ese equipo.
- Cambiar la contraseña o el código de recuperación no invalida backups antiguos ni copias expuestas. Si se pierde la vía válida de recuperación o el backup utilizable, no hay bypass.

El contrato y el alcance implementado están en los tickets [21](../../.scratch/passwordmanager/issues/21-backup-pmb1-pmf1-y-exportacion-humana.md) y [22](../../.scratch/passwordmanager/issues/22-recuperacion-rotacion-de-vias-y-compromiso.md), y en el [diseño de claves y backup](../design/key-hierarchy.md).

## Estado y evidencia pendiente

**Medición local Linux atribuida a los workers:** la entrada humana de CLI mostró el flujo TUI descrito arriba; el candidato daemon midió registro, adaptadores sintéticos, revocación y reconciliación. Estas ejecuciones usaron fixtures propias. No se compusieron aquí los SHAs hermanos ni se ejecutó el vector completo.

**Estado de composición registrado por el coordinador:** el lote sigue parcial; batchAccepted e integrationExecuted son falsos. Windows y macOS nativos están NOT_RUN. El consumidor Windows ordinario de registro/adaptadores sigue incompleto. La compatibilidad de ACL/ubicación de configuración Windows continúa como hipótesis inferida y no se valida por proponer una ruta alternativa; la propuesta de configuración pública bajo ProgramFiles tampoco tiene prueba nativa. No se afirma soporte de Windows o macOS. El [estado consolidado de spec §15](../../.scratch/passwordmanager/spec.md#15-estado-consolidado-acuerdos-cierres-de-diseño-y-validación) sigue siendo la fuente global.

La aceptación nativa hospedada continúa pendiente de la decisión del propietario 3. La intención preparada durable y el cierre de esquema G7 continúan pendientes de la decisión del propietario 4. Revisa el [método CI nativo efímero](../verification/native-ci.md) antes de preparar runners; su disponibilidad no acredita soporte. No se cierran tickets ni se declara producto listo, aceptado para instalación o certificado en seguridad.

La guía conserva límites y comandos útiles del corte anterior, pero la comparación histórica con SHA 2272a1f446fb80cf35566b2b4406338a61e4f1dd y los resultados W7 ya no se presentan como estado actual. Los tickets [29](../../.scratch/passwordmanager/issues/29-paquetes-tuf-mantenimiento-y-fuente-correspondiente.md), [30](../../.scratch/passwordmanager/issues/30-evidencia-nativa-linux-en-dos-arquitecturas.md) y [35](../../.scratch/passwordmanager/issues/35-revision-unificada-y-cierre-verificable-de-la-especificacion.md) conservan las puertas de distribución, aceptación Linux multi-arquitectura y revisión unificada.
