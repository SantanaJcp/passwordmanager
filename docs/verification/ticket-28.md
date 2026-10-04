# Ticket 28 — método de fallos operativos, canarios y crash safety

## Windows G7 — W5: diagnóstico nativo de cuota (2026-10-03)

Worktree aislado `w5-win-memory`, rama `codex/pm-w5-win-memory`, base
`893074af5192217d313fce12ea81ca3351aa22ea`. Alcance autorizado: allocator
protegido, cuota al arrancar Windows y owners del preview si se demuestra
agotamiento del presupuesto. Sin integración ni cambios de estado de tickets.

Método previo al código: instrumentar únicamente fallos de alloc/budget/mlock
Windows y el estado inicial del proceso. Registrar categoría, capacidad
solicitada/vigente, presupuesto de 32 MiB, regiones vigentes, bytes de páginas
del payload bloqueado, GetLastError capturado inmediatamente y working set
mínimo/máximo/flags. El contador de páginas de payload es un límite inferior:
`sodium_malloc` también intenta bloquear el canario; no confundirlo con todo el
working set ni con una medición del overhead interno. Sin contenido, direcciones,
handles, identidades, paths de secretos o stack traces.

El probe enfocado independiente de ConPTY ejecutará el servicio normal con
diagnóstico explícito y el mismo seed de ocho registros/tipos7 de ticket27,
por el wire humano autenticado, seguido del 1PUX sintético del harness
(adjunto 2097159 bytes). Usará las APIs existentes de transferencia y restauración
sin modificarlas. El modo normal conserva todas sus aserciones y pasos; el
modo enfocado no acredita TUI ni aceptación integral. Se exige preview exitoso,
conteos exactos y cancelación del preparado sin importar; un error sigue RED.

Prerrequisitos: método [CI efímero](native-ci.md), runner estándar Windows11
ARM64, Rust1.98.1 y libsodium1.0.22 autenticados, compilación offline, identidades
reales separadas y cleanup estricto existentes. Hasta cinco dispatches autorizados
del workflow `Ticket 27 Windows custody`, cada uno sobre SHA exacto W5 y con
hipótesis/cambio distinto. Soltar flock mientras se espera CI.

RED de referencia: [37134445641](https://github.com/SantanaJcp/passwordmanager/actions/runs/37134445641),
SHA `1c490764c0cf2dae44d996243351d24101b90918` (W1), `crypto-resource` en
preview tras validar/duplicar el descriptor y con lease restaurada. No mide
VirtualLock ni demuestra su causa. El probe nuevo discriminará cuota nativa
frente al presupuesto agregado o un fallo de asignación.

Si la cuota es causal, antes de implementar se devolverá la decisión concreta
sobre mínimo/máximo/margen/flags, todavía no fijada por G7. El rechazo del SO
debe detener explícitamente el arranque; nunca desbloquear memoria, reducir KDF,
aumentar el presupuesto o reintentar con otra política.

Gates locales autorizados: `check.sh`, `clean-offline-build.sh` y, al tocar código
compartido, los 52 casos/49 rc0 de integración, comparados por comando y rc.
Cada Cargo/check/lab bajo `flock /tmp/pm-cargo-window.lock`, cwd W5 y artefactos
Keycloak/CFT fijados por el despacho. Logs propios `/tmp/pmw5-*.log`. Sólo Linux
cfg observado localmente; Windows queda acreditado exclusivamente por su run.

Fallbacks heredados inspeccionados y conservados: `WindowsServerPipe::drop`
descarta CloseHandle; creación de pipe/DPAPI/SID descarta ciertos LocalFree;
`ClipboardWindow::drop` descarta DestroyWindow. Si la liberación falla, se
oculta su error y se conserva el resultado previo. `sodium_malloc` de libsodium
ignora internamente su primer mlock; el producto exige después sodium_mlock
comprobado antes de colocar el secreto, como ya prevé G7. Ninguno se corrige
ni se atribuye como causa sin evidencia.

### Reanudación y primer checkpoint

Tras el reinicio se preservaron los diez archivos heredados. `git status`,
diff completo y los tres archivos nuevos se inspeccionaron antes de editar;
`gh run list --branch codex/pm-w5-win-memory` no encontró corridas previas.
La rama no tenía commits propios. La referencia W1 se descargó de nuevo en
`/tmp/pmw5-reference-w1-red.log`, SHA y conclusión comprobados por API.

Se corrigió un hueco de observación: el listener heredado descarta el error de
una conexión y continúa (zona W4, conservado). Por tanto, registrar memoria
sólo al terminar el servicio no observa el fallo de preview. Ahora el opt-in
registra su snapshot de memoria junto al resultado del preview, sin cambiar
listener, transferencia ni lease. El probe exige los siete conteos exactos
`2/2/0/0/0/4/1`; ya no basta que campos preservados/páginas sean positivos.
El test nativo independiente de presupuesto se ejecuta incluso con preview
RED; ambos exit codes deben ser cero para declarar GREEN.

Primer gate: `flock /tmp/pm-cargo-window.lock sh -c
'./scripts/cargo-local.sh fmt --all && ./scripts/check.sh'`, rc0,
`/tmp/pmw5-checkpoint-check.log`. Incluye fmt/check/test/clippy del workspace
locked/offline. `flock /tmp/pm-cargo-window.lock
./scripts/clean-offline-build.sh` también terminó rc0, compilación 42.49 s,
`/tmp/pmw5-checkpoint-clean.log`. El YAML del workflow carga con el parser disponible y conserva
trigger manual, runner estándar ARM64, contents:read y ausencia de
caches/artifacts/secrets. Este gate sólo ejecuta cfg Linux, no acredita aún
compilación ni comportamiento Windows.

Fuentes primarias consultadas al reanudar:
[VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock),
[SetProcessWorkingSetSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsizeex)
y [libsodium 1.0.22 utils.c](https://github.com/jedisct1/libsodium/blob/1.0.22/src/libsodium/sodium/utils.c).
VirtualLock tiene una cuota relacionada con el mínimo del working set menos
overhead; esto sustenta la hipótesis, no sustituye el RED nativo. El código
fijado de sodium_mlock Windows devuelve directamente el resultado de
VirtualLock: GetLastError se captura antes de cleanup. Las páginas de canario
que bloquea internamente sodium_malloc siguen fuera del contador de payload.

## Frontera y prerrequisitos

Este método prueba Linux x86_64 en un `user namespace` desechable con UIDs
separados, procesos y SQLite reales. No modifica límites, mounts, dump policy ni
servicios del host: los límites `rlimit`, el `tmpfs` finito y cualquier proceso
que se detiene o mata pertenecen al namespace y directorio temporal del lab.
Los puertos nativos repiten esta evidencia en 30–32; este ticket no los declara
validados. La guarda de proceso de este tracer es una API Unix explícita;
Windows G7 (VirtualLock y WER/LocalDumps) sigue **no implementado** y no existe
una función genérica que devuelva éxito sin instalar controles. Todos los
secretos son canarios sintéticos identificables.

Antes de ejecutar Cargo, build o labs, root concede una ventana Linux local
exclusiva. Se fijan el toolchain y artefactos ya aprobados; no se instalan
dependencias, no hay red y no se cambian Argon, deadlines o backoffs. Cada
vertical TDD se ejecuta RED una sola vez contra el seam público indicado, se
conserva su log y sólo después se implementa el mínimo GREEN.

## Seams y resultados observables

1. **Admisión del proceso y memoria protegida.** `pm vault create` y
   `pm-custody serve-vault` son procesos públicos. Antes de recibir material
   secreto deben fijar core soft/hard a cero y `PR_SET_DUMPABLE=0`. El lab
   demuestra primero que el padre puede `ptrace` a un hijo control sin esa
   protección y después exige `EPERM` para cada binario sujeto; inspecciona
   `/proc/<pid>/limits`. Mientras la creación mantiene raíces vivas entre las
   confirmaciones, `VmLck` debe ser no cero. Otro hijo con `RLIMIT_MEMLOCK=0`
   debe fallar cerrado antes de publicar recovery, bóveda o secreto, sin usar
   memoria desbloqueada. Las regiones propias tienen presupuesto agregado de
   32 MiB; alloc/mlock/protección fallidos son `RESOURCE_UNAVAILABLE` y nunca
   reducen KDF o cambian de allocator.
2. **Atomicidad y disco real.** Un volumen `tmpfs` privado y finito fuerza
   `ENOSPC` en staging/WAL/commit/auditoría/outbox. Se comparan conteos,
   authority frontier, recibos y hashes antes/después: o existe el commit
   íntegro con receipt durable, o no existe ninguna de sus partes. Un crash
   `SIGKILL` se inyecta sólo después de observar WAL/staging real y se reinicia
   el mismo vault. Nunca se publica éxito ficticio, se borra evidencia de
   autoridad ni se reenvía un login; intención sin resultado reaparece
   `INDETERMINATE`. Fallos de `fsync` se inyectan en el syscall real del proceso
   mediante un interposer compilado del fixture, limitado por PID/path y
   contador explícitos; no es callback del motor. Cada frontera se ejecuta en
   un vault nuevo, sin retry oculto.
3. **Reloj, capacidad y pérdida de custodia.** Por la API real de intentos, un
   rollback mayor que la tolerancia devuelve `CLOCK_UNTRUSTED`; 17 intentos
   vivos del mismo agente devuelven `RATE_LIMITED` en el 17.º y conservan
   exactamente 16, mientras otros estados/autoridad no mutan. Retirar o hacer
   ilegible bootstrap, audit custody o vault detiene nuevas admisiones con
   `CUSTODY_UNAVAILABLE`; no fabrica claves, abre otra revisión ni repite un
   proveedor. La restauración exacta del fixture permite reiniciar y observar
   la autoridad previa, no una alternativa reconstruida.
4. **Canarios activos e históricos.** Durante ejecución y tras error/crash se
   escanean, con el custodio quiescente cuando SQLite pueda rotar sidecars:
   stdout, stderr, logs, errores públicos, `/proc/<pid>/{cmdline,environ}`,
   temporales propios, DB/WAL/SHM, staging, audit y core/crash artifacts. Desde
   UID agente se prueban además archivos, `process_vm_readv`/ptrace y recursos
   de agente. El canario nunca aparece fuera del ciphertext esperado; una
   lectura truncada o inventario incompleto falla la prueba, no demuestra
   ausencia. El lab enumera explícitamente cada canal y no borra artefactos
   antes de escanearlos.

## Cleanup y criterio de éxito

Cada lab registra PID, mount y raíz propios; en `finally` reanuda cualquier PID
pausado, termina sólo sus hijos, desmonta sólo su `tmpfs`, elimina estrictamente
su raíz e informa todas las fallas agregadas. Ningún `ignore_errors`, barrido
por patrón, señal por nombre o cleanup omitido puede preceder un `PASS`.

Tras los GREEN enfocados deben pasar, en este orden: `git diff --check`,
`scripts/check.sh`, `scripts/clean-offline-build.sh`, el nuevo lab y una única
barrida secuencial de todos los `scripts/test-linux-*-lab.sh`, con contador y
exit propagado. Se conservan logs por lab y no se reintenta una operación dentro
de una aserción. Éxito requiere cero fallos, cero procesos/residuos propios y
todos los canales de canario completos. La evidencia no es auditoría externa,
no acredita administradores/kernel ni sustituye 30–34.

## Fallbacks heredados con corrección acotada autorizada

- `pm-process-runner::TemporaryDirectory::drop` descarta el error de
  `remove_dir_all`; puede dejar un directorio de evidencia aunque la observación
  ya fue devuelta.
- `pm-custody` descarta fallos al retirar la privada si `keygen` no publica su
  pública, al retirar `.partial` después de fallo de descarga y al retirar un
  archivo nuevo después de fallo de write/fsync.

Esos cuatro fallbacks se informaron antes de tocar código y el usuario autorizó
explícitamente su corrección el 2026-09-14. Se abordarán en un vertical separado
después de stdin: error primario más cleanup, path owned, un solo intento y sin
ruta sustituta. La autorización es sólo para esos cuatro lugares, no una
autorización global de cleanup. `persist_new` ya se corrigió en el cambio
separado compuesto y este ticket no duplica esa edición.

## Evidencia TDD en curso

El primer intento, conservado en `/tmp/pm28-red-process-security.log`, no cuenta
como RED de producto: el control `sleep` quedó detenido tras `PTRACE_DETACH` y
el cleanup agotó sus 8 segundos. El harness se corrigió enviando `SIGCONT` al
PID exacto, sin señales por patrón ni fallback. La siguiente ejecución
`/tmp/pm28-red-process-security-2.log` terminó rc 1 en el seam correcto: el
control positivo aceptó attach/detach y demostró que el namespace permitía la
observación, `pm vault create` llegó al primer prompt real, y falló al exigir
`Max core file size` soft/hard `0/0`. Por tanto el `EPERM` posterior no se usa
todavía como prueba ni se atribuye a Yama. La causa observada es que el cliente
humano no instala `RLIMIT_CORE=0` antes de aceptar material secreto; no fue un
fallo de compilación o dependencia. Tras este RED se liberó la ventana Linux.

El primer GREEN Unix centraliza las claves propias de 32 bytes en memoria
obtenida por `sodium_malloc`, exige `sodium_mlock`, aplica un presupuesto
agregado de 32 MiB y limpia/libera con `sodium_memzero`/`sodium_free`. El cliente
humano y custodio llaman la guarda Unix antes de procesar argumentos secretos;
la API no existe en Windows. La primera ejecución posterior demostró que root
del user namespace podía ignorar dumpability con `CAP_SYS_PTRACE`, por lo que no
se aceptó. El harness ahora crea/copía su binario como namespace-root y baja de
forma irreversible a UID1 antes de los controles: su hijo control admite ptrace
y el sujeto protegido lo rechaza. Dos fallos intermedios por proceso control
detenido y `/proc/environ` denegado fueron defectos del harness conservados, no
fallos de producto ni retries de una operación de autenticación.

El resultado aceptado `/tmp/pm28-green-process-security-4.log` terminó rc 0 en
2 segundos con `core=0 dumpable=0 locked-secrets=1 memlock-denial=closed` y
cleanup verificado. `pm-crypto` completo pasó en 13 segundos
(`/tmp/pm28-green-crypto-2.log`), `scripts/check.sh` pasó en 103 segundos
(`/tmp/pm28-first-vertical-check.log`) y el build limpio locked/offline pasó en
40 segundos (`/tmp/pm28-first-vertical-clean.log`).

Este GREEN es deliberadamente parcial: `VmLck>0` y la denegación con memlock=0
prueban el constructor central de raíces/claves, no que todos los buffers
plaintext propios hayan sido migrados. Tampoco implementa VirtualLock/WER de
Windows, evidencia macOS, fault injection fsync/WAL/disco, crash de intentos,
ni la matriz completa de canarios. Esos criterios permanecen abiertos y este
checkpoint no resuelve 28.

## Segundo vertical preparado: buffers plaintext propios

El inventario estático encuentra material propio todavía protegido sólo por
`Zeroizing<Vec<u8>>`, no por memoria bloqueada:

- `pm-cli`: password/confirmación/recovery leídos por `read_limited_line` antes
  de entrar al boundary criptográfico;
- `pm-custody`: password humano, token, requester secret, claves SSH,
  passphrases, records/frames abiertos y requests temporales;
- `pm-vault`: leases de password/token/SSH, auth serializado, chunks de
  backup/attachment/import y plaintext de revisiones;
- adaptadores `pm-web-auth` y `pm-ssh-client`: secretos ya entregados dentro de
  su proceso confiable, además de heaps internos de TLS/russh explícitamente
  fuera de la garantía completa G7.

El siguiente RED acota primero la entrada humana: con `RLIMIT_MEMLOCK=0`, tras
enviar sólo la primera línea a `pm vault create`, el proceso debe devolver
`RESOURCE_UNAVAILABLE` **antes** de imprimir `Confirm master password`. La
ejecución conservada en `/tmp/pm28-red-plaintext-buffer.log` terminó rc1 en 3 s:
la variante previa llegó a esa confirmación y sólo falló por EOF
(`unexpected end of input`), discriminando el buffer `Vec` desbloqueado de las
claves centrales ya cubiertas. El GREEN creará
un buffer opaco de longitud variable en el mismo allocator/budget protegido,
consumirá y limpiará el `Vec` de entrada, no implementará `Clone`, `Debug`,
`Display` o serialización, y migrará verticalmente cada frontera pública con un
RED propio. No se afirmará cobertura completa hasta inventariar y ejercitar
todos los grupos anteriores; TLS/russh/browser/Argon mantienen los límites
documentados, no se renombran como memoria protegida.

El checkpoint GREEN preparado consume una lectura temporal
`Zeroizing<Vec<u8>>` y la transfiere a memoria bloqueada antes del siguiente
prompt. Eso acota la vida y garantiza limpieza del buffer ordinario, pero no
prueba entrada directa en memoria bloqueada: durante `read_until` la primera
línea todavía reside brevemente en heap no bloqueado. Un vertical posterior
debe preasignar/proteger el destino antes de leer bytes, sin alterar prompts ni
formato público, antes de atribuir cumplimiento estricto G7 a la entrada.

El GREEN de este checkpoint está conservado en
`/tmp/pm28-green-plaintext-buffer.log`: terminó rc0 en 3 s, mantuvo positivo el
control ptrace, rechazó memlock=0 antes de confirmación y verificó cleanup. Las
suites enfocadas terminaron rc0 para `pm-crypto`
(`/tmp/pm28-green2-pm-crypto-2.log`) y `pm-cli`
(`/tmp/pm28-green2-pm-cli.log`). Antes de esas ejecuciones, el primer comando
enfocado no llegó a compilar porque `Cargo.lock` omitía la dependencia workspace
`zeroize` recién declarada (`/tmp/pm28-green2-pm-crypto.log`, rc101); se conserva
como fallo de bookkeeping, no como RED conductual. La corrección sincronizó sólo
esa entrada. Además, `LockedKey` reutiliza un allocator privado desde su array de
stack y lo limpia en éxito o error, sin introducir una copia `Vec` desbloqueada.

## Tercer vertical preparado: entrada directa protegida

El checkpoint anterior reserva memoria protegida sólo después de completar
`read_until`, así que no satisface todavía la entrada directa de G7. El próximo
RED inicia `pm vault create` con `RLIMIT_MEMLOCK=0`, mantiene abierto su stdin y
no envía ningún byte. Tras el primer prompt, el proceso debe fallar cerrado como
`RESOURCE_UNAVAILABLE` dentro del plazo ya acotado del fixture. La variante
actual permanece esperando entrada: ese timeout demuestra que intenta leer
antes de reservar/bloquear el destino, no un fallo de credencial o dependencia.

La ejecución `/tmp/pm28-red-direct-protected-input.log` reprodujo exactamente
ese RED una vez: build correcto y rc1 en 7 s; el hijo mantuvo stdin abierto sin
recibir bytes, agotó los 3 s del fixture y falló con `client read stdin before
reserving its protected input destination`. El `finally` verificó cero procesos
y raíces propias antes de liberar la ventana.

El GREEN preasignará el destino nativo protegido antes de la primera lectura y
leerá en su capacidad mediante `Read`, sin un `BufRead` propio intermedio. Debe
conservar exactamente: aceptación de LF, retirada de un único CR antes de LF,
aceptación de EOF tras al menos un byte, rechazo de EOF vacío y rechazo sobre el
límite. Las regresiones enfocadas comparan sólo booleanos y errores públicos,
sin imprimir el material sintético. Este vertical no amplía la garantía a los
buffers internos de stdio/OS ni a librerías de terceros permitidos por G7 §2.1,
y tampoco reescribe Argon, TLS, russh o browser.

El GREEN estático posterior reserva y bloquea `maximum + 2` bytes inicializados
antes del primer `Read`, lee cada byte directamente en esa región para no
consumir parte de la línea siguiente y limpia inmediatamente el sufijo retirado.
El owner conserva capacidad separada de longitud para limpiar/liberar y cargar
el presupuesto completo incluso después de truncar. No se ejecutó todavía.

El checkpoint compilado prueba solamente que el buffer **propio** de destino se
reserva y bloquea antes de invocar `Read`; el caller aún usa `stdin.lock()` y
`StdinLock` puede precargar plaintext en su `BufReader` interno. Por tanto no se
afirma todavía protección integral desde stdin. El siguiente vertical debe leer
del handle nativo sin buffer en cada plataforma, preservando terminal y pipe y
sin ruta sustituta; no se crea una excepción nueva para stdio.

Evidencia enfocada: `pm-crypto` rc0
(`/tmp/pm28-direct-green-pm-crypto.log`); el primer `pm-cli` no compiló por haber
retirado el import de `BufRead` que usa otro flujo público
(`/tmp/pm28-direct-green-pm-cli.log`, rc101), se restauró sólo ese trait y la
segunda ejecución pasó rc0 (`/tmp/pm28-direct-green-pm-cli-2.log`). El lab se
ejecutó una vez y pasó rc0 con cleanup verificado
(`/tmp/pm28-direct-green-fault-safety.log`). `scripts/check.sh` registró tres
fallos previos, todos conservados: formato (`...-check.log`, rc1), documentación
`# Panics` (`...-check-2.log`, rc101) y lints de rango/aserciones
(`...-check-3.log`, rc101). Tras correcciones acotadas pasó rc0
(`/tmp/pm28-direct-green-check-4.log`). El build limpio locked/offline pasó rc0
en 40 s (`/tmp/pm28-direct-green-clean.log`).

## Cuarto vertical preparado: stdin nativo sin prefetch

El RED Linux reemplaza sólo el stdin del hijo por un `socketpair` propio. El
padre conserva abierto el extremo lector y envía dos líneas de password seguidas
de un canario sin newline. Al observar el prompt de confirmación consulta
`FIONREAD` sobre ese mismo receive queue: una lectura nativa de un byte deja al
menos el canario completo en kernel, mientras `StdinLock` puede vaciar el socket
hacia su `BufReader` aunque el caller haya pedido un byte. No se lee ni consume
el canario para probar ausencia. El control normal sigue creando raíces hasta
recovery, el sujeto se termina por PID exacto y el `finally` cierra ambos
sockets antes del cleanup estricto.

El GREEN debe duplicar el stdin nativo sin tomar ownership del descriptor
original y hacer `Read` directamente sobre la región protegida. Linux/macOS usan
el fd nativo; Windows requiere su handle nativo equivalente, no un no-op ni
retorno a `StdinLock`. Errores de duplicación/lectura conservan rc5 público y no
seleccionan una ruta sustituta. Los tests de línea existentes fijan LF, CRLF,
CR, EOF y límites. Este lab sólo puede producir RED/GREEN Linux: compilación y
evidencia nativas siguen siendo requisitos separados antes de afirmar las otras
plataformas.

La ejecución única `/tmp/pm28-red-native-stdin-prefetch.log` terminó rc1: build
correcto y `FIONREAD=0`, frente a los 304 bytes mínimos esperados. Así observó
que `StdinLock` había retirado el canario completo del kernel hacia memoria del
proceso; no fue error de compilación, credencial o timeout. Cleanup dejó cero
procesos, sockets y raíces propias.

El GREEN estático introduce `NativeStdin` sin ownership del stdin original. En
Unix valida y lee directamente `STDIN_FILENO` con `read(2)`. En Windows clasifica
el handle prestado con `GetConsoleMode`: pipe/file usa `ReadFile`; consola usa
`ReadConsoleW` y `WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS)`, con UTF-16,
surrogate pendiente y UTF-8 pendiente dentro de `ProtectedBytes`. Esto preserva
la semántica UTF-8 que [documenta `std::io::stdin`](https://doc.rust-lang.org/stable/std/io/fn.stdin.html)
sin cambiar el modo/codepage del host. Ambas rutas escriben sólo en regiones ya
bloqueadas y propagan cada error; no existe rama `StdinLock`, allocator
alternativo ni degradación de consola a `ReadFile`.

El handle Windows nulo conserva el resultado público previo: representa EOF y
`read_protected_line` lo convierte en `unexpected end of input`, rc5, sin crear
vault ni tratarlo como éxito. Hay regresión Windows enfocada y la prueba nativa
debe confirmar el proceso completo. La API de líneas inyectable sigue usando
`Read` para sus demás regresiones. Aún no se ha compilado ni ejecutado este
GREEN, y un PASS Linux no acreditará terminales macOS/Windows ni sus builds
nativos.

El GREEN Linux enfocado terminó rc0 en los tres seams: `pm-crypto` completo
(`/tmp/pm28-native-stdin-green-pm-crypto.log`), `pm-cli` completo
(`/tmp/pm28-native-stdin-green-pm-cli.log`) y el lab real
(`/tmp/pm28-native-stdin-green-fault-safety.log`). Este último observó
`stdin=native-unbuffered`, memlock antes de bytes, canario restante en kernel y
cleanup verificado. El primer `scripts/check.sh` posterior llegó sólo a
`rustfmt --check` y terminó rc1 por el wrapping de un import Windows
(`/tmp/pm28-native-stdin-green-check.log`); se conserva como fallo de formato,
no conductual, y se corrigió sin tocar comportamiento. El segundo check completo
terminó rc0 (`/tmp/pm28-native-stdin-green-check-attempt2.log`) y el clean
offline posterior terminó rc0 en 38.15 s
(`/tmp/pm28-native-stdin-green-clean.log`). Esta evidencia sigue siendo
Linux x86_64: los casos Windows enumerados y macOS no se infieren de ella.

La comparación de compatibilidad queda fijada contra el código fuente de
`std` 1.98.1, no contra una inferencia de `ReadFile`. El caller de create/open
es el único lector humano durante esa invocación; `NativeStdin` toma prestado el
fd/handle actual, no lo duplica, cierra ni transfiere, y no se mezcla con el
`BufReader` global de `std`. En pipe/file, `ERROR_BROKEN_PIPE` conserva el EOF
que expone `std`; los demás errores I/O se propagan. En consola se pasa a
`ReadConsoleW` la máscara de wakeup de Ctrl-Z: Ctrl-Z terminal no se entrega
como byte secreto, Ctrl-C/Break (`ERROR_OPERATION_ABORTED` sin unidades) vuelve
a esperar como `std`, y un surrogate alto sólo se conserva en memoria locked
hasta la siguiente unidad. Una pareja válida se convierte a UTF-8; un surrogate
aislado o pareja inválida falla `InvalidData`, sin reemplazo silencioso.

La prueba nativa Windows pendiente debe ejercer por proceso real y consola
real: ASCII y Unicode suplementario en password/confirmación; CRLF; Ctrl-Z
antes de bytes (mismo rc5 `unexpected end of input`, sin vault) y después de
bytes (EOF que entrega esos bytes al parser); Ctrl-C seguido de entrada válida;
surrogate aislado alto y bajo (fallo explícito, sin vault); pipe con dos líneas;
pipe cerrado antes de bytes (mismo rc5); handle nulo (mismo rc5); y un error de
handle no nulo inválido propagado, nunca reinterpretado como EOF. Debe comprobar
que el handle original continúa abierto y que ningún caso activa `StdinLock`,
`ReadFile` para consola, reemplazo Unicode o una segunda ruta. Linux sólo cubre
el caso pipe/socket y el límite de prefetch; macOS debe repetir terminal/pipe en
su ticket nativo.

## Quinto vertical preparado: cuatro cleanups autorizados

Este vertical empieza sólo después del GREEN nativo de stdin. Sus RED son
fallos reales del filesystem, no callbacks que devuelven errores inventados:

1. `pm-process-runner`: una evidencia real conserva un subdirectorio owned que
   el UID de la prueba no puede retirar. Se captura su path, se deja vivir la
   evidencia hasta terminar todas las observaciones y luego se exige una
   finalización checked que devuelva el único `remove_dir_all` fallido. La
   variante actual carece de esa finalización y Drop retorna normalmente tras
   descartar el error. El fixture restaura permisos por un owner separado y
   elimina/verifica el path exacto aun cuando falle la aserción. El GREEN no
   acorta la vida de `ProcessEvidence`: añade cierre explícito consumiendo la
   evidencia; Drop sólo cubre salidas no gestionadas, no reintenta después de un
   cierre checked y emite un diagnóstico fijo no secreto si su único intento
   falla.
2. `keygen`: se precrea la pública para causar el error primario real después
   de publicar la privada. Un interposer `unlink`/`unlinkat`, limitado al PID y
   path privado exactos, falla una vez con `EIO` y registra contador. El RED
   actual devuelve sólo `CUSTODY_UNAVAILABLE`, dejando la privada y ocultando el
   cleanup; el GREEN debe conservar la indisponibilidad primaria y añadir una
   categoría fija de cleanup, con contador exactamente uno.
3. `rpc_download_atomic`: el servidor TLS/RPK del fixture corta una descarga
   sólo después de que exista y tenga bytes el `.partial`. El mismo interposer,
   limitado al PID/path `.partial`, falla su único unlink. Se conservan tanto el
   fallo de protocolo/escritura como el de cleanup; el destino final nunca
   aparece y no hay reconexión, retry o descarga sustituta.
4. `write_new`: el interposer localiza el fd por `/proc/self/fd`, falla una sola
   llamada `fsync` del archivo nuevo exacto y después falla una sola retirada de
   ese mismo path. El RED actual conserva sólo `Unavailable`; el GREEN agrega el
   fallo de cleanup sin perder el fallo fsync primario, sin publicar otro path.

El interposer escribe únicamente eventos no secretos (`pid`, operación,
contador y basename sintético) a un pipe owned por el lab; aborta el caso si el
path/PID o los conteos no coinciden. Cada caso usa raíz y proceso nuevos. El
resultado público mantiene rc4 y `CUSTODY_UNAVAILABLE`, y agrega sólo el
diagnóstico fijo de cleanup requerido para que la propagación sea observable;
no imprime paths ni errores del SO. Cleanup del fixture corre fuera del proceso
inyectado, restaura permisos si aplica, retira cada path exacto y falla si queda
residuo. No se ejecutará ni implementará GREEN antes de conservar cada RED
conductual.

Los cuatro RED públicos quedaron observados antes del GREEN. ProcessEvidence
descartó el fallo real de `remove_dir_all` y no emitió `CLEANUP_FAILED`
(`/tmp/pm28-red-cleanup-process-runner-final.log`, rc101); el helper restauró
permisos y retiró el path exacto antes de propagar la aserción. Keygen y
`write_new` ejecutaron exactamente los fallos `unlink` y `fsync+unlink`, dejaron
sus archivos owned y devolvieron sólo `CUSTODY_UNAVAILABLE`
(`/tmp/pm28-red-cleanup-custody-keygen-write-final.log`, rc1). Finalmente, el
fixture de descarga mató al peer sólo después de observar bytes en `.partial`;
el unlink exacto falló una vez, el destino final no existió y el cliente también
devolvió sólo `CUSTODY_UNAVAILABLE`
(`/tmp/pm28-red-cleanup-rpc-download.log`, rc1). Cada fixture verificó y retiró
sus residuos. Los intentos anteriores de custody que no compilaron el
interposer o no permitieron escribir su log se conservan como fallos de fixture,
no RED; el primer helper ProcessEvidence reveló una omisión de cleanup del
propio test, se retiró exactamente ese path y el helper final usa
`catch_unwind` para garantizar limpieza aun con la aserción RED.

El GREEN conserva el fallo operacional y cada `std::io::Error` de cleanup en
una representación tipada agregada; el renderer deriva rc2/rc4 exclusivamente
del primario y emite una sola línea fija `CLEANUP_FAILED` cuando la lista no
está vacía. Una regresión con syscalls reales acumula dos errores distintos:
`write_new(public)` falla `fsync`, falla el unlink de la pública, y keygen
intenta y falla además el unlink de la privada. Ambos `io::Error` permanecen en
la lista interna, los tres eventos del interposer tienen conteo exacto y la
salida pública sigue siendo rc4 con un solo marcador no secreto. El focused
final pasó (`/tmp/pm28-green-cleanup-aggregate-focused-attempt2.log`); su
intento anterior no compiló por una anotación de tipo ausente y no cuenta como
evidencia conductual (`/tmp/pm28-green-cleanup-aggregate-focused.log`).

`ProcessEvidence::close` consume la evidencia sólo después de que el caller
termina de observarla y devuelve el error del único intento. El estado interno
impide que Drop reintente después de `close`; si no hubo cierre explícito, Drop
hace exactamente un intento y emite el marcador fijo ante fallo. Los consumers
de tests usan cierre checked en sus retornos normales; dos helpers marcados
`ignored` sólo son entrypoints de subprocess que las regresiones padre ejecutan
explícitamente para capturar stderr y no representan casos omitidos.

El primer check completo de este vertical alcanzó clippy y terminó rc101 por
`needless_pass_by_value` en el helper inicial; se conserva en
`/tmp/pm28-green-cleanup-check.log`. Tras corregir ese lint, check pasó, pero
una inspección estática detectó que un segundo cleanup anidado podía descartarse;
la barrida 23/23 previa se conserva en
`/tmp/pm28-green-cleanup-labs-summary.log` pero no se acepta como final. Con la
agregación corregida, `scripts/check.sh` pasó
(`/tmp/pm28-green-cleanup-check-final.log`), clean offline pasó en 35.78 s
(`/tmp/pm28-green-cleanup-clean-final.log`) y la única barrida final separada
terminó `SUMMARY count=23 failures=0 elapsed=603s`
(`/tmp/pm28-green-cleanup-labs-final-summary.log`). Los 23 logs individuales
usan prefijo `/tmp/pm28-green-cleanup-final-test-linux-`; no quedaron procesos,
roots ni caches propios. Esta evidencia sigue sin cerrar ticket 28 ni acreditar
los puertos nativos de estos cleanups.

## Verticales de fault/crash pendientes de RED

El seam de almacenamiento será un lab público separado, no una colección de
callbacks internos. Cada caso parte de un vault nuevo y conserva snapshot de
conteos/hashes. El orden previsto es: (a) `ENOSPC` real en `tmpfs` privado
durante WAL/staging; (b) interposer de fixture acotado al PID/fd que falla el
syscall `fdatasync/fsync` seleccionado una sola vez; (c) trigger SQLite real en
audit y outbox; (d) `SIGKILL` después de observar staging/WAL, seguido de restart
y consulta del mismo ID. Cada RED debe fallar por parcialidad, categoría falsa
o retransmisión observable, no por falta del compilador/interposer. Ninguno se
ejecuta hasta terminar el vertical anterior y recibir ventana exclusiva.

## Sexto vertical preparado: ENOSPC durante staging/WAL real

El siguiente seam público es `pm-custody human-streaming-file` contra un
`serve-vault` real. Estado, DB, WAL y SHM viven en un `tmpfs` de 64 MiB montado
dentro del user+mount namespace del lab; binarios, perfiles y artefactos de
build quedan fuera de ese volumen. No se cambia el host ni se usa un error
SQLite simulado.

El lab parte de una bóveda nueva, guarda conteos independientes de items,
revisiones, streams/chunks, authority, outbox, receipts y auditoría, y lanza el
stream de 16 MiB. Sólo cuando el WAL real supera 1 MiB —evidencia de staging
material, no un sleep— envía `SIGSTOP` al PID custodio exacto y confirma estado
stopped dentro del plazo de fixture. Un filler owned consume los bloques libres
del mismo `tmpfs` hasta observar `ENOSPC`; el lab confirma cero bloques
disponibles, reanuda exactamente el mismo PID y exige fallo público rc4
`CUSTODY_UNAVAILABLE`, sin `PASS` ni canario en salida.

Antes de retirar el filler, el custodio se vuelve a pausar si sigue vivo y se
escanean DB/WAL/SHM y todos los archivos del volumen: el canario plaintext fijo
del stream no puede aparecer. En `finally`, cualquier PID detenido se reanuda,
se termina sólo cada hijo owned, se elimina el filler por su path exacto, se
desmonta sólo el mount registrado y se retira la raíz estrictamente. Tras liberar
espacio, SQLite debe abrir e informar `integrity_check=ok`; items, revisiones,
streams/chunks, authority, outbox y receipts quedan exactamente como antes,
staging queda vacío y sólo se permite el delta de una auditoría
`HumanUnlock` ya durable antes del intento. Un restart del mismo custodio debe
volver a publicar ambos sockets; no se reintenta la mutación.

El RED se acepta sólo si falla por parcialidad durable, canario, categoría
pública incorrecta, falta de `ENOSPC` real o imposibilidad de recuperar el mismo
vault. Un fallo de mount, build, UID map, deadline de fixture o detector WAL no
es RED de producto. El test queda preparado sin ejecución ni GREEN hasta la
siguiente ventana Linux exclusiva.

La primera ejecución, `/tmp/pm28-red-storage-enospc.log`, no alcanzó el seam:
los homes sintéticos se crearon `0700`, por lo que el UID custodio no pudo leer
las claves públicas del fixture durante `provision-bootstrap`. Se corrigió sólo
esa precondición a `0755`, preservando ownership y contenido. La ejecución
válida `/tmp/pm28-red-storage-enospc-attempt2.log` terminó rc0 y observó ENOSPC
real, rollback integral, canario ausente, `integrity_check=ok`, delta único de
`HumanUnlock`, restart del mismo vault y cleanup verificado. Es cobertura GREEN
de comportamiento existente, no un RED y no motivó cambios de producto.

## Séptimo vertical: primer campo secreto en custodia

El seam público es `pm-custody human-password-crud`. El fixture crea claves y
perfil reales con UIDs separados, pero no necesita iniciar servidor: el comando
lee su primer campo password antes de conectar. Un hijo con `RLIMIT_MEMLOCK=0`
recibe únicamente el header wire de longitud 32 y mantiene abierto stdin sin
entregar payload. Debe terminar rc4 `CUSTODY_UNAVAILABLE` dentro del plazo fijo
del fixture, antes de leer un byte secreto, sin stdout ni socket/vault creado.
La variante actual reserva `Vec<u8>` desbloqueado y queda esperando payload; ese
timeout será el RED conductual. El GREEN mínimo reserva `ProtectedBytes` por la
longitud pública después de validar el límite y antes de `read_exact`, y migra
sólo el password de este comando; no convierte el owner protegido a `Vec`, no
cambia otros campos ni atribuye cobertura a custodia/vault/adaptadores completos.

La ejecución RED `/tmp/pm28-red-custody-protected-input.log` terminó rc1 en
4 s: tras recibir sólo el header, el proceso siguió esperando payload durante
los 3 s del fixture. El GREEN mínimo usa `ProtectedBytes::zeroed` después del
límite y antes de `read_exact`; `/tmp/pm28-green-custody-protected-input.log`
terminó rc0 en 1 s, con rc4 exacto y cleanup verificado. Esta evidencia cubre
sólo el primer password de `human-password-crud`; el resto del inventario
custodia/vault/adaptadores continúa abierto.

Gate del checkpoint parcial: `pm-custody` enfocado pasó 23/23 unidades/doc/integración
en 1 s (`/tmp/pm28-custody-buffer-focused.log`); `scripts/check.sh` rc0 en
102 s (`/tmp/pm28-custody-buffer-check.log`) y clean locked/offline rc0 en 41 s
(`/tmp/pm28-custody-buffer-clean.log`). La barrida única posterior terminó
`SUMMARY count=25 failures=0 elapsed=619s` en
`/tmp/pm28-custody-buffer-labs-summary.log`, con logs individuales prefijados
`/tmp/pm28-custody-buffer-test-linux-`. No hubo retries dentro de aserciones.
Este gate congela un checkpoint parcial integrable; ticket 28 permanece claimed.

Corrección del seam de custodia antes de admitir el checkpoint: usar
`stdin.lock()` invalida el claim “antes de leer payload”, porque su `BufReader`
puede precargar el secreto al obtener el header. La regresión reemplaza stdin
por socketpair, envía header más canario y, tras el rc4 por memlock=0, exige que
el canario completo siga en la receive queue (`FIONREAD`). El RED correcto es
rc4 con `FIONREAD=0`: la categoría pública es correcta pero el secreto ya entró
en un buffer ordinario. El GREEN debe reutilizar el mismo `NativeStdin`
multiplataforma del CLI desde un módulo común, sin duplicar unsafe, y conservar
ownership del fd/handle y semántica Windows ya documentada.

El RED reforzado `/tmp/pm28-red-custody-native-input.log` terminó rc1 con
`FIONREAD=0`: aunque devolvió rc4, `StdinLock` ya había precargado el canario.
El GREEN mueve el `NativeStdin` existente a `pm-crypto` como único seam común y
hace que CLI y el primer password de custodia lo usen sin tomar ownership.
`/tmp/pm28-green-custody-native-input.log` terminó rc0 con el canario completo
en kernel. Las suites enfocadas pasaron rc0 en 24 s y clippy enfocado rc0. El
primer comando `--locked` no compiló porque mover `windows-sys` entre paquetes
requirió sincronizar `Cargo.lock`; se conserva en
`/tmp/pm28-green-shared-native-input-focused.log` como bookkeeping, no RED.
No se repitió la barrida 25/25 anterior; el merger ejecutará el gate compuesto.

## Integración parcial en raíz — 2026-09-14

El merger distinto integró por merge normal el candidato `96dd37a` (rama
`codex/pm-28`, base `52d1920`) como `3ca41eee220cfff0e5498c2439c7dedf5e60e9b1`.
Se conservaron los 17 paths del candidato, incluidos este método y el issue
28 en estado `claimed`; no se alteraron workflows ni candidatos nativos de
otros tickets u otros worktrees.

Antes de la ejecución se verificaron `git diff --check` y
`scripts/verify-native-ci-config.sh`. En la única ventana Linux x86_64, con
toolchain local 1.98.1, builds `--locked --offline`, sin retries, requisitos omitidos
ni labs paralelos, pasaron los focused `pm-crypto`, `pm-cli` y
`pm-custody` con todos sus targets. Los servicios locales de los labs sí utilizan red;
`offline` describe la resolución de dependencias Cargo, no ausencia de
transporte. Los entrypoints de subprocesos marcados `ignored` se ejecutan
explícitamente desde sus tests padres. También pasaron los tres nuevos labs reales:
`custody-protected-input`, `fault-safety` y `storage-fault`.

La comprobación compuesta pasó:

- `scripts/check.sh`, rc0 — `/tmp/pm-g7-root-check.log`;
- `scripts/clean-offline-build.sh`, rc0 — `/tmp/pm-g7-root-clean.log`;
- focused package/lab logs — `/tmp/pm-g7-root-focused-*.log`;
- una única barrida secuencial de los 25 wrappers
  `scripts/test-linux-*-lab.sh`, rc0 cada uno,
  `SUMMARY count=25 failures=0` — `/tmp/pm-g7-root-labs-summary.log` y
  `/tmp/pm-g7-root-labs-test-linux-*-lab.log`.

La barrida usó exactamente los artefactos sintéticos absolutos ya aprobados:

```text
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
```

El target observado fue `/home/santana/Documents/ChatGPT/passwordmanager/target`.
No quedaron procesos de Cargo/lab propios activos ni cambios sin commit; los
wrappers verificaron su cleanup. Esta evidencia es únicamente Linux x86_64:
los puertos nativos, los verticales restantes de fault/crash y la aceptación
final de 28 siguen abiertos. El ticket permanece `claimed` y este es un
checkpoint parcial, no una resolución del ticket ni de G7.

## Bloque coherente pendiente: owners plaintext completos

El bloque siguiente se prueba como cuatro fronteras, pero se integra y barre una
sola vez. Primero, dos tests subprocess aislados preparan paquetes y streams
válidos, bajan sólo su propio `RLIMIT_MEMLOCK` después de crear keys/opener y
exigen `ResourceUnavailable` al abrir revision human/auth y el primer chunk. La
implementación cambia `open`, `OpenedRevisionPackage` y ambos wrappers
`FileOpener`/`BackupOpener` a `ProtectedBytes`; la FFI descifra directamente en
el owner locked, comprueba rc, longitud exacta y tag antes de devolverlo. Drop
limpia capacidad también en error de manifest/auth; cipher, AAD y estado inline
de secretstream no se renombran plaintext protegido.

Segundo, una prueba subprocess de `AttemptVault::claim_next` prepara una
credencial completa password+TOTP+subject-token+SSH, agota el presupuesto público
con owners `ProtectedBytes` conservados y exige `ResourceUnavailable` antes de
entregar `AttemptLease`. `OperationalCredential`, `CredentialMaterial`,
`DecodedAuthMethod`, `AttemptLease`, `TotpLease` y `SshLease` deben poseer
`ProtectedBytes`/`Option<ProtectedBytes>`; getters slice no cambian. El decode
CBOR debe copiar directamente desde bytes autenticados al owner locked y no
crear `Zeroizing<Vec>` intermediario. Metadata no secreta queda en String/Vec.

Tercero, los clientes custody y TUI prueban memlock denegado en cada clase de
frame abierto: password/recovery/token/requester secret/private key, response de
reveal y chunks. Los headers/límites se leen por `NativeStdin` o canal TLS; la
región protegida se reserva antes de payload propio. `read_frame_bounded` no
puede seguir devolviendo un `Vec` cuando el frame contiene plaintext; parsers
borrowean `ProtectedBytes`, y serializers sensibles escriben en un destino
protegido antes del socket. No se protege ni reclama el heap interno de rustls.

Cuarto, los labs reales web-auth y ssh arrancan cada adapter en un subprocess
con memlock insuficiente y una request válida. Deben cerrar/fallar la request
antes de browser/HTTP/SSH y no reflejar canarios. Sus frames completos se leen
directamente a `ProtectedBytes`; cursores sólo prestan slices y eliminan clones
`to_vec` de password/TOTP/token/private/passphrase. Respuestas que contienen
bearer/resultados o material de firma permanecen protegidas hasta `write_all`.
TLS, Chromium y russh internos siguen siendo excepciones explícitas, no fallback.

Los RED se ejecutarán por filtro y lab exactamente una vez tras nueva ventana.
Un fallo de build/fixture no cuenta. Sólo después de reproducir los cuatro seams
se escribe GREEN; no habrá otra barrida integral entre microcambios.

Checkpoint test-first estático: `protected_plaintext.rs` contiene helpers
subprocess independientes para revision y backup chunk; `delegated_authorization`
reutiliza su fixture Keycloak completo y agota el presupuesto mediante la API
pública antes de `claim_next`; `adapter_protected_frame_lab.py` inicia los dos
binarios reales con memlock=0, envía sólo header y exige cierre/error antes de
payload. El custody socketpair previo cubre el frame humano. Ninguno de estos
RED nuevos se ejecutó ni tiene GREEN anticipado; próxima ventana requiere los
tres filtros Rust (crypto revision, crypto stream, lease) y el lab adapters por
separado, preservando cualquier fallo de fixture/compilación como no RED.

Corrección estática previa al RED: `RLIMIT_MEMLOCK=0` en revision podía fallar
al reabrir keys y producir un falso positivo antes del destino plaintext. El
fixture ahora prepara paquetes pequeño y 4 MiB, ocupa memoria locked en bloques
de 1 MiB y libera exactamente uno: el paquete pequeño debe abrir bajo la misma
presión (control de keys+output), mientras el grande debe fallar por su owner.
El lease usa password de 512 KiB sólo en el helper, ocupa bloques de 128 KiB y
libera uno antes de construir `DelegatedVault`/`AttemptVault`; esas APIs deben
abrir el key path bajo presión y sólo `claim_next` del payload grande debe fallar.
El stream conserva opener preinicializado antes de RLIMIT0. Los parents no
renderizan stdout/stderr con conversión lossy: reportan únicamente status fijo;
los canarios nunca entran al diagnóstico.

Ejecución RED discriminada: los primeros logs de crypto y lease, sin marcador
post-control, quedan clasificados como indeterminados y no acreditan el seam.
Tras agregar marcadores fijos que sólo se emiten después del paquete pequeño,
opener o key path exitoso, revision y stream fallaron rc101 porque el destino
plaintext ordinario fue aceptado (`/tmp/pm28-red-revision-plaintext-attempt2.log`
y `/tmp/pm28-red-stream-plaintext-attempt2.log`). El lease original falló rc101
después de abrir el key path y entregar el payload grande en owners ordinarios
(`/tmp/pm28-red-attempt-lease-plaintext-attempt2.log`). El adapter lab tuvo un
primer error de fixture `Path` y un intento que sólo alcanzó web; ninguno cuenta.
El intento válido separado llegó a ambos procesos y terminó rc1 con la categoría
fija `('web','ssh')`, ambos esperando payload tras el header
(`/tmp/pm28-red-adapter-protected-frame-attempt3.log`).

El GREEN abre AEAD revision/control y secretstream directamente en
`ProtectedBytes`, exige longitud y tag exactos, y mantiene owners protegidos en
`OpenedRevisionPackage`, `OperationalCredential` y leases password/token/TOTP/SSH.
Los adapters web/SSH reservan el frame protegido después de validar el header y
antes de leer payload; sus clones propios de secretos de request pasan también a
owners protegidos hasta la frontera de bibliotecas externas. El primer GREEN de
lease falló antes de delivery porque proteger el documento auth completo movió
la denegación a admission; no fue regresión de producto ni se aceptó como prueba.
El fixture final crea el intento antes de presión, reabre custodia/key path bajo
esa misma presión y exige que `claim_next` propague `CUSTODY_UNAVAILABLE`.

Evidencia GREEN: crypto focused rc0
(`/tmp/pm28-green-protected-crypto-focused-attempt2.log`), lease focused rc0
(`/tmp/pm28-green-attempt-lease-focused-attempt5.log`), adapters rc0
(`/tmp/pm28-green-adapter-protected-frame.log`), `scripts/check.sh` rc0 tras
preservar los intentos de lint previos
(`/tmp/pm28-green-plaintext-block-check-attempt5.log`) y clean/offline rc0 en
41.71 s (`/tmp/pm28-green-plaintext-block-clean.log`). Este checkpoint no
acredita todavía serializers/responses sensibles ni todos los frames custody/TUI;
ticket 28 continúa abierto.

Siguiente RED estático, aún sin ejecución: el lab custody repite el seam con
un presupuesto de 128 KiB, entrega completamente el primer password corto y
después sólo el header público de un segundo campo de 512 KiB más un canario
pequeño. El proceso debe fallar rc4 antes de leer ese canario. Así se distingue
la protección del primer `NativeStdin` de los restantes `read_wire_field`; no se
considera RED un fallo anterior al segundo header. El GREEN posterior migrará
el inventario de campos secretos al lector protegido común sin cambiar límites,
orden, CRLF/EOF ni los campos declaradamente públicos.

La primera ejecución del caso adicional pasó sólo porque el fixture colocaba el
header grande en la posición de `title`; no alcanzó el segundo secreto y queda
invalidada. El segundo intento añadió conteo exacto de bytes pendientes, pero
conservaba el mismo orden y también queda invalidado. Tras entregar password,
title y username completos, `/tmp/pm28-red-custody-subsequent-frame-attempt3.log`
terminó rc1 por timeout: `secret_one` había reservado un `Vec` ordinario y
esperaba payload. El GREEN cambia todos los campos stdin previamente envueltos
en `Zeroizing<Vec>` a `ProtectedBytes`, usa `NativeStdin` sin prefetch en todos
esos callers, y conserva los campos públicos y límites. El lab pasó rc0 en
`/tmp/pm28-green-custody-subsequent-frame.log`; el compile enfocado final pasó
rc0 en `/tmp/pm28-green-custody-inventory-compile-attempt2.log`. Un intento de
ampliar simultáneamente todos los frames TLS no compiló y fue retirado completo;
se conserva `/tmp/pm28-green-custody-frames-compile.log` como fallo de
composición, no como evidencia conductual ni GREEN. Los frames TLS abiertos,
serializers y responses siguen pendientes de su RED público discriminante.
La suite enfocada `pm-custody` pasó rc0
(`/tmp/pm28-green-custody-inventory-focused.log`).

## Octavo vertical: frames TLS y serializers sensibles

La migración estática comenzó después del GREEN de stdin, antes de ejecutar la
regresión adicional de este vertical; esta cronología se conserva y ningún fallo
de compilación cuenta como RED. El baseline conductual para la regresión será el
checkpoint limpio `9ec8b30`, en una copia aislada propia: un hijo limita sólo su
`RLIMIT_MEMLOCK`, supera un control pequeño de construcción pública y solicita
una respuesta sintética con canario de 512 KiB. El marcador fijo posterior al
control distingue la precondición; aceptar una respuesta `Vec` bajo denegación es
el RED. El candidato debe devolver `CUSTODY_UNAVAILABLE` antes de crear el owner
de respuesta y no escribir ni reflejar el canario. El parent sólo observa status
y marcadores fijos, nunca renderiza bytes del canario.

El contrato interno del GREEN separa `HumanResponse::Public` para frames de
estado/metadatos ya clasificados y `HumanResponse::Protected` para records,
secrets, resultados, challenges, material de firma y prepared command/body.
Todo frame entrante pertenece a `ProtectedBytes`; `Cursor` sólo presta slices.
Los serializers sensibles calculan el tamaño con aritmética checked, reservan el
owner locked antes de escribir y sólo entregan `finish_exact`; cualquier error o
desajuste descarta el owner completo. No existe salida truncada, retry, `Vec`
secreto alternativo ni conversión para diagnóstico. Los heaps internos de
rustls permanecen fuera de este claim.

El mismo bloque migra el input/reveal/password persistente del TUI, las claves
RPK propias de custody y `pm-sync`, y sus lecturas de archivo: la longitud se
valida desde el header público, el owner locked se reserva antes de leer private
key y sólo el SPKI público usa `Vec`. La copia que exige la API de rustls se crea
únicamente al transferir ownership al proveedor TLS; no vuelve a ser storage
propio ni se presenta como memoria interna de la biblioteca protegida.

### Usage interruption checkpoint — 2026-09-16

User requested bounded closure followed by STOP/handoff, not completion claims
for this vertical. On resumption the uncommitted migration was preserved and
checked from the actual WT28 cwd. First compile failed at the new `push!`
macro's trailing comma grammar (28 errors); second exposed expression-position
semicolon and one non-mutable request that is explicitly zeroized. Those syntax/
mutability errors were corrected without changing the memory/protocol contract.
Logs: `/tmp/pm-handoff-g7-check{,2,3}.log`. This does not supply the missing
baseline behavioral RED, focused response GREEN, full check or integration gate.
The pre-interruption compile logs in `/tmp` are no longer present on this host;
previous narrative remains historical evidence, not an accessible log claim.

Final compile after rustfmt passed: `/tmp/pm-handoff-g7-final-check.log`,
`cargo check -p pm-custody -p pm-sync -p pm-vault --all-targets --locked --offline`
from WT28. Saved as a local WIP checkpoint, NOT integrated or accepted.
Next: run the discriminating regression on baseline9ec8b30 before claiming
a behavioral correction; then candidate focused tests and full G7 inventory.

## Reanudación 2026-10-02 — método discriminante concretado

El WIP `8bf30bf` es una migración estática previa al RED de respuestas; no se
presenta como TDD. Copia detached propia de `9ec8b30` en
`/tmp/pm28-20261002-baseline9ec8b30`, añadiendo sólo el fixture de regresión.
El baseline reproduce las dos instrucciones del serializer real de reveal
(opcodes 50/52/53: status seguido de `push_bytes`), sin migrar producto.
El hijo fija memlock soft/hard a 128 KiB, serializa un campo pequeño bajo ese
mismo límite, verifica sus bytes y libera el resultado. Sólo después emite
`PM28_RESPONSE_CONTROL_READY` y solicita un campo sintético de 512 KiB desde
stack. Se exige `Failure::Unavailable` (categoría pública
`CUSTODY_UNAVAILABLE`); aceptar el Vec de respuesta es RED conductual. El parent
exige el control antes de status y no imprime las salidas del hijo. Esto cubre
el serializer de respuesta, no un recorrido TLS completo. Todas las corridas
usan `flock /tmp/pm-cargo-window.lock` desde su cwd exacto. Los logs nuevos usan
`/tmp/pm28-20261002-*`; los históricos ausentes no son evidencia accesible.

Resultado del vertical: RED rc101 con control confirmado en
`/tmp/pm28-20261002-red-response.log`, baseline `9ec8b30`; GREEN rc0 en
`/tmp/pm28-20261002-green-response.log`. El primer intento de preparación usó
un cwd incorrecto y ejecutó cero pruebas: `/tmp/pm28-20261002-baseline-no-fixture.log`
queda invalidado, no es RED. El fixture definitivo usa un canario estático
sintético; no añade un owner heap ordinario. El gate inicial falló por formato
(`wip-check.log`), el segundo completó tests pero falló por 35 lints
(`wip-check2.log`), y el siguiente intento enfocado quedó con un lint del fixture
(`wip-clippy2.log`). Corregidos borrows y forma de expresiones sin alterar los
fallbacks heredados, `scripts/check.sh` completo terminó rc0 en
`/tmp/pm28-20261002-wip-check3.log`: config, build inputs, fmt, check, tests y
clippy locked/offline. Esto valida el checkpoint, no cierra el inventario G7.

### Pérdida real de custodia audit — regresión adicional

Se concreta el seam ya seleccionado en §3: fixture Linux propio con vault
real, tres UIDs y TLS/RPK. Primero `human-password-crud` debe completar y
`audit_keys` contener la generación inicializada; sólo entonces se emite el
control fijo. Se para únicamente el daemon propio, se retiene por rename
el archivo `.audit-custody` original y se reinicia el mismo vault. Se observa
si aparece un reemplazo y se exige rechazo rc4 sin stdout ni canarios.
Después se retira únicamente el reemplazo creado por el fixture, se restaura
el original exacto y se comprueba el restart. La prueba falla si generó claves
para sustituir una custodia perdida; no es RED si falla setup/control/cleanup.
No se modifica `load_or_create_audit_custody`: su corrección necesita la
autorización específica exigida para fallbacks heredados. El fixture no usa
proveedor externo y no acredita ausencia de doble login.

El primer fixture llegó al control inicializado y falló en la categoría de
admisión, con cleanup rc0, pero no imprimía métricas fijas que permitan
identificar el resultado: `/tmp/pm28-20261002-red-audit-custody-loss.log`.
Se conserva como fallo posterior al control sin atribuirle aún la causa.
La variante instrumentada registra sólo rc/booleanos, termina restauración y
cleanup antes de exigir ausencia de claves sustitutas; no imprime salidas ni
material privado. Se ejecuta en otro vault propio, sin retry de proveedor.

### Rate y clock — concreción del seam público de §3

`seventeenth_attempt_and_clock_rollback_leave_admission_atomic` usa el motor
real sobre SQLite cifrado, dos RPK de transporte registradas y credencial
habilitada. Crea 16 intentos vivos del agente A; el 17.º debe ser
`RATE_LIMITED` sin delta en intentos/audit/authority/outbox/receipts. Repetir
la idempotencia del primero conserva su ID y esos conteos; el agente B aún
puede admitir uno. Después el fixture adelanta la ancla durable del reloj
1000 s y exige `CLOCK_UNTRUSTED` en una admisión nueva de B, sin delta en
esas tablas. La modificación SQL sólo controla el reloj del fixture: no
simula proveedor, persistencia ni autoridad. Es cobertura de comportamiento
existente; si pasa, no se inventa un RED ni se atribuye cambio de producto.
No cubre el techo custodial de 128 ni todos los límites de G7.

### Evidencia nueva consolidada — 2026-10-02

- Respuesta: RED discriminante rc101 en baseline `9ec8b30`,
  `/tmp/pm28-20261002-red-response.log`; GREEN rc0 del candidato,
  `/tmp/pm28-20261002-green-response.log`. Se confirma el control bajo el mismo
  límite de 128 KiB antes de intentar 512 KiB. No se llama TDD retrospectivo
  a `8bf30bf`. El checkpoint de correcciones de lint/regresión es `dec9b44`.
- `scripts/check.sh` completo final rc0:
  `/tmp/pm28-20261002-final-check.log`, incluye la prueba nueva de rate/clock.
- Clean locked/offline del checkpoint rc0 en 33.68 s:
  `/tmp/pm28-20261002-wip-clean.log`. El build final con los tests añadidos se
  registra separadamente en `/tmp/pm28-20261002-final-clean.log`.
- Barrida de los 26 `scripts/test-linux-*-lab.sh` existentes: todos rc0,
  657.41 s, `/tmp/pm28-20261002-labs-summary.log`. Logs individuales
  `/tmp/pm28-20261002-test-linux-<nombre>-lab.log`. Cada script adquirió su
  propio `flock`, sin paralelismo de Cargo ni retry del lab. El código de
  producto fue el mismo que en `dec9b44`; sólo se añadieron pruebas/documentación
  después. El nuevo negativo audit-loss se ejecuta aparte y **no** está incluido
  en ese 26/26; no se presenta como gate integral verde de G7.
- Rate/clock rc0: `/tmp/pm28-20261002-rate-clock.log`; cobertura GREEN de
  comportamiento existente, sin cambio de producto ni RED fabricado.
- Audit-loss final rc1: `/tmp/pm28-20261002-red-audit-custody-loss3.log`:
  control inicializado, admisión `rc=0 closed=0`, `replacement-created=1`,
  original restituido, restart y `cleanup errors=0`. El segundo log tenía una
  etiqueta fija errónea “admission=closed” después de medir `closed=0`; no se
  usa esa etiqueta como evidencia. El tercero corrige sólo el diagnóstico y
  conserva la aserción negativa. No hay GREEN de este fallo heredado.

Comandos reproducibles desde el cwd indicado:

```sh
# RED: cwd=/tmp/pm28-20261002-baseline9ec8b30, baseline más fixture test-only
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-custody --lib linux::protected_frame_tests::sensitive_response_requires_locked_owner_before_serialization --locked --offline -- --exact --nocapture
# GREEN y gates: cwd=.worktrees/28-fault-safety
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-custody --lib linux::protected_frame_tests::sensitive_response_requires_locked_owner_before_serialization --locked --offline -- --exact --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization seventeenth_attempt_and_clock_rollback_leave_admission_atomic --locked --offline -- --exact --nocapture
```

Para cada lab, con artefactos existentes (no se reinstalaron):

```sh
export PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
export PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
# Enumerar scripts/test-linux-*-lab.sh y ejecutar uno por vez, con log propio:
flock /tmp/pm-cargo-window.lock ./scripts/test-linux-storage-fault-lab.sh
```

El negativo de custodia utiliza el mismo namespace multi-UID de
`test-linux-custody-protected-input-lab.sh`: sustituir únicamente su invocación
Python por `audit_custody_loss_lab.py target/debug/pm-custody target/debug/pm`,
desde el worktree, manteniendo el `flock`, los mapas UID/GID y el mount-proc.
Este fixture necesita el build actual, no instala dependencias ni toca host.

### Estado exacto de aceptación G7 al entregar la fase 1

| Criterio | Estado y alcance | Evidencia nueva |
|---|---|---|
| Respuesta sensible: control pequeño + 512 KiB bajo memlock | PASS del serializer; no E2E de todos los response tipos | red/green-response.log; final-check.log |
| Guardas Linux, core=0, dumpable=0, denegación memlock y stdin nativo | PASS del tracer público | test-linux-fault-safety-lab.log; test-linux-custody-protected-input-lab.log |
| Memoria propia protegida integral / todos serializers, records, imports y requests | FAIL de inventario: siguen owners/serializers ordinarios; no se declara cierre | Punteros concretos debajo |
| Presupuesto agregado 32 MiB observado y perfil suficiente | No demostrado íntegramente; contador central existe, host soft/hard memlock observado 8192 KiB | root.rs; límite del entorno, no se aumentó |
| 17.º RATE_LIMITED, idempotencia a capacidad y CLOCK_UNTRUSTED sin parcialidad | PASS por API real; reloj controlado mediante ancla durable del fixture | rate-clock.log; final-check.log |
| Todos los demás límites, incluido techo custodial 128 | No demostrado como matriz integral | Suites existentes pasan; no extrapolar |
| ENOSPC real durante WAL, rollback de item/revision/streams/authority/outbox/receipt/audit y restart | PASS acotado | test-linux-storage-fault-lab.log |
| Fsync de archivo y fallos de cleanup reales | PASS acotado; no acredita fsync SQLite en todas las fronteras | test-linux-cleanup-fault-lab.log; test-linux-rpc-cleanup-fault-lab.log |
| Matriz real fsync/WAL/commit/outbox/audit por frontera | No demostrado integralmente | ENOSPC y SQL triggers no sustituyen los syscalls faltantes |
| Crash con intención, reconciliación y ausencia de login duplicado | PASS del proveedor externo controlado; no se extrapola a todos los proveedores | test-linux-attempts-lab.log: provider-calls=1, no-blind-retry |
| Canarios activos/históricos en todos los canales, temp, dumps y recursos de agente | No demostrado integralmente; hay barridos acotados y controles de aislamiento | 26 logs; faltan matriz completa, crash dump real y process_vm_readv integral |
| Pérdida audit-custody sin sustitución automática | FAIL: sustitución y CRUD rc0 observados; corrección pendiente de autorización | red-audit-custody-loss3.log |
| Otras pérdidas de custodia sin doble login | No demostrado como matriz combinada | No atribuir el proveedor del lab attempts al fixture audit-loss, que no tiene proveedor |
| VirtualLock, WER/LocalDumps Windows | Diferido a implementación/evidencia Windows; Linux no lo acredita | Gates 27/32; sin cambios ni cierre inferido |
| Controles/crash nativos macOS | Diferido a evidencia nativa macOS | Gates 26/31; sin cierre inferido |
| Integración por merger y revisión final independiente | Pendiente; ticket sigue claimed, PR #1 no fusionado | Esta rama no se integra desde el implementador |

Las rutas de logs abreviadas en esta tabla llevan el prefijo
`/tmp/pm28-20261002-` salvo donde se especifica otro.

### Inventario pendiente concreto y frontera de autorización

El octavo vertical del WIP cubre readers TLS/FrameReader, préstamo de Cursor,
`WirePrepared`, `HumanResponse::Public/Protected`, destinos exactos de responses,
input/password/reveal persistente de TUI y lectura de privadas RPK custody/sync.
La prueba nueva discrimina sólo un serializer; los 26 labs validan sus flujos
observables, no la ausencia de owners ordinarios en todo el producto.

Pendientes visibles, sin introducir `Clone`/`Debug` en ProtectedBytes ni
adapters secretos para ocultar errores:

- `pm-vault/src/content.rs`: AuthRecord/password/token/SSH, notes/custom/source
  fields/attachments y to_bytes/encode_human/encode_auth todavía String/Vec.
- `pm-vault/src/human.rs`: PasswordRecord, PreparedHumanCommand y serializers
  de documentos/chunks/grants todavía incluyen Vec/Zeroizing<Vec>.
- `pm-vault/src/migration.rs` y `onepux.rs`: CSV/JSON y buffers de importación
  aún ordinarios; proteger únicamente el frame TLS no los migra.
- `pm-custody/src/linux.rs`: keygen/provision-bootstrap, read_import_source,
  read_regular, read_tty_password, call_provider y encode_attempt_snapshot
  conservan tramos propios ordinarios.
- `pm-custody/src/linux/tui.rs`: algunos requests de import/restore/rotación/
  export/sync y split_exact hacen copias ordinarias; draw/display_secret vuelven
  a construir String para reveal. Además Ratatui copia símbolos a sus Cell/
  buffers internos (fuente instalada ratatui-core 0.1.2); esa memoria no se
  declara protegida ni se agrega como excepción implícita. Debe resolverse el
  camino de presentación preservando los comportamientos TUI acordados.
- `pm-web-auth`: responses de provider y bodies/scripts/JSON/HTTP propios aún
  usan Vec/String; frames protegidos de entrada no cierran este inventario.

Excepciones preservadas: internals TLS/rustls, russh, Chromium y Argon, stack/
registros/expansiones criptográficas según G7. No se amplían por inferencia.

Fallback nuevo identificado, **heredado**: `linux.rs::load_or_create_audit_custody`
genera y escribe nuevas claves si falta `.audit-custody`; al entrar una operación
humana con KH, `audit.rs::ensure_package` acepta AuditKeyUnavailable y provisiona
una generación nueva. El negativo demuestra pérdida de un dispositivo ya
inicializado y aceptación rc0 de un CRUD ordinario. Se solicitó autorización
específica para distinguir primera provisión de pérdida/cambio de claves en
un dispositivo inicializado, denegar sin claves/generaciones nuevas y verificar
restauración. La regla del usuario de conservar fallbacks heredados impide
aplicar esa corrección sin respuesta explícita. No se reabre el contrato G7
ni se interpreta silencio como aprobación.

Otros heredados observados estáticamente y conservados: ProcessTlsTransport::put
retiene temporal ciphertext al fallar write/fsync y descarta unlink; sync_stage
borrar/recrear ante AlreadyExists; agent_attempt sustituye bytes UTF-8 inválidos
mediante from_utf8_lossy; el runner descarta errores de kill y usa tiempo default
si pre-epoch. Los demás del handoff (cleanup de fixtures, clipboard/pipe Windows
y Mac) permanecen comunicados, sin autorización ampliada ni validación nativa
atribuida a este turno.

Zonas de composición con 26/27: el WIP modifica linux.rs/linux/tui.rs y lib.rs;
los puertos extraen esas responsabilidades a tui.rs/human_wire.rs/agent_wire.rs/
sync_job.rs y cfg nativo. Integrar trasladando los owners y lectores a su engine
único, sin duplicarlo. pm-sync/main.rs también requiere composición cfg. No se
realizó merge, cherry-pick ni cambio de sus worktrees.

Gate del checkpoint final: `scripts/check.sh` rc0 y clean locked/offline
rc0 en 36.83 s, con todos los targets/tests actuales compilados
(`/tmp/pm28-20261002-final-check.log`,
`/tmp/pm28-20261002-final-clean.log`). El AST del nuevo fixture Python,
`git diff --check`, las referencias locales y la consistencia `claimed`/G7
incompleto fueron comprobados. Soft y hard RLIMIT_MEMLOCK del host son
8192 KiB, observados de nuevo sin modificarlos. Se retiraron sólo los dos
`__pycache__` creados por nuestras corridas en este worktree; se conserva
la copia baseline y los logs para revisión. La barrida 26/26 no se repitió
porque desde `dec9b44` no cambió producto ni ningún lab existente.

Entrega parcial publicable: conserva el WIP `8bf30bf`, añade validación y
regresiones, **no** completa G7 ni autoriza integración a ciegas. La migración
del inventario anterior y el negativo audit-loss siguen abiertos; la
corrección de los fallbacks espera la respuesta explícita solicitada.

Otros silenciamientos heredados observados en `linux.rs::serve_loop`: si
`DelegatedVault::open` falla al arrancar un servicio con proveedor, el
`if let Ok` omite `recover_inflight` y continúa el arranque; el worker descarta
el error de `run_provider_once` y vuelve al loop cada 5 ms. Se conserva ese
comportamiento. El lab audit-loss no usa proveedor, por lo que no demuestra
las consecuencias de esos caminos ni ausencia de duplicación bajo esa pérdida.
No quedan incluidos en la autorización específica solicitada para audit custody.

## Fase 2 — 2026-10-02

Continuación desde `e3fb352` limpio en `codex/pm-28`. Cada ejecución local usa
`flock /tmp/pm-cargo-window.lock`, un check/test/lab por bloque; los logs de esta
fase llevan `/tmp/pm28-20261002b-`. No se modifica la regeneración de audit
custody ni los demás fallbacks heredados, ni se integra la rama principal.

El primer seam adicional concreta §1 para los constructores públicos de
`PasswordRecord` (password y notas) y `Attachment`. Tres hijos independientes
fijan memlock soft/hard a 128 KiB; cada uno construye/verifica/libera un record
y un attachment pequeños bajo el mismo límite antes del marcador fijo. Sólo
después intenta copiar un canario ASCII estático de 512 KiB y exige
`HumanCommitError::Crypto(ResourceUnavailable)`. El parent registra únicamente
la clase pública, control y status, sin renderizar stdout/stderr del hijo.
Es RED si un constructor acepta el destino ordinario después del control;
compilación/precondición/marker ausente no son RED. El GREEN reservará y
bloqueará el owner antes de copiar, conservando getters, límites y formato.

Seams adicionales concretados antes de los labs de pérdida: bootstrap y vault
usan cada uno un vault nuevo, cinco UIDs y proveedor controlado. Un login ambiguo
inicial debe dejar el mismo `attempt_id` en `INDETERMINATE` con journal de una
sola llamada antes del control. Se para el daemon, se retiene por rename el
bootstrap o el vault y sus sidecars exactos y se arranca una sola vez. El
arranque debe rechazar rc4 o la API debe denegar con su código 1 contractual;
no se permite recrear el archivo perdido. Se restituyen únicamente los archivos
originales, se reinicia y se consulta ese mismo ID sin reautenticar. Conteos de
intentos/audit/autoridad/outbox/receipts y claves deben conservarse; el journal
sigue en una llamada. Un error de fixture/control/cleanup no acredita RED.
`scripts/verify-ticket28-custody-loss.sh` ejecuta un caso y admite `audit` para
el negativo heredado, siempre bajo `flock`; queda fuera de la barrida existente
porque un negativo bloqueado no puede contarse como gate verde.

El presupuesto agregado se prueba además en un subprocess de pm-crypto con un
límite de contador test-only de 64 KiB, manteniendo 32 MiB en producto. Dos
owners de 32 KiB deben estar realmente bloqueados; truncar uno a un byte no
libera su capacidad, una tercera asignación de un byte se deniega y Drop libera
exactamente la capacidad cobrada. No modifica rlimits ni acredita que este host
pueda bloquear físicamente los 32 MiB completos con su hard memlock de 8 MiB.

Los primeros intentos de pérdida no acreditan RED de producto: bootstrap-loss
rc1 por nombre de tabla incorrecto; bootstrap-loss2 por tratar un arranque rc4
ya observado como daemon aún vivo durante cleanup. Ambos fixtures retiraron sus
procesos/raíces; los logs se conservan. Bootstrap-loss3 y vault-loss observaron
el control ambiguo pero fallaron en conteos, antes del diagnóstico completo.
El motor reclama `INDETERMINATE` para reconciliación cada 100 ms
(`attempts.rs::claim_reconciliation`) y registra `AuthState` al asentarla: exigir
cero registros adicionales de audit a través de ese restart no discrimina
sustitución de custodia. Esos logs no se presentan como RED/GREEN de pérdida.
Se mantiene el modo ambiguo y su aserción exacta para investigar por separado.

Antes del caso adicional se define un control **completado** explícito
(`verify-ticket28-custody-loss.sh <bootstrap|vault> completed`): una llamada real
terminada en `SUCCEEDED`, seguida de pérdida/restauración y consulta del mismo
ID. Conserva todos los conteos exactos, claves, denegación y prohibición de
reemplazo; no debilita ninguna aserción del modo ambiguo. Acreditará únicamente
pérdida con intento completado; no el caso en vuelo ni una intención ambigua.

### Cronología TDD y composición de memoria de la fase 2

Los siguientes RED son conductuales, con control pequeño bajo el mismo límite
antes del caso grande. El baseline es `e3fb352`, en el worktree original para
records/auth y en la copia propia `/tmp/pm28-20261002b-baseline` para parsers,
archivo inline y serializers. La copia sólo añade fixtures test-only compatibles
con la API previa; no altera comportamiento de producto. Adaptar en el fixture
baseline el retorno infalible anterior a `Ok` no protege sus bytes ni cambia la
aserción de denegación; el candidato usa su API fallible real.

| Seam y fallo discriminado | RED rc101 | GREEN rc0 |
|---|---|---|
| PasswordRecord/password, notas y Attachment: acepta 512 KiB en heap ordinario tras control de 128 KiB | red-records.log | green-records.log; check2.log |
| Decoder AuthRecord: acepta password de 512 KiB tras control | red-auth-record.log | green-records-lib.log; check2.log |
| Parsers CSV y JSON: aceptan campo ASCII de 512 KiB bajo 128 KiB | red-import-parsers.log | green-records-lib.log; check2.log |
| Descifrado inline PMF1: publica 4 MiB tras control pequeño con sólo ~1 MiB de memlock disponible | red-inline-file.log | green-crypto.log; check2.log |
| Serializer de descriptor y record completo: publica 512 KiB de notas bajo presión de owners protegidos, con control pequeño | red-record-serializers.log | green-records.log; check2.log |

Todos los nombres abreviados de esta fase llevan `/tmp/pm28-20261002b-`.
Los comandos exactos, ejecutados con cwd del baseline para RED o del candidato
para GREEN, son:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --test protected_records records_require_locked_destinations_before_copying --locked --offline -- --exact --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --lib content::protected_record_tests::decoded_auth_requires_locked_destination --locked --offline -- --exact --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --lib parser_requires_locked_destination --locked --offline -- --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-crypto --test protected_plaintext inline_file_plaintext_requires_locked_output --locked --offline -- --exact --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --test protected_record_serializers --locked --offline -- --nocapture
# GREEN agrupados (sin modificar los criterios de cada fixture):
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --lib --locked --offline
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --test protected_records --test protected_record_serializers --locked --offline -- --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-crypto --all-targets --locked --offline
```

El cambio añade `ProtectedText` sin Clone/Debug y `ProtectedWriter` exacto. Un
write fallido deja el writer inválido; `finish_exact` rechaza sobrelongitud,
subllenado o fallo nativo aunque haya bytes escritos. El encoder CBOR mide
sin retener plaintext, comprueba el límite previo y bloquea el destino exacto
antes del segundo recorrido. PMF1 valida framing/tamaño antes de reservar y
descifra directamente hacia ese destino; cada tag/longitud debe ser válido
antes de publicar. Se preservan los bytes y orden canónicos del esquema.

Se migran notas/custom/source values, secretos de AuthRecord, contenido inline
de Attachment y PasswordRecord; serializers human/auth/descriptor/completo y
credential, parsers CSV/JSON/UTF-16/percent/base32 y canonical JSON. Los callers
propagan fallos tipados; no se agrega adapter que convierta owners secretos a
Vec. Los cambios en backup y linux.rs son composición obligatoria de esos tipos,
no cierre de sus buffers internos. Las comparaciones de regresión retornan
booleanos para no introducir Debug del secreto por una aserción fallida.

La revisión posterior encontró una regresión del candidato: el array privado
passkey `[u8;32]` se convirtió en owner variable sin trasladar su invariancia al
constructor. `red-passkey-seed-invariant.log` rc101 compiló, pasó control de
32 bytes y aceptó una longitud inválida. Sólo después se agregó la comprobación
32 en `valid_auth` y se verificó esa longitud antes de copiar en el decoder.
El GREEN enfocado se conserva en `green-passkey-seed-invariant.log`. No es un
RED retrospectivo del baseline: es el RED de un defecto introducido en esta
fase, reconocido y corregido antes de publicar.

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --test protected_records protected_passkey_seed_preserves_exact_32_byte_invariant --locked --offline -- --exact --nocapture
```

La primera barrida Linux ya estaba en curso al detectar esa regresión. Su
summary rc0, 26/26 en 676.99 s, se conserva como ejecución intermedia; no se usa como la barrida final
uniforme del candidato corregido. Tras el GREEN se repiten check, clean offline
y una barrida completa en ese orden, con logs final-* y sin retry oculto de
ningún caso dentro de un fixture.

`green-crypto.log` incluye la prueba aislada del presupuesto agregado de 64 KiB
test-only: capacidad truncada sigue cobrada, asignación adicional denegada y
Drop libera exactamente lo cobrado. Producto conserva 32 MiB. También incluye
rechazo del writer después de un write fallido/sobrelongitud y de un encoding
corto. El error del writer se inyecta en la closure del unit test; prueba que
no publica bytes tras error, **no** es fault injection real de fsync/storage.
Esas regresiones del owner no se presentan como RED contra una
API inexistente. Soft/hard reales del host se observaron en 8 MiB; no se cambiaron.

Los logs `records-compose*` e `inventory-compose*` anteriores son errores de
composición/compilación y **no RED**. `inventory-compose7.log` termina rc0 para
`check --workspace --all-targets`. El primer `check.log` pasó todos los tests y
falló en Clippy; `clippy2.log`–`clippy6.log` conservan errores de préstamos,
aserciones o fixtures. `clippy7.log` termina rc0. No se añadieron Debug/Clone,
dependencias, cambios de KDF/deadlines o límites de producto para satisfacerlos.

### Pérdida de bootstrap y vault: evidencia y nuevo bloqueo

```sh
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh bootstrap completed
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh vault completed
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh audit
```

`bootstrap-completed-loss.log` rc0 demuestra el caso completado: denegación,
ningún archivo sustituto, una llamada al proveedor, claves originales y los
cinco conteos exactos después de restitución. No acredita pérdida en vivo ni
intento en vuelo/ambiguo.

`vault-completed-loss.log` rc1 midió sustitución, pero clasificó como abierta
una admisión que devolvió rc4 con stdout vacío. Esa expectativa limitada a
`DENIED code=1` del fixture no se usa como fallo de categoría del producto.
Antes de la siguiente ejecución se añadió diagnóstico por booleanos/código,
sin imprimir bytes públicos potencialmente secretos: rc4,
`CUSTODY_UNAVAILABLE` exacto y ninguna respuesta de éxito son rechazo cerrado,
tanto si sale al arrancar como al atender el cliente.

`vault-completed-loss2.log` es el **RED válido rc1**: control `SUCCEEDED`, una
llamada, rechazo rc4/`CUSTODY_UNAVAILABLE`, **main-vault=1**, claves originales,
conteos `(1,1,1,1,1)` conservados tras restitución, cleanup errors=0. La única
aserción final fallida es `lost custody was replaced automatically`.

Fallback heredado descubierto: `authorization.rs::open_connection` usa
`Connection::open` con creación implícita; ante ruta ausente crea un SQLite vacío
antes de fallar validación. `human.rs::open_connection` usa el mismo patrón.
La comprobación de arranque `serve_loop` ya documentada omite el error de
DelegatedVault::open; continúa atendiendo/ejecutando el worker. La causalidad
estática coincide con la recreación observada, sin afirmar que el nuevo archivo
tenga claves, autoridad o datos válidos. **No se modifica ninguno de esos caminos**:
corregir la creación implícita de un vault perdido exige autorización específica.
El bloqueo audit-loss anterior también se conserva sin tocar
`load_or_create_audit_custody` ni su comportamiento. Un negativo esperado no es
un gate verde ni se oculta del estado de aceptación.

### Inventario restante y fallbacks encontrados en la fase 2

La migración integral permanece **FAIL de inventario**, aunque los grupos
anteriores pasan los controles acotados. Siguen, entre otros:

- Metadata plaintext de records (`String` de título, destinos, tags, usernames,
  paths/labels) y `content.rs::matches_search`: `to_lowercase` de notas/custom
  vuelve a crear Strings ordinarias. No se declara esa metadata una excepción.
- `PreparedHumanCommand` y serializers/chunks propios de backup; buffer de
  `backup.rs::BackupWriter` sigue `Zeroizing<Vec>`. Otros envelopes/serializers
  propios de crypto/vault requieren clasificación caso por caso.
- `onepux.rs::ArchiveInventory`, captura de export.attributes/export.data y
  readers/chunks de ZIP siguen ordinarios. Proteger el parser JSON no protege
  la descompresión previa ni todos los streams de importación.
- Requests/responses/snapshot de proveedor, copias de rpc_prepare_record,
  read_regular/read_import_source/read_tty_password y otros callers de linux.rs.
- Requests/split_exact/display_secret y buffers de presentación de TUI;
  Ratatui retiene símbolos ordinarios. No se ha reescrito el renderer ni se
  ha reducido reveal/copy/search ni ninguna capacidad existente.
- Bodies/scripts/JSON/HTTP/outputs propios de pm-web-auth, y los tramos propios
  pendientes de los demás adaptadores. TLS/russh/Chromium/Argon conservan sólo
  sus excepciones explícitas; no amparan automáticamente esas copias propias.

La inspección del backend locked de 1PUX encuentra otro punto de diseño de
ingeniería que impide afirmar todo el heap protegido: Cargo selecciona
zip 8.6.0 `deflate-flate2-zlib-rs`; flate2 1.1.10 `ffi/zlib_rs.rs::make` llama
zlib-rs 0.6.7 `Inflate::new`; `inflate.rs::init` instala el allocator Rust por
defecto y reserva estado/window juntos. `inflate/window.rs::extend` copia bytes
descomprimidos a ese window ordinario. Evidencia **estática** de fuentes locked,
no extracción de canario en runtime. Esa memoria no figura entre las excepciones
G7 autorizadas. No se cambia dependencia/backend, no se introduce excepción ni
se cierra el punto por inferencia. Resolverlo requiere seleccionar una solución
que conserve ZIP/DEFLATE y comprobarla antes de completar el inventario.

Otros fallbacks heredados observados y conservados:

- `onepux.rs::map_item`: si `notesPlain` existe con tipo distinto de string,
  sustituye notas por vacío; favIndex ausente/no entero pasa a 0. El raw_item
  canónico conserva el origen, por lo que no se afirma pérdida de ese origen.
- `onepux.rs::section_fields`: cualquier error de `parse_totp`, incluido el
  nuevo error de memoria protegida, deriva a `invalid_totp` de source_fields.
  No se cambia esa captura heredada ni se usa como evidencia de denegación
  integral de recursos. Separar input inválido de ResourceUnavailable necesita
  autorización para ese fallback, no un GREEN del fixture por reclasificación.
- `linux.rs::agent_attempt`: una respuesta vacía cae en
  `response.first().copied().unwrap_or(1)`, imprimiendo DENIED code=1. Rechaza
  públicamente pero sustituye la categoría ausente; se conserva.

Las zonas tocadas para composición con 26/27 en **esta fase** se limitan a
linux.rs (constructores/propagación de serializers), sin editar linux/tui.rs ni
cfg nativo. Al integrar, trasladar esos cambios al único engine extraído por
26/27 en tui.rs/human_wire.rs/agent_wire.rs/sync_job.rs. No se tocó ningún otro
worktree ni se integró la rama principal o PR #1.

Archivos de producto tocados en esta fase, sin Cargo.toml/Cargo.lock nuevos:
`crates/pm-crypto/src/{lib,root,protected_text,protected_writer}.rs`,
`crates/pm-vault/src/{lib,authorization,backup,content,human,migration,onepux,plaintext}.rs`
y `crates/pm-custody/src/linux.rs`. Los cambios en pm-sync son únicamente
fixtures de tests. Los fixtures y documentación nuevos no constituyen otra
implementación del engine.

### Estado de criterios 28/G7 al entregar fase 2 — histórico

Esta tabla registró el checkpoint de fase 2 y actualizó fase 1. Su estado es
histórico desde fase 3. Ticket sigue `claimed`; ninguna casilla integral queda resuelta.

| Criterio | Estado y alcance vigente | Evidencia |
|---|---|---|
| PasswordRecord/password/notas, Attachment y decoder AuthRecord | PASS acotado: control pequeño y rechazo de 512 KiB antes de copiar | RED/GREEN anteriores |
| Parsers CSV/JSON y serializers descriptor/completo | PASS acotado; no demuestra todos los paths de import/backup/auth por separado | RED/GREEN anteriores |
| Descifrado inline PMF1 hacia owner exacto | PASS del control de 4 MiB, framing y regresiones de crypto | red-inline-file; green-crypto; check2 |
| Invariancia passkey de 32 bytes tras migrar el owner | PASS del constructor: control válido, rechazo 0/31/33; decoder verifica antes de copiar | red/green-passkey-seed-invariant; final-check |
| Memoria propia integral: records/imports/serializers/providers/presentación | FAIL de inventario; lista concreta arriba | No convertir GREEN acotado en cierre |
| Presupuesto agregado | PASS del contador con 64 KiB configurados sólo en test; 32 MiB físicos y overhead de páginas no demostrados en host de 8 MiB | green-crypto; rlimit observado |
| Guardas Linux/core/dumpable/stdin | PASS acotado heredado y regresión Linux final | final-test-linux-fault-safety-lab.log; final-test-linux-custody-protected-input-lab.log |
| 17.º RATE_LIMITED / CLOCK_UNTRUSTED | PASS acotado de fase 1 y regresión workspace | delegated_authorization; check2 |
| Resto de límites, incluido techo custodial 128 | No demostrado integralmente | No extrapolar suites |
| ENOSPC en WAL + atomicidad/restart | PASS acotado de fase 1 y regresión Linux final | final-test-linux-storage-fault-lab.log |
| Matriz fsync/WAL/staging/commit/outbox/audit y ENOSPC por frontera | No demostrado integralmente; no se añadió una matriz completa en esta entrega | Los casos acotados no la sustituyen |
| Crash/intención sin resultado → INDETERMINATE, no doble login | PASS acotado de attempts con proveedor controlado y regresión final | final-test-linux-attempts-lab.log |
| Bootstrap perdido, intento completado | PASS: sin sustituto, conteos/claves exactos y proveedor=1 | final-bootstrap-completed-loss.log |
| Vault perdido, intento completado | FAIL bloqueado por autorización: crea SQLite sustituto aunque rechaza rc4; proveedor=1 y restitución exacta pasan | final-vault-completed-loss.log |
| Audit-custody perdido | FAIL bloqueado por autorización: regeneración/CRUD aceptado; no corregido | final-audit-custody-loss.log separado |
| Otras variantes de pérdida en vivo/en vuelo/ambigua | No demostrado; pruebas ambiguas actuales no discriminan audit repetido de reconciliación | bootstrap-loss3/vault-loss no son RED válido |
| Todos los canales de canarios activos/históricos y core/crash | No demostrado integralmente; inventario y lecturas completas faltan | No aceptar lectura truncada como ausencia |
| Windows VirtualLock/WER y macOS nativo | Diferido; sin cierre ni cfg nuevo por inferencia | 26/27 y futura evidencia 30–32 |
| Gates finales Linux | PASS: check completo, clean offline y 26/26 labs uniformes | Logs finales debajo |
| Integración y revisión independiente | Pendiente; no autorizada a este implementador | PR #1 no fusionado |

### Gates finales de esta fase y límite de la entrega

Después de la corrección passkey y sin cambios posteriores de producto:

- `final-check.log` rc0: fmt/check/test/clippy completos, locked/offline.
- `final-clean.log` rc0: build limpio de todos los targets, 36.56 s.
- `final-bootstrap-completed-loss.log` rc0: cierre rc4, sustituto=0,
  cinco conteos y claves originales, proveedor=1, cleanup errors=0.
- `final-vault-completed-loss.log` rc1: cierre rc4 correcto pero main-vault=1;
  cinco conteos/claves y proveedor=1 al restituir, cleanup errors=0. RED bloqueado.
- `final-audit-custody-loss.log` rc1: CRUD rc0/closed=0 y replacement-created=1,
  restitución original y cleanup errors=0. RED bloqueado; no tiene proveedor.
- Barrida final uniforme rc0, **26/26** en **622.12 s**:
  `final-labs-summary.log`, un `flock` y log
  `final-test-linux-<nombre>-lab.log` por cada uno de los 26 scripts.
  Los rc0 son regresiones acotadas; no acreditan el criterio integral de
  canarios ni corrigen los cleanups heredados ya reportados.

Se comprobaron enlaces locales/anchors, AST Python, shell syntax,
`git diff --check`, estado `claimed` y conservación byte a byte de
`load_or_create_audit_custody` respecto a `e3fb352`; el fixture audit-loss
original tampoco cambió. Se retiraron sólo los dos `__pycache__` creados por
estas corridas, por inventario exacto de sus cinco archivos. Logs y baseline
test-only se retienen como artefactos de revisión; no se barró `/tmp/pm-*`.

```sh
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh bootstrap completed
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh vault completed
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh audit
# Repetir una vez por cada script enumerado, secuencialmente y con log propio:
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3 PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64 flock /tmp/pm-cargo-window.lock ./scripts/test-linux-storage-fault-lab.sh
```

La entrega es un checkpoint **parcial**, no la finalización del objetivo de
fase 2 ni de G7. La regla de conservar fallbacks heredados detiene la corrección
del vault perdido, audit custody y captura TOTP; no se usa ese bloqueo para
declarar cumplidos los demás criterios. Quedan trabajo y evidencia pendientes
en memoria, matriz de fallos y canarios enumerados arriba. Siguiente acción del
orquestador: resolver las autorizaciones acotadas, componer los tipos con 26/27
y continuar esos verticales sobre el engine único. No integrar este checkpoint
como cierre de seguridad ni marcar 28 resolved.

## Fase 3 — 2026-10-03: custodia audit autorizada

Base limpia `d4550ce`. El usuario autoriza cambiar el comportamiento sólo de
`load_or_create_audit_custody`: si el dispositivo tiene una generación en
`audit_keys`, ausencia/ilegibilidad de su archivo exige `CUSTODY_UNAVAILABLE`.
Primera inicialización puede crear. No cambia formato ni los demás fallbacks.
La consulta será read-only para el device exacto, antes de generar claves;
no se trata un error de lectura/schema como estado nuevo. Se usa `rusqlite`
ya fijado en el workspace/lockfile, sin instalar dependencias ni tocar pm-vault.
Sólo se añaden los parámetros vault/device a los dos callers del loader.

Método de función (§3): vaults sintéticos independientes; primera creación y
relectura exacta; inicialización humana real con generación audit y evento de
autoridad antes del control; archivo ausente o modo 000 rechaza sin sustituto;
rename/restauración del original permite reabrir autoridad con DB idéntica.
Vault ausente o schema ilegible no puede habilitar generación de audit keys.
Cleanup checked incluso tras panic, sin imprimir secretos.

El lab existente exige sockets tras el reinicio; el loader corregido rechaza
antes de crearlos. Se ajustará únicamente la observación para admitir ese
rc4/diagnóstico exacto al arrancar, conservando rechazo de admisión, prohibición
de reemplazo, original restituido y restart. No se debilita el oráculo. Un
arranque fallido se consume y valida, nunca se anuncia vivo ni se reintenta.

Siguiente seam (§1, providers): serializer real `pm-web-auth::provider::response`,
compartido por browser/exchange/GitHub/passkey/reconcile. Subprocess con memlock
32 KiB verifica un campo pequeño y emite control; un canario estático de 64 KiB
(dentro del límite wire de 128 KiB) debe rechazarse antes de copiar. Baseline
infalible se envuelve sólo en `Ok` dentro del test; al migrar la API a fallible
se retira ese `Ok`, conservando exactamente la aserción. Parent sólo muestra
marcadores/status. GREEN usará `ProtectedWriter` de tamaño checked exacto y
propagará fallo al loop del proveedor sin frame sustituto. Esto sólo acredita
el owner final del response, no JSON/browser/HTTP ni todos sus buffers fuente.

Seam real adicional de §2: control CRUD íntegro y caso EIO, cada uno en un vault
nuevo. Interposer del fixture observa `fsync`/`fdatasync` del WAL exacto, comprueba
PID propio mediante archivo persistido antes de enviar la request y falla sólo
el primero; registra operación/contador/PID, sin contenido. Error de registro
termina el sujeto, nunca da evidencia silenciosa. El caso negativo exige rc4,
DB byte a byte idéntica y conteos de items/revisions/streams/authority/outbox/
receipts/audit_keys/audit_records originales, staging vacío e integridad/restart.
No reenvía CRUD ni usa proveedor. Acredita primera frontera WAL de admisión
humana/audit, no todas las fronteras ni intención después de transmisión.
Escaneo de almacenamiento propio quiescente con inventario explícito, conteo
completo de bytes y overlap entre chunks; falla por lectura parcial/canario.
No se presenta como todos los canales activos/históricos de §4.

### Cronología y alcance verificado de fase 3

- Audit-loss RED válido rc1 sobre `d4550ce`:
  `/tmp/pm28-20261003-red-audit-custody-loss.log`, con control inicializado,
  CRUD rc0/closed=0, replacement-created=1, restitución y cleanup errors=0.
- Función: `red-audit-function.log` y `red-audit-function2.log` son errores de
  API del fixture y no RED. `red-audit-function3.log` rc101 compila y falla
  después del control audit+autoridad al regenerar custodia ausente. El GREEN
  `green-audit-function.log` rc0 pasa cinco casos; primera inicialización y
  archivo ilegible ya pasaban en el baseline, no se inventa RED para ellos.
- Audit-loss GREEN rc0: `green-audit-custody-loss.log`, rc4/closed=1,
  replacement-created=0, original-restored=1, restart y cleanup errors=0.
  El fixture ahora observa el rechazo exacto antes de sockets y retira sólo los
  dos nombres de socket propios dejados por SIGTERM para no confundirlos con
  listeners nuevos. Conserva las dos aserciones finales de ausencia de
  sustitución y admisión cerrada; no usa proveedor.
- Response web: `red-web-response.log` rc101, compilación/control confirmados,
  destino ordinario aceptado bajo memlock. `green-web-response.log` rc0, 8/8
  unidades web; response final protegido hasta write_frame, sin Clone/Debug
  ni conversiones a Vec. Los parseos y buffers fuente siguen pendientes.
- SQLite real: `sqlite-sync.log` rc0, control íntegro y EIO único del syscall
  WAL en vaults nuevos, rechazo/rollback/integridad/restart. Es GREEN de
  comportamiento existente y no originó corrección productiva ni RED ficticio.
- `check.log` llegó a completar las suites y falló sólo en tres lints de
  igualdad en los fixtures. Se cambiaron a booleanos `.eq`, preservando que un
  fallo no imprima claves privadas. `check2.log` rc0: configuración, build
  inputs, fmt, check/test/clippy workspace all-targets locked/offline.

Los nombres abreviados de esta fase llevan `/tmp/pm28-20261003-`.
Comandos exactos, siempre cwd `.worktrees/28-fault-safety`:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh audit
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-custody --lib linux::audit_custody_tests --locked --offline -- --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-web-auth --lib provider::protected_response_tests::provider_response_requires_locked_destination --locked --offline -- --exact --nocapture
# GREEN web agrupado:
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-web-auth --lib --locked --offline -- --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh sqlite-sync
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
```

### Inventario restante, límites y fallbacks de fase 3

Memoria integral sigue **FAIL**, con evidencia estática concreta:

| Owner/copia pendiente | Ubicación | Alcance que falta |
|---|---|---|
| Request al proveedor y secreto SSH temporal | `linux.rs::call_controlled_provider/call_ssh_provider` | Zeroizing<Vec>/Vec; responses entrantes ya usan reader protegido, no las requests |
| Access/id token, form y HTTP body propios | `pm-web-auth/src/{exchange,oidc,github}.rs` | Strings/JSON/Vec y clones propios antes del response migrado |
| Scripts, escape JS y mensajes CDP | `browser.rs::authenticate/command/read_message` | Copias propias plaintext; la excepción Chromium no cubre el cliente CDP |
| Perfil provider y copias de parseo | `provider.rs::read_private/handle_browser/handle_passkey` | Perfil Vec y algorithm/username ordinarios; clasificación integral pendiente |
| Metadata, búsquedas, prepared commands y backup | `pm-vault/src/{content,human,backup}.rs` | String/to_lowercase, serializers/chunks y owners ordinarios heredados de fase 2 |
| ZIP/DEFLATE y readers de import | `onepux.rs` y fuentes locked de zlib-rs | Estado/window ordinarios sin excepción G7; seleccionar solución que conserve ZIP |
| Presentación TUI y requests/split_exact | `linux/tui.rs` y Ratatui | Cell/String y requests propios; se conserva reveal/copy/search y no se refactorean zonas concurrentes |
| Lecturas de claves/inputs y otros serializers | `linux.rs::read_regular/read_import_source/read_tty_password/...` | Memoria ordinaria previa a owners finales protegidos; inventario no cerrado |

Puntos que requieren coordinación antes de tocarse: la presentación intersecta
las zonas TUI extraídas por 26/27, que este encargo prohíbe refactorizar. Opciones:
componer luego un renderer protegido conservando capacidades, o añadir una
excepción/reducir reveal. Se recomienda la primera; las otras no están
aprobadas. ZIP/DEFLATE también requiere una solución de ingeniería validada;
no se cambia backend ni se amplían excepciones en este checkpoint.

Fallbacks/silenciamientos heredados adicionales inspeccionados y **conservados**:

- `provider.rs::serve`: error de read_frame continúa sin responder; fallo de
  write_frame se descarta y sigue el loop. Puede ocultar una request truncada o
  una respuesta perdida. No se cambia ninguna de esas ramas.
- `provider.rs::handle_{github,browser,exchange}`: el error al copiar un campo
  secreto a ProtectedBytes se agrupa con parseo inválido y responde status4
  (`UNSUPPORTED_INTEGRATION`). No se presenta eso como denegación integral de
  recursos ni se reclasifica el error sin autorización acotada. Opciones:
  separar error de recursos y cerrar la operación, o preservar el status
  sustituto; se recomienda lo primero para un futuro cambio autorizado.
- `browser.rs::Browser::stop`: descarta errores de kill/wait/remove_dir_all;
  puede ocultar proceso/perfil residual al cerrar. No se amplía la autorización
  histórica de los cuatro cleanups a este lugar.

Las autorizaciones pendientes de vault SQLite vacío, notesPlain/favIndex,
TOTP→source_fields, respuesta vacía→DENIED, ProcessTlsTransport::put, sync_stage,
from_utf8_lossy y demás handoff siguen vigentes. Ninguna se considera concedida.

Archivos de producto de fase 3: `crates/pm-custody/src/linux.rs` (loader y sus
2 callers), `crates/pm-web-auth/src/provider.rs` (serializer/propagación),
`crates/pm-custody/Cargo.toml` y `Cargo.lock` (dependencia directa de rusqlite ya
fijada). No cambia pm-vault, formato, KDF, deadlines, limits, cfg nativo,
tui.rs/human_wire.rs/agent_wire.rs/sync_job.rs ni otros worktrees.
Conflicto previsto de composición con 26/27: mover loader/callers de linux.rs
al único engine extraído; Cargo.lock puede requerir composición mecánica. No
se integra en principal, no se fusiona PR #1 ni se resuelve ticket 28.

### Estado histórico de criterios 28/G7 — fase 3 (checkpoint parcial)

Esta tabla sustituyó el estado de fase 2. El estado vigente está en W3 al final
de este documento; se conserva esta cronología.

| Criterio | Estado y alcance vigente | Evidencia |
|---|---|---|
| Records/password/notas/Attachment, decoder AuthRecord y serializers acotados | PASS acotado heredado; no todos los owners | RED/GREEN de fase 2; check2 |
| Parsers CSV/JSON e inline PMF1 | PASS acotado heredado | Fase 2; check2 |
| Invariancia passkey 32 bytes | PASS del constructor/decoder | Fase 2; check2 |
| Response sensible custody y frames protegidos ya migrados | PASS acotado; no todos los caminos | Fase 1; check2 |
| Response final web-auth compartido | PASS: owner exacto locked antes de copiar, control 32 KiB y rechazo 64 KiB | red/green-web-response; check2 |
| Memoria propia integral/providers/presentación/owners restantes | FAIL de inventario; zonas TUI concurrentes y ZIP aún sin solución integrada | Tabla de inventario fase 3 |
| Presupuesto agregado | PASS contador test-only 64 KiB; 32 MiB físicos/overhead no demostrados con host memlock 8 MiB | Fase 2; check2 |
| Guardas Linux/core/dumpable/stdin | PASS acotado heredado | final-test-linux-fault-safety-lab; final-test-linux-custody-protected-input-lab |
| 17.º RATE_LIMITED y CLOCK_UNTRUSTED | PASS acotado heredado | delegated_authorization; check2 |
| Resto de límites, incluido techo custodial 128 | No demostrado integralmente | No extrapolar los controles acotados |
| ENOSPC en WAL + atomicidad/restart | PASS acotado heredado | final-test-linux-storage-fault-lab.log |
| Primera sincronización WAL de admisión humana/audit | PASS acotado: EIO real único, rc4, DB/conteos intactos y restart | sqlite-sync.log; final-sqlite-sync.log |
| Matriz fsync/WAL/staging/commit/outbox/audit y ENOSPC por frontera | No demostrado integralmente | Primera frontera nueva no sustituye todas las restantes |
| Crash/intención sin resultado → INDETERMINATE, no doble login | PASS acotado heredado de attempts | final-test-linux-attempts-lab.log; no todos los proveedores |
| Bootstrap perdido con intento completado | PASS: claves/conteos originales, sustituto=0, proveedor=1 | final-bootstrap-completed-loss.log |
| Vault perdido con intento completado | FAIL bloqueado por autorización: crea SQLite vacío aunque rechaza rc4 | Test sin modificar; final-vault-completed-loss.log rc1 |
| Audit-custody perdido/ilegible; primera inicialización; restitución exacta | PASS acotado autorizado: sin generación sustituta; loader falla antes de listeners | RED/GREEN audit; 5 tests función; check2 |
| Pérdidas en vivo/en vuelo/ambiguas | No demostrado integralmente | Audit-loss no tiene proveedor; no atribuirle no-doble-login |
| Canarios activos/históricos en todos los canales, agente y core/crash | No demostrado integralmente | Escaneo completo nuevo sólo de almacenamiento propio quiescente y salidas CRUD |
| Windows VirtualLock/WER y macOS nativo | Diferido | 26/27 y gates 30–32; sin evidencia inferida de Linux |
| Check completo y build limpio | PASS | check2.log rc0; clean.log rc0 en 36.73 s |
| 26 labs Linux secuenciales + audit-loss + SQLite-sync | PASS acotado: 26/26 rc0, audit-loss y SQLite-sync rc0 | final-labs-summary.log; final-focused-summary.log |
| Integración por merger/revisión independiente | Pendiente, fuera de esta entrega | Ticket claimed; PR #1 borrador sin fusionar |

La matriz completa de fallos y los canales integrales de canarios **no se
completaron en esta fase**. Se entrega el checkpoint verificado solicitado,
no un cierre de fase 3/G7. Siguiente vertical: migrar requests de proveedor y
fuentes HTTP/JSON/CDP con RED propio; coordinar presentación después de componer
26/27; continuar cada frontera real de §2 y cada canal de §4 sin retries,
lecturas truncadas ni oráculos reducidos. El fallback SQLite perdido continúa
bloqueado por autorización del usuario a través del orquestador.


### Gate final y entrega del checkpoint de fase 3

Sin cambios posteriores de producto ni fixtures de los 26 labs:

- `check2.log` rc0 y `clean.log` rc0, build en **36.73 s**.
- `final-audit-custody-loss.log` rc0: rc4/closed=1, reemplazo=0,
  original restituido, restart y cleanup errors=0.
- `final-sqlite-sync.log` rc0: control CRUD rc0 con 24 llamadas WAL;
  caso EIO en el primer `fsync`, llamadas=1/inyecciones=1, cliente rc4,
  DB y 9 conteos intactos, staging vacío, siete archivos propios leídos
  completos, canario ausente, integridad/restart y cleanup errors=0.
- `final-bootstrap-completed-loss.log` rc0: proveedor=1, sustituto=0,
  cinco conteos/claves exactos y restitución/cleanup verificados.
- `final-vault-completed-loss.log` **rc1 esperado y separado**: rechaza rc4,
  main-vault=1; proveedor=1 y cinco conteos/claves/restauración exactos,
  cleanup errors=0. Continúa RED bloqueado por autorización; no se oculta
  dentro de un summary de labs verdes.
- Barrida única final de los 26 scripts existentes: **count=26 failures=0**,
  **1085.97 s**, `final-labs-summary.log`. Logs individuales
  `final-test-linux-<nombre>-lab.log`. Ese tiempo y los tiempos por caso incluyen
  espera del lock compartido con 26/27; no indican ampliación de deadlines.
  Se adquirió un flock por invocación, sin paralelismo/retries de producto.
  Audit-loss y SQLite-sync corren aparte del 26/26, ambos rc0.

Se comprobaron AST Python, shell syntax, enlaces locales, diff, estado claimed,
y conservación exacta de pm-vault, zonas TUI/sync/cfg y custody_loss_lab.py
respecto a d4550ce. Las regiones propias centrales siguen sin Debug/Clone y
sus excepciones G7 no se amplían. Se retienen los logs para el orquestador;
cleanup de cada fixture se comprobó antes de PASS. Se retiraron los dos
archivos propios linux_lab/storage_fault_lab.cpython-314.pyc y su __pycache__
exacto, verificando ausencia. No se barreron temporales
ajenos ni se retiró el worktree. La integración/revisión independiente sigue
fuera de esta entrega.

Comandos adicionales del gate final:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh bootstrap completed
flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh vault completed # RED esperado, no corregido
# Por cada uno de los 26 scripts enumerados, con log propio y rc propagado:
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3 PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64 PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/test-linux-storage-fault-lab.sh
```

## Fase 4 — 2026-10-03: providers sobre la integración

Base verificada `36eecc8c365328ca4c8ca074ae013564767d79b7`; worktree propio
`.worktrees/28-g7-phase4`, rama `codex/pm-28-phase4`. No cambia el estado del
issue ni se integra en principal. La composición mueve TUI/handlers a
`tui.rs`, `human_wire.rs`, `agent_wire.rs` y `sync_job.rs`.

Concreción de §1 antes de GREEN: subprocess por seam, control válido completo
y luego denegación real de memlock. HTTP fijo/chunked, form, JSON y JavaScript
usan control pequeño con 32 KiB y fuente estática sintética de 64 KiB, dentro
del límite existente; no se imprime el contenido. GitHub valida el request
completo antes de bajar memlock a cero y exige rechazo al serializar el mismo
PAT sintético. CDP controla una respuesta válida, baja memlock a cero y exige
rechazo con cero bytes consumidos del reader. `read_cdp_message` se extrae
sin cambiar el loop de lectura para probar el reader utilizado por Browser.
Las APIs infalibles form/js se envuelven sólo en `Ok` en el fixture RED; ese
wrapper se retira cuando la API pase a fallible, sin cambiar el oráculo.
Un error de compilación no acredita RED. Los procesos hijos conservan stdout/
stderr completos en memoria del fixture; se muestran sólo marcadores seguros.

Comando RED (cwd del worktree, log `/tmp/pm28p4-red-provider-sources.log`):

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-web-auth --lib memory_tests --locked --offline -- --nocapture
```

Fallback nuevo inspeccionado, conservado: `browser.rs::wait_for_view`, diagnóstico
tras timeout, usa `unwrap_or(false)`, `unwrap_or("?")` y `unwrap_or("")` si
faltan campos de la vista. Sustituye valores desconocidos en el diagnóstico;
el intento sigue fallando. Opciones: categorías explícitas de campos ausentes
o mantener los sustitutos. Se recomienda distinguir ausencia explícitamente
en un correctivo autorizado; no se cambia esta rama en fase 4.

Siguiente RED de §1: se extrae el encoder realmente usado por requests
controladas, metadata SSH, password SSH tardío y respuesta de firma, preservando
prefix/fields/suffix byte a byte. Control independiente completo antes de bajar
memlock a cero; serializar los mismos campos debe fallar antes de producir
request. El fixture no abre una conexión ni repite un login. GREEN usará el
ProtectedFrameWriter ya integrado, con tamaños checked exactos y sin adapters
Vec. Los labs de providers comprobarán compatibilidad de esos callers.

Concreción adicional de §1 para TUI: subprocess con control UTF-8/escapes de
`split_exact` (seam real de master_rotate e importación), luego memlock=0 y
misma entrada válida, debajo de 32 KiB. Otro caso controla el encoder real de
requests master-rotate/native-restore y exige rechazo memlock=0. Se extrae ese
encoder sin cambiar bytes/semántica para el RED. GREEN limitará el cambio a
owners únicos de campos y requests: sin cambiar footer, resumen, etiquetas,
confirmaciones ni capacidades. Ratatui/reveal sigue pendiente; proteger esos
dos seams no acredita sus Cell/String internos.

Verificación de compatibilidad del helper propio: comparar recursivamente JSON
válido con el parser previo (texto/números exactos, Unicode/control, claves y
orden) y exigir el mismo rechazo de duplicados, surrogates, profundidad y
trailing. Probar lectores completos con EOF, exceso de límite, CDP máximo con
NUL y truncamiento; no aceptar un owner parcial. Es extensión concreta de §1,
sin ampliar gramática, límites ni excepciones G7.

### Inventario de fase 4 y fronteras conservadas

Owners migrados: fuentes/valores de los tres perfiles web; request GitHub,
forms OIDC/exchange, HTTP entero/cuerpo fijo/chunked; JSON propio (también
claves/números desconocidos); segmentos JWT, tokens/resultados/serializers;
state/nonce/verifier, scripts/escapes, mensajes CDP/evaluación y callback HTTP.
El encoder de CDP toma vistas prestadas; las estructuras Vec contienen nodos,
punteros o metadata numérica, nunca un payload secreto ordinario. Los owners
sensibles no ganan Debug/Clone/Display ni conversiones a Vec. La excepción TLS
PKCS8 ya existente (`callback_key`→rustls) sigue pendiente de evaluación de la
biblioteca: su fuente propia ahora está locked, pero `key.to_vec()` conserva
la copia requerida por la API rustls prevista en G7; no se acredita como locked.
RNG/TOTP producen su salida propia directamente en destino protegido. Heap
Chromium, TLS/crypto y russh no quedan acreditados por estos cambios.

Custody: encoder exacto compartido por las requests controladas, metadata SSH,
password SSH tardío y firma. El presupuesto y límites wire no se cambian.
TUI: `split_exact` mide escapes/UTF-8 sin almacenar texto y después escribe en
owners ProtectedText; native-restore/master-rotate reservan su request exacta
antes de copiar la maestra. Se conservan las confirmaciones y los valores del
resumen. `render_footer`, `decode_import_preview` y el bloque que construye
`Mapping=... duplicate-action=...; {summary}` se comprobaron byte a byte
idénticos a la base. No se ha resuelto el resumen recortado.

Los nuevos errores de memoria web posteriores al parseo de la request se
conservan tipados y se propagan sin fabricar respuesta; los diagnósticos de
etapa usan inspect_err. Las closures `parsed` de handle_github/browser/exchange
siguen agrupando el error de las copias ProtectedBytes preexistentes con parseo
y status4: **ese fallback no se corrige**. `provider::serve` y `Browser::stop`
se comprobaron idénticos a la base. No se modifican listener/dispatcher,
admisión, `provider: None`, carriles macOS, Windows ni engine.

Inventario integral sigue **FAIL**: pm-ssh-client (perfil/resultado propios y
request de firma; la contraseña String de russh pertenece a la excepción
explícita de la biblioteca); `human_wire::handle_recovery_rotation` conserva
RecoveryCode Display→hex/String→Vec, y `encode_catalog` conserva metadata Vec;
`agent_wire::encode_attempt_snapshot` conserva resultado Vec y los owners de
admisión/contexto previos. TUI reveal conserva display_secret/sanitize_text,
format de Exposure, Paragraph/Cell de Ratatui; import/sync/streams y metadata
ordinaria restante no se migraron. ZIP/DEFLATE y el resto del inventario de
fase 3 continúan abiertos. No hay una excepción nueva que los declare seguros.

Fallbacks/silenciamientos adicionales encontrados por lectura, **sin corrección
ni RED runtime propio en esta fase**:

| Lugar | Activación | Sustitución u ocultación conservada |
|---|---|---|
| `Profile::value` / `ExchangeProfile::value` web | Getter de una clave ausente | Devuelve `""`; la validación previa cubre claves requeridas, el method opcional también usa esta representación. |
| `pm-ssh-client::read_frame/authenticate`→`serve` | Alloc/mlock propio falla | Lo convierte en Error::Io; el dispatcher emite frame3 indeterminado, agrupado con I/O/SSH. |
| `pm-ssh-client::serve`, carril consumer | read_frame o parseo inválido | Continúa el loop sin devolver la causa. |
| `agent_wire::serve_agent` | read_frame falla, también por alloc/mlock | Retorna Ok y cierra el carril sin conservar la categoría del fallo. |
| `tui::display_secret` | Secreto no UTF-8 | Muestra `<binary secret: N bytes>`; no los bytes. Es comportamiento heredado y su test binario sigue intacto. |

Opciones para las fallas operativas: conservar estas sustituciones, o separar
categorías tipadas y propagarlas por el workstream autorizado de dispatcher/
proveedor. Se recomienda la segunda. Este checkpoint se detiene antes de
ampliar esos owners cuando exigiría introducir otra clasificación sustituta o
cambiar esa frontera prohibida. Para getter/presentación, distinguir ausencia
y representación binaria explícitamente en una decisión propia, preservando
las capacidades humanas; no inferir autorización desde G7.

Los fallbacks enumerados por el usuario (SQLite perdido/implícito, sync .or_else,
notesPlain/favIndex, TOTP→source fields, respuesta vacía→DENIED, frames provider,
Browser::stop, ProcessTlsTransport::put, sync_stage, from_utf8_lossy, Drops
Windows/LocalFree/DestroyWindow) siguen sin corrección en esta entrega.

### Ajustes del harness tras la primera barrida

La primera barrida queda íntegra en `/tmp/pm28p4-local-summary.log` y
`/tmp/pm28p4-local-results.json`: dos diferencias adicionales a la base,
adapter-protected-frame y passkey-login. No se contabiliza como gate verde.
Concreción de §1 antes de volver a ejecutar: el perfil web ahora necesita
memlock antes de bind. El lab exige primero rechazo rc4/sin socket cuando se
deniega desde exec; después arranca un control válido con su perfil protegido,
usa `prlimit` en ese PID propio para bajar soft/hard a cero y conserva exactamente
el oráculo de frame: sólo header de longitud, cero payload enviado, cierre sin
timeout ni respuesta. El carril SSH conserva el control anterior memlock=0.
No se relaja la aserción ni se concede memoria ordinaria para arrancar web.

En passkey-login el primer fallo observado es CUSTODY_UNAVAILABLE tras un
reinicio, no una aserción de tokens/WebAuthn. El harness usaba existencia de
path como readiness y dejaba los sockets del PID anterior: podía devolver
readiness antes de que el custodio nuevo reemplazara esos paths. Concreción
de la regresión existente: después de terminar y observar el PID exacto,
validar tipo socket y retirar sólo `agent.sock`/`human.sock` propios antes de
cada reinicio. Se exige aparición nueva en el mismo plazo y se repite el lab
entero en fixture nuevo; no se reenvía ninguna operación/login dentro del caso.
Esta corrección no cambia listener/dispatcher de producto.

Fallbacks adicionales del harness passkey-login conservados: `stop` sustituye
SIGTERM por SIGKILL si agota 8 s y el finally usa
`shutil.rmtree(root, ignore_errors=True)`, ocultando errores al retirar su raíz.
Se reportan sin corregir: no se acredita cleanup integral §4 con ese lab.

### RED/GREEN y compatibilidad nuevos

Todos los comandos siguientes se ejecutaron con cwd del worktree propio y
`flock /tmp/pm-cargo-window.lock`, locked/offline. Cada RED llegó al control
válido completo y compiló: la falla discriminante fue aceptar el owner
ordinario después de denegar memlock, no compilación ni dependencia.

| Seam real | RED | GREEN y regresión |
|---|---|---|
| HTTP fijo/chunked, form, JSON, request GitHub, JavaScript y CDP | `pm28p4-red-provider-sources.log` rc101: 7/7 fallan después de control | `pm28p4-green-provider-sources.log` rc0: 15/15; check3 incluye además 3 controles de compatibilidad, 18/18 lib y 6/6 profiles |
| Requests custody hacia providers, incluido password SSH tardío | `pm28p4-red-custody-provider-request.log` rc101: 1 fallo después de control de layout | `pm28p4-green-custody-provider-request.log` rc0: 1/1 |
| TUI split con UTF-8/escapes y request restore/rotate | `pm28p4-red-tui-owners.log` rc101: 2/2 fallan después de control | `pm28p4-green-tui-owners.log` rc0: 17/17, incluidos los 2 nuevos |

Comandos de los tres RED, en ese orden:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-web-auth --lib memory_tests --locked --offline -- --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-custody --lib linux::provider_memory_tests --locked --offline -- --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-custody --lib tui::memory_tests --locked --offline -- --nocapture
```

Para GREEN se usó `--lib` sin filtro en web, el mismo filtro de request custody,
y `tui::` en TUI. Las APIs form/js ahora fallibles sustituyen sólo el wrapper
Ok del fixture RED; controles, límites y canarios permanecen iguales.
Los errores de compilación intermedios (`green-provider-sources-build1/2`,
`green-tui-owners-build1`, `check1`) y ajustes Clippy (`check2`) quedan en
`/tmp/pm28p4-*.log`, **no son RED de producto**.

El parser propio preserva gramática previa, números exactos y Unicode; rechaza
duplicados, surrogates, profundidad y trailing igual que el parser anterior.
Los readers rechazan truncamiento/exceso y sólo devuelven fuentes completas.
Los controles nuevos usan datos sintéticos estáticos identificables; no se
copian credenciales reales ni se imprimen payloads secretos en asserts.

### Estado histórico de criterios 28/G7 — fase 4 (checkpoint parcial)

Esta tabla sustituyó el estado de fase 3; el estado vigente está en W3 al final de
este documento. Ningún PASS acotado cierra G7 ni el ticket. La integración y la revisión
independiente siguen a cargo del orquestador.

| Criterio | Estado y alcance vigente | Evidencia |
|---|---|---|
| Records/password/notas/Attachment, decoder AuthRecord y serializers | PASS acotado heredado | Fase 2; check3 |
| Parsers CSV/JSON e inline PMF1 | PASS acotado heredado | Fase 2; check3 |
| Passkey de 32 bytes | PASS del constructor/decoder heredado | Fase 2; check3 |
| Response sensible custody y frames ya migrados | PASS acotado heredado; no todos los caminos | Fase 1; check3 |
| Response final web-auth compartido | PASS acotado heredado | Fase 3; check3 |
| Sources/requests propios HTTP/JSON/CDP y resultados web | PASS acotado nuevo; no heaps TLS/Chromium/russh ni todo pm-ssh-client | 7 RED/GREEN, parser/readers y labs web/GitHub/exchange/passkey |
| Requests custody hacia providers | PASS acotado nuevo | RED/GREEN request y labs proveedores; bytes/semántica conservados |
| Owners TUI split y requests restore/rotate | PASS acotado nuevo | 2 RED/GREEN; 17/17 TUI; footer/resumen intactos |
| Memoria propia integral, wires y presentación restante | **FAIL de inventario** | Inventario fase 4: SSH, recovery, snapshot, import/sync, Ratatui, ZIP/DEFLATE |
| Presupuesto agregado | PASS contador test-only 64 KiB; 32 MiB físicos/overhead no demostrados | Fase 2; host memlock 8 MiB; no se amplía |
| Guardas Linux/core/dumpable/stdin | PASS acotado heredado | Labs fault-safety/custody-protected-input |
| 17.º RATE_LIMITED y CLOCK_UNTRUSTED | PASS acotado heredado | delegated_authorization y labs autorización |
| Límites restantes, incluido techo custodial 128 | No demostrado integralmente | Sin nuevas pruebas de estos techos |
| ENOSPC WAL + atomicidad/restart | PASS acotado heredado | Lab storage-fault |
| Primer fsync WAL de admisión humana/audit | PASS acotado heredado: EIO real único | Caso SQLite-sync |
| Matriz fsync/WAL/staging/commit/outbox/audit y ENOSPC por frontera | **No demostrado integralmente** | No se añadieron fronteras §2 en esta fase |
| Crash/intención sin resultado → INDETERMINATE, no doble login | PASS acotado heredado | Lab attempts; no todos los proveedores/fronteras |
| Bootstrap perdido con intento completado | PASS acotado heredado | Caso bootstrap-completed |
| Vault perdido con intento completado | **FAIL sin autorización para corregir** | red-vault rc1: main-vault=1; rechazo rc4 no basta |
| Custodia de auditoría perdida/ilegible, inicialización y restitución | PASS acotado heredado autorizado | Caso custody-audit |
| Pérdidas en vivo/en vuelo/ambiguas | No demostrado integralmente | Sin extensión §3 en esta fase |
| Canarios activos/históricos, todos los canales y UID agente/core/crash | **No demostrado integralmente** | No se añade escaneo integral §4; labs acotados no lo sustituyen |
| Purge/outbox de revisión purgada | **RED heredado separado de gates** | red-purge: QueryReturnedNoRows; no se corrige |
| Windows VirtualLock/WER y macOS nativo | Diferido | Sin evidencia nativa nueva; seams no acreditan soporte |
| Check completo y build limpio | PASS | check3 rc0; clean-offline rc0 en 35.16 s |
| Barrida final de 36 casos frente a integración | Sin regresión frente a base: 33 rc0, TUI mismatch conocido y 2 RED separados | pm28p4-local-final-summary.log/JSON: BASELINE_CHANGES=0, mismatches=1 |
| Integración/revisión independiente | Pendiente, fuera de esta entrega | Rama propia; ticket/PR #1 sin cambio de estado |

### Archivos y siguiente frontera

Producto: `pm-web-auth/src/{lib,provider,oidc,exchange,github,browser,plaintext}.rs`
y `pm-custody/src/{linux,tui}.rs`. Fixtures: cuatro módulos web de soporte/memoria,
dos custody de memoria, `pm-web-auth/tests/{profile,passkey_login_lab}` y
`pm-custody/tests/adapter_protected_frame_lab`. Documento: este método/evidencia.
No cambia Cargo.lock, dependencias, workflows ni configuración del host.

Conflictos previsibles: `linux.rs` en packing/callers del worker de providers;
`provider.rs` en propagación posterior al parseo y reader de perfil; `tui.rs` en
split/restore/rotate y adaptación de callers. Los correctivos de proveedor pueden
tocar las mismas regiones. Listener/dispatcher/admisión no tienen ediciones
directas de esta entrega, ni los archivos `human_wire`, `agent_wire`, `sync_job`
y Windows. Las fronteras prohibidas y el footer/resumen se conservan.

Siguiente acción: el orquestador decide la propagación explícita de fallos de
memoria SSH/agente en el correctivo autorizado, preservando capacidades; después
migrar sus owners y los de presentación con RED propio. Continuar §2 con vault
nuevo por frontera y §4 con inventario/canales completos. No atribuir cierre
integral a estos GREEN ni corregir SQLite/purge u otros fallbacks sin autorización.

### Gate final del checkpoint de fase 4

Los últimos cambios de producto preceden a `check3` y al build limpio; después
sólo cambian los dos harness descritos y esta evidencia. No se repiten gates
Cargo sin una modificación que los invalide. La barrida final reutiliza sus
logs completos en sus dos primeras filas y ejecuta los restantes 34 casos,
secuenciales, un flock por invocación:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
# Runner local: enumera exactamente los 36 casos de integración, rc propagado,
# cada comando con flock y artifacts aprobados; no modifica fixtures ajenos.
PYTHONDONTWRITEBYTECODE=1 python3 /tmp/pm28p4-run-local-final.py > /tmp/pm28p4-local-final-summary.log 2>&1
```

Resultados verificados:

- `/tmp/pm28p4-check3.log` rc0: fmt, config/build-inputs, workspace check/test
  all-targets y Clippy. `/tmp/pm28p4-clean-offline.log` rc0: build limpio locked/
  offline, **35.16 s**. Las dos filas reutilizadas lo declaran explícitamente.
- `/tmp/pm28p4-local-final-results.json`: **36 casos, 33 rc0, cero diferencias
  de rc respecto a** `/tmp/pmint2-20261003-fixed-local-results.json`; tiempo de
  los 34 casos ejecutados **225.45 s**, cero raíces residuales nuevas observadas.
  El summary termina rc0, `BASELINE_CHANGES 0`, `mismatches=1`.
- De los 26 labs, 25 rc0 y **tui-operations rc1**: el mismo
  `wait_text("exact-duplicates=1")` frente a la línea de importación recortada.
  Se observó la pantalla real en tmux; footer/resumen permanecen iguales.
  Los otros labs TUI, OIDC, TOTP, exchange, GitHub y passkey-login pasan.
  Publication backup/plaintext/attachment: 3/3 rc0.
- Custody-audit rc0: rechazo rc4, reemplazo=0, restitución original y cleanup
  errors=0. SQLite-sync rc0: control con 24 fsync; EIO real único en primer
  fsync, una llamada/una inyección, rc4, siete archivos propios completos,
  rollback/integridad/restart y cleanup errors=0. No se acredita otra frontera.
- Bootstrap-completed rc0: provider-calls=1, sustituto=0, cinco conteos exactos,
  restitución y cleanup errors=0.
- **RED vault y purge/outbox siguen fuera de gates y no se corrigen**:
  `/tmp/pm28p4-final-red-vault.log` rc1 registra main-vault=1 aunque el cliente
  rechaza rc4, provider-calls=1, restitución exacta y cleanup errors=0;
  `/tmp/pm28p4-final-red-purge.log` rc1 registra QueryReturnedNoRows, pending=4,
  signed-headers=4. No se cambia su esperado para ocultarlos.

La primera barrida y los dos fallos del harness se conservan, no se renombran
como PASS. Los focused posteriores están en
`/tmp/pm28p4-adapter-frame-harness-green.log` y
`/tmp/pm28p4-passkey-readiness-green.log`, ambos rc0; la final repite esos labs
en fixtures nuevos. La única raíz residual de la primera falla del adapter
(`/tmp/pm-adapter-protected-frame-linux-lab-1n7ku1ly`) se inventarió, comprobó
sin ejecutables vivos y retiró por path exacto con rmtree estricto; no se barrió
ningún `/tmp/pm-*` ajeno. No se generan pycache en las barridas.

`/tmp/pm28p4-preservation.log` confirma regiones protegidas sin cambios, wires/
sync/Windows, pm-vault y Cargo.lock idénticos a la base. También se comprobaron
AST de ambos fixtures Python, enlaces del documento, diff y estado del ticket
sin cambios. La raíz conserva `.gitignore`, `.pi/` y `odd/` ajenos intactos.
Se publica únicamente la rama propia; PR #1 continúa borrador y no se fusiona.
Esto es **checkpoint parcial verificado, no cierre de fase 4 ni G7**.

## Fase 5 — método concreto de §2 y §4

Base `ae713db`, mismo worktree/rama de fase 4. Se reutiliza
`verify-ticket28-custody-loss.sh` y el setup/teardown de
`sqlite_sync_fault_lab.py`. Sin cambios de producto, estados de
tickets, dependencias, límites o plazos.

Antes de la matriz, un control de `human-streaming-file` pausa el custodio
mediante el interposer **antes** de cada fsync/fdatasync del WAL exacto.
PID, path y ordinal se comprueban en cada evento. Una copia de DB/WAL/SHM,
hecha con el proceso detenido, identifica las filas pendientes sin abrir ni
checkpointar el original. El control debe completar stream/receipt/outbox;
la copia no acredita durabilidad, identifica el contenido del syscall.
Cada EIO/ENOSPC usa vault nuevo y el ordinal confirmado por ese control,
exigiendo el mismo contenido lógico antes de inyectar. Audit de unlock,
staging y commit final son fronteras separadas. Commit/outbox/audit del cambio
humano pertenecen a **una misma transacción física**: se comprueban juntos,
sin inventar tres fsync independientes. Se compara contenido/hash de tablas
de autoridad, revisión, outbox, receipt y audit; no solamente conteos. El lab
ENOSPC del tmpfs finito existente conserva la comprobación de disco real.

El inventario de canales es cerrado: cada archivo/directorio/socket owned
debe estar registrado; un path desconocido, tipo inesperado, rotación o
lectura parcial falla. Lecturas de archivos completas, con overlap entre
chunks. Se enumeran stdout/stderr, logs, errores públicos, cmdline/environ,
temporales, DB/WAL/SHM/journal, staging/audit, core/crash y recursos del agente.
SQLite permanece quiescente durante escaneo/copia. Los assets inmutables del
fixture (binarios/interposer/observer) se verifican por hash y se distinguen
de artefactos producidos; no son un permiso para excluir archivos desconocidos.
El observador UID agente prueba primero lectura process_vm_readv y attach/
detach de su propio hijo con dirección válida; después exige EPERM sobre los
PIDs sujetos y denegación de archivos privados. No cuenta dirección inválida,
Yama sin control positivo, EOF parcial o inventario inaccesible como ausencia.
La extensión de pérdidas en vuelo usa el proveedor controlado existente,
con barrera después de registrar una llamada y antes de responder; no se
reenvía start ni login. Los fallos relacionados con fallbacks/semántica
prohibidos quedan RED separados de gates.

Comandos iniciales, siempre cwd `.worktrees/28-g7-phase4`:

```sh
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh matrix trace
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh matrix
```

Los resultados observados y la tabla vigente se recogen más abajo. Compilación,
setup o timeout del fixture no son RED de producto.

Extensiones concretadas antes de la barrida final:

- Spill no confirmado: pwrite64 del WAL, ordinal 600, con WAL observado mayor
  que 1 MiB antes de la llamada. Control completo y EIO/ENOSPC, tres vaults
  nuevos; no sustituye ENOSPC físico del tmpfs existente.
- Settling después de transmisión: la barrera del proveedor registra el
  único send y mantiene la respuesta pendiente. Un archivo de control del
  interposer arma el segundo fsync siguiente; su copia debe mostrar cambio
  de intento y audit adicional, con autoridad intacta. Control sin fallo antes
  de EIO y ENOSPC, cada uno con vault nuevo. No callbacks de motor, reenvío
  de start ni reconexión de login.
- Pérdida en vuelo: rename del bootstrap/audit o vault/sidecars mientras el
  proveedor está detenido después de registrar `calls=1`, con intención
  `running/provider_sent=1` ya durable. SIGKILL, arranque con custodia ausente,
  ausencia de sustitutos, restitución de originales y get del mismo ID como
  INDETERMINATE. Caso crash aparte usa SIGABRT real y exige WCOREDUMP=false.
  Acredita **pérdida durante una llamada + crash/restart**, no detección de
  retirada en caliente por un proceso que conserva claves en memoria.
- Canarios históricos: `human-password-crud` existente crea, verifica, edita
  y manda a papelera; dos revisiones cifradas deben persistir. Se escanean
  canarios original/editado activos, históricos y tras reinicio, con los
  mismos controles UID agente. Su replay explícito de receipt/body-change
  pertenece al control público preexistente, no es retry de login oculto.
- Scanner: positivos separados prueban detección de canario que cruza el
  límite de chunk, EOF prematuro, archivo sin clasificar y archivo requerido
  ausente. Todos deben fallar por su causa exacta. El control truncado altera
  sólo el reader del scanner de prueba, nunca un syscall/reader productivo.
- TMPDIR de cada UID apunta a un subdirectorio privado propio. Se inventarían
  también todos los fd de sujetos vivos, rechazando archivos/temporales
  desconocidos incluso fuera de la raíz. UID agente prueba fd/maps/mem además
  de process_vm_readv/ptrace. Proceso crash con core soft/hard 0/0 y sin flag
  de dump no genera un archivo de core propio; archivos desconocidos de crash
  hacen fallar el inventario. Archivos históricos ajenos del colector del host,
  dumps de administrador/kernel, swap/FDE y otros targets no se acreditan.
- El lab físico ENOSPC existente ahora exige inventario cerrado de su estado,
  tipos regulares, lectura completa estable y overlap; también lee su filler
  owned de ceros. Su anterior filtro is_file y chunks sin overlap no probaban
  ausencia completa. No cambia el fallo, mutación, conteos ni plazos del lab.

Los fallbacks del fixture proveedor preexistente se conservan: `provider`
retira socket con `missing_ok`, trata EOF/BrokenPipe como cierre y el main
histórico de `attempts_lab.py` descarta errores de rmtree. La nueva barrera
no cambia esos caminos. Las nuevas corridas usan el teardown estricto de
SQLite-sync y Channels, sin invocar ese main/cleanup histórico. No se atribuye
cleanup integral a los labs heredados solo por su rc0.

```sh
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh canaries
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh inflight result-sync
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh inflight bootstrap
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh inflight audit
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh inflight vault
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh inflight crash
```

Extensión de retirada **en caliente**, antes del gate final: los tres casos
`inflight-live <bootstrap|audit|vault>` hacen una sola admisión nueva mientras
el proceso original sigue vivo y el proveedor permanece detenido en la primera
llamada. Exigen CUSTODY_UNAVAILABLE. Si el producto la admite, el fixture
cancela explícitamente ese segundo intento antes de liberar al proveedor;
esta contención del fixture no convierte la admisión en PASS y el RED se
propaga después de restitución/scan/cleanup. No se repite el primer start,
no se entrega un segundo login y no se corrige listener/admisión. Luego se
ejecutan el mismo crash/restart y get originales. Se comparan hashes de raíces,
autoridad/outbox/receipts, y journal con únicamente el primer ID/calls=1.

### Evidencia de fronteras reales — fase 5

Todas las corridas siguientes usan cwd `.worktrees/28-g7-phase4`, vault nuevo
por caso y este prefijo. En las tablas, `V` abrevia exclusivamente el wrapper
existente; no es otra ruta de ejecución del producto:

```sh
export PYTHONDONTWRITEBYTECODE=1
V=./scripts/verify-ticket28-custody-loss.sh
flock /tmp/pm-cargo-window.lock "$V" matrix
flock /tmp/pm-cargo-window.lock "$V" canaries
flock /tmp/pm-cargo-window.lock "$V" inflight result-sync
flock /tmp/pm-cargo-window.lock "$V" inflight bootstrap
flock /tmp/pm-cargo-window.lock "$V" inflight audit
flock /tmp/pm-cargo-window.lock "$V" inflight vault
flock /tmp/pm-cargo-window.lock "$V" inflight crash
flock /tmp/pm-cargo-window.lock "$V" inflight-live bootstrap
flock /tmp/pm-cargo-window.lock "$V" inflight-live audit
flock /tmp/pm-cargo-window.lock "$V" inflight-live vault
```

El interposer comprueba el PID persistido y path del fd en cada syscall, cuenta
su ordinal y registra una única inyección EIO o ENOSPC. El control positivo
detiene el proceso antes de la llamada, verifica el contenido pendiente en
copia y después deja completar la operación. La matriz confirma ordinales
fsync 1/2/5/8 para este fixture, no un número universal de SQLite. Las copias
se abren read-only; no crean/checkpointan el vault original. Los hashes cubren
contenido de raíces, autoridad, objetos cifrados, items/revisiones, staging,
outbox/receipts y tablas audit. Los distintos vaults usan identidades/nonce
sintéticos; no hay retry de la operación ni del login tras inyectar el fallo.

| Frontera/criterio | Resultado observado y control positivo | Comando después de flock | Log completo |
|---|---|---|---|
| WAL: primer fsync, ordinal 1 | **PASS** EIO y ENOSPC, una inyección por caso; rechazo rc4, rollback exacto, mismo vault tras restart | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` |
| Spill sin commit: pwrite64 ordinal 600 | **PASS** control sin fallo y EIO/ENOSPC; WAL observado 1,178,376 bytes antes del syscall; rollback/restart exactos | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` |
| Staging stream: fsync ordinal 5 | **PASS** EIO y ENOSPC; el control identifica 17 chunks pendientes; no staging durable tras el fallo | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` |
| Commit final: fsync ordinal 8 | **PASS atomicidad y autoridad**, EIO/ENOSPC inyectados; **RED cleanup** de staging tras error y restart inmediato | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` (rc1) |
| Outbox/receipt del cambio humano | **PASS atomicidad**, parte del mismo fsync 8; ningún efecto autorizado parcial. **RED cleanup** compartido, no frontera física independiente | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` (rc1) |
| Audit del commit humano | **PASS atomicidad**, mismo fsync 8; audit/raíces exactos al prefijo durable. **RED cleanup** compartido | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` (rc1) |
| Audit de unlock: fsync ordinal 2 | **PASS** EIO y ENOSPC; control con audit pendiente, rollback exacto | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` |
| Resultado/audit después de una transmisión externa | **PASS** control y EIO/ENOSPC en segundo fsync posterior a barrera; pending-state cambiado y audit +1; rollback a intención durable, INDETERMINATE, calls=1 | `"$V" inflight result-sync` | `/tmp/pm28p5-outcome-both-errors.log` (rc0) |
| Disco realmente lleno, tmpfs existente | **PASS** ENOSPC físico, WAL >1 MiB, rollback/restart; scanner reforzado lee los 6 archivos/65,843,744 bytes completos | `./scripts/test-linux-storage-fault-lab.sh` | `/tmp/pm28p5-gate-lab-storage-fault.log` (rc0) |
| Bootstrap retirado en vuelo + crash/restart | **PASS** intención running/provider_sent=1, calls=1; arranque cerrado rc4, replacement=0, restitución exacta y mismo ID INDETERMINATE | `"$V" inflight bootstrap` | `/tmp/pm28p5-complete-inflight-bootstrap.log` (rc0) |
| Audit retirado en vuelo + crash/restart | **PASS**, mismos controles; replacement=0, autoridad exacta, mismo ID INDETERMINATE/calls=1 | `"$V" inflight audit` | `/tmp/pm28p5-complete-inflight-audit.log` (rc0) |
| Vault retirado en vuelo + crash/restart | **RED heredado**: rechazo rc4 pero replacement=1; restitución recupera INDETERMINATE/calls=1 y autoridad exacta | `"$V" inflight vault` | `/tmp/pm28p5-complete-inflight-vault.log` (rc1) |
| Bootstrap retirado con proceso vivo | **RED nuevo**: nueva admisión CREATED, rc0; fixture cancela segundo intento antes de liberar proveedor. Luego restitución/INDETERMINATE/calls=1 | `"$V" inflight-live bootstrap` | `/tmp/pm28p5-live-bootstrap1.log` (rc1) |
| Audit retirado con proceso vivo | **RED nuevo**, admisión CREATED/rc0 y cancelación explícita; calls=1, restitución exacta | `"$V" inflight-live audit` | `/tmp/pm28p5-live-audit1.log` (rc1) |
| Vault retirado con proceso vivo | **PASS rechazo de admisión** rc4; **RED heredado** replacement=1 en recuperación | `"$V" inflight-live vault` | `/tmp/pm28p5-live-vault1.log` (rc1) |
| Crash real mientras el proveedor está en vuelo | **PASS acotado** SIGABRT real, WCOREDUMP=false, canales propios vacíos de core/crash; mismo ID INDETERMINATE, calls=1 | `"$V" inflight crash` | `/tmp/pm28p5-complete-inflight-crash.log` (rc0) |

La matriz completa termina rc1 únicamente por los dos RED de cleanup EIO/ENOSPC
del commit final. Continúa todos los casos aislados después de esos RED; todos
los teardown terminan `errors=0`. No se acredita cada variante futura de
SQLite/FS ni todos los proveedores: el contador corresponde al proveedor
controlado del lab. ENOSPC por frontera es errno del syscall real; el lab tmpfs
demuestra aparte el límite físico del dispositivo.

### Canales activos e históricos — fase 5

`"$V" canaries` termina rc0 en `/tmp/pm28p5-complete-canaries.log`: dos revisiones
cifradas, tres receipts/outbox y canarios original/editado tras create/check/
edit/trash/restart. La matriz y los casos en vuelo repiten el mismo inventario
durante operación, después de error/crash y tras restitución/restart. Se pausa
el custodio antes de enumerar archivos/copies/SQL para impedir rotación
concurrente de sidecars; el proveedor también se pausa cuando está sujeto al
escaneo. Los archivos de captura propios contienen stdout/stderr completos,
no sólo el resultado parseado. Un inventario desconocido, archivo requerido
ausente, tipo inesperado, EOF corto o cambio de tamaño/inode/mtime falla.

| Canal enumerado | Estado/control positivo y alcance | Comando después de flock | Logs |
|---|---|---|---|
| stdout, stderr, logs, errores públicos | **PASS acotado**: capturas completas activas/históricas, canarios ausentes; control de canario cruzando chunk detectado | `"$V" canaries`; `"$V" matrix`; `"$V" inflight result-sync` | `/tmp/pm28p5-complete-canaries.log`; `/tmp/pm28p5-locked-witness-matrix.log`; `/tmp/pm28p5-outcome-both-errors.log` |
| `/proc/<pid>/cmdline,environ` | **PASS acotado**: lectura hasta EOF del PID vivo detenido o EPERM explícito; también desde UID agente | `"$V" canaries`; `"$V" inflight crash` | `/tmp/pm28p5-complete-canaries.log`; `/tmp/pm28p5-complete-inflight-crash.log` |
| Temporales propios y fd de sujetos | **PASS acotado**: TMPDIR privado por UID; inventario cerrado de raíz y fd; archivo regular fuera del inventario falla | `"$V" canaries`; `"$V" matrix` | `/tmp/pm28p5-complete-canaries.log`; `/tmp/pm28p5-locked-witness-matrix.log` |
| DB, WAL, SHM, journal y copias SQLite | **PASS acotado**: bytes completos, overlap, copias quiescentes y SQL sin canarios; sidecars ausentes se enumeran con files=0 | `"$V" matrix`; `"$V" canaries`; `"$V" inflight result-sync` | `/tmp/pm28p5-locked-witness-matrix.log`; `/tmp/pm28p5-complete-canaries.log`; `/tmp/pm28p5-outcome-both-errors.log` |
| Staging, incluidos streams/chunks SQL | **PASS de ausencia de plaintext** aun en los dos RED de cleanup; staging residual cifrado no se reclasifica como cleanup correcto | `"$V" matrix` | `/tmp/pm28p5-locked-witness-matrix.log` |
| Audit-custody y tablas audit | **PASS acotado**: archivos y filas de records/state/segments/manifests íntegros, activos/históricos | `"$V" matrix`; `"$V" inflight audit`; `"$V" inflight-live audit` | `/tmp/pm28p5-locked-witness-matrix.log`; `/tmp/pm28p5-complete-inflight-audit.log`; `/tmp/pm28p5-live-audit1.log` |
| Core/crash propios | **PASS acotado** SIGABRT con WCOREDUMP=false y core soft/hard 0/0; inventario explicita files=0 y rechaza artefactos nuevos sin categoría | `"$V" inflight crash` | `/tmp/pm28p5-complete-inflight-crash.log` |
| Archivos privados desde UID agente | **PASS acotado**: EACCES/EPERM para estado, keys humanas y capturas privadas; recursos propios legibles se escanean completos | `"$V" canaries`; `"$V" inflight crash` | `/tmp/pm28p5-complete-canaries.log`; `/tmp/pm28p5-complete-inflight-crash.log` |
| process_vm_readv y ptrace desde UID agente | **PASS** del lab: hijo del mismo UID con dirección/contenido conocido se lee/attach-detach; custodio/proveedor dan EPERM | `"$V" canaries`; `"$V" inflight crash` | `/tmp/pm28p5-complete-canaries.log`; `/tmp/pm28p5-complete-inflight-crash.log` |
| Recursos agente y `/proc/<pid>/{fd,maps,mem}` | **PASS acotado**: keys/profile propios sin canarios; fd/maps/mem de sujetos denegados explícitamente | `"$V" canaries`; `"$V" inflight result-sync` | `/tmp/pm28p5-complete-canaries.log`; `/tmp/pm28p5-outcome-both-errors.log` |
| Scanner incompleto/truncado | **PASS de discriminación**: canario entre chunks detectado, EOF prematuro, archivo desconocido y requerido ausente rechazados por la causa exacta | `"$V" canaries`; `"$V" matrix` | Primer control en ambos logs |
| Archivos ajenos del colector del host, dumps de administrador/kernel, swap/FDE; todos los demás flujos/native targets | **No demostrado** por este fixture; el log `collector-invoked=0` sólo deriva de ausencia del flag de core, no de una auditoría del servicio del host | No ejecutado | Sin evidencia atribuida |

Los canarios que entran al producto sólo se aceptan como contenido de las
revisiones/chunks cifrados esperados; se comprueban revisiones históricas y
ausencia literal en todos los bytes/canales producidos. Los scripts/binarios
inmutables del fixture incluyen constantes sintéticas de entrada y están
identificados como assets con hash, separados del inventario generado. No se
permite excluir outputs/artefactos del producto con ese criterio. Esta evidencia
acotada no sustituye el inventario pendiente de owners/memoria del ticket.

### Defectos, límites y autorización — fase 5

- **Staging residual tras fallo del commit final (nuevo RED de §2):** queda
  una fila human_staging, una human_staging_streams y 17 chunks, inmediatamente
  tras EIO/ENOSPC y tras reinicio inmediato. Atomicidad de items/revisiones,
  raíces, autoridad, audit/outbox/receipts se conserva. `HumanVault::commit`
  elimina staging dentro de la misma transacción; su rollback conserva el
  comando preparado anterior. No se demuestra persistencia indefinida ni
  plaintext. G7 exige retirar parciales propios al arrancar; aplicar esa limpieza
  sin romper el preparado/receipt G4 exige resolver su composición y obtener
  autorización específica. No se reabre el control confirmado ni se decide
  aquí si el preparado conserva autoridad para reanudarse.
- **Bootstrap/audit retirados con custodio vivo (nuevo RED de §3):** el proceso
  admite una autenticación nueva usando custodia previamente cargada. La
  hipótesis causal concuerda con bootstrap leído una vez en `serve_loop` y
  `audit_custody` conservada en memoria; la admisión rc0 es evidencia directa.
  La cancelación del segundo intento es contención explícita del fixture, no
  corrección. Resolver toca listener/admisión/custodia, fuera de autorización.
- **Recreación SQLite al perder vault (RED heredado):** se confirma también
  en vuelo y en caliente, replacement=1 aunque el request rechaza rc4. La
  restauración exacta/INDETERMINATE no oculta ese sustituto. No se corrige.
- **Purge/outbox (RED heredado):** continúa QueryReturnedNoRows con pending=4
  y signed-headers=4, separado de gates; ninguna edición de pm-sync/pm-vault.
- Los fallbacks de proveedor/cleanup del fixture descritos arriba y la lista
  de fase 4 se conservan. No hay cambios de producto, nuevos fallbacks, límites,
  KDF, deadlines, engine, memoria restante, footer ni resumen de importación.

Los intentos intermedios no se cuentan como RED discriminantes: `matrix1/2`
pararon antes de completar todas las verificaciones históricas; `matrix3/4`
preceden al inventario/hash final; `result-sync1` esperaba erróneamente otro
sync después del error y agotó el plazo. En `inflight-crash1` faltaba SIGCONT
después de SIGABRT sobre proceso detenido; se reanudó únicamente el PID owned
identificado y se corrigió el fixture. Las corridas finales aquí citadas usan
el método completo. No se borran/renombran esos logs como GREEN ni se atribuye
un defecto al producto por setup, timeout o compilación.

### Gates y preservación — fase 5

Se ejecutaron de nuevo los 36 comandos del baseline de integración, cada uno
secuencial y con flock, sin reutilizar check/build previos. Runner enumerado en
`/tmp/pm28p5-run-local.py`, resultados en `/tmp/pm28p5-local-results.json` y
summary `/tmp/pm28p5-local-summary.log`. Las filas contienen comando completo,
rc/expected/baseline_rc, comparación, duración, log y raíces residuales nuevas.

```sh
export PYTHONDONTWRITEBYTECODE=1
export PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
export PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
flock /tmp/pm-cargo-window.lock ./scripts/check.sh
flock /tmp/pm-cargo-window.lock ./scripts/clean-offline-build.sh
# Runner: cada comando Cargo/lab con su propio flock; sólo artefactos aprobados.
python3 /tmp/pm28p5-run-local.py > /tmp/pm28p5-local-summary.log 2>&1
```

Resultado: **36 casos, 33 rc0, BASELINE_CHANGES=0, mismatches=1**, 372.60 s
totales registrados; ninguna raíz residual nueva observada. Check rc0 en
42.98 s (`/tmp/pm28p5-gate-final-check.log`), build limpio locked/offline rc0 en
43.54 s incluyendo ventana/runner (`/tmp/pm28p5-gate-final-clean.log`).
Los 26 wrappers Linux tienen 25 rc0 y el mismo tui-operations rc1:
`wait_text("exact-duplicates=1")` frente al resumen de importación recortado,
observado en tmux, `/tmp/pm28p5-gate-lab-tui-operations.log`. No se cambia su
esperado ni la interfaz. Publication backup/plaintext/attachment 3/3 rc0;
custody-audit/sqlite-sync/bootstrap-completed 3/3 rc0. La compatibilidad del
provider sin barrera y del interposer SQLite-sync original se verifica en
esas corridas y attempts. Vault-loss y purge siguen rc1 fuera de gates en
`/tmp/pm28p5-gate-red-{vault,purge}.log`; los nuevos RED también se mantienen
fuera del gate de regresión. No se añaden wrappers test-linux duplicados.

Cambios de esta fase: fixtures `attempts_lab.py` (barrera opcional),
`sqlite_sync_fault_lab.py`/`sqlite_sync_interposer.c` (casos/reales syscalls),
`storage_fault_lab.py` (lectura/inventario) y cuatro helpers
`g7_{canary_channels,fault_matrix,inflight,result_sync}.py`; wrapper
`verify-ticket28-custody-loss.sh` y este documento. No hay ediciones Rust/src,
Cargo.lock/Toml, dependencias, workflows, tickets, integración ni reglas.
Conflictos previsibles sólo en esos fixtures/wrapper/documento, especialmente
provider del lab y contrato de variables del interposer. El orquestador debe
revisar integración independientemente. Raíz ajena preservada, sin barridos
de `/tmp/pm-*`; cleanup exacto y explícito en todos los focused finales.
La verificación estática final (`/tmp/pm28p5-preservation.log`) comprueba diff,
sintaxis shell, AST de los 29 fixtures Python, enlaces/tabla vigente, paths
autorizados y logs finales completos sin canarios literales. Producto y
estado del ticket permanecen idénticos a la base.

### Estado histórico de criterios 28/G7 — fase 5 (checkpoint parcial)

Esta tabla registró la fase 5; la tabla vigente está en W3 al final de este
documento. Se conserva sin cambiar acuerdos de [spec §15](../../.scratch/passwordmanager/spec.md)
ni estado del [ticket 28](../../.scratch/passwordmanager/issues/28-fallos-operativos-canarios-y-crash-safety-integral.md).
Se conserva el contrato de [G7](../design/security-operations.md).
PASS significa evidencia con el alcance indicado; **G7 sigue
abierto**, con defectos RED, memoria restante y revisión independiente pendientes.

| Criterio | Estado y alcance vigente | Evidencia |
|---|---|---|
| Records/password/notas/Attachment, AuthRecord/serializers; CSV/JSON/PMF1; passkey 32 bytes | PASS acotado heredado | Fases 1–4; check de fase 5 |
| Frames/responses custody/web, sources/requests propios HTTP/JSON/CDP y providers | PASS acotado heredado; no heaps TLS/Chromium/russh ni todo SSH | RED/GREEN anteriores y labs de fase 5 |
| Owners TUI split y requests restore/rotate | PASS acotado heredado; footer/resumen intactos | Fase 4, labs TUI excepto mismatch conocido |
| Memoria propia integral, wires y presentación restante | **FAIL de inventario**, trabajo posterior | SSH, recovery/snapshot/import/sync, Ratatui, ZIP/DEFLATE de fase 4 |
| Presupuesto agregado | PASS contador test-only 64 KiB; 32 MiB físicos/overhead **no demostrados** | Host memlock 8 MiB, sin ampliación |
| Guardas Linux/core/dumpable/stdin | PASS acotado heredado + SIGABRT real sin core del lab | fault-safety/protected-input; complete-inflight-crash |
| 17.º RATE_LIMITED y CLOCK_UNTRUSTED | PASS acotado heredado | autorización y check; no cambia rate/clock |
| Límites restantes, incluido techo custodial 128 | **No demostrado integralmente** | Sin nuevas pruebas de estos techos |
| ENOSPC físico y spill WAL real EIO/ENOSPC | **PASS** acotado, rollback/restart y canales completos | gate-storage-fault y locked-witness-matrix |
| Matriz WAL/staging/commit/outbox/audit con EIO/ENOSPC | **PASS atomicidad/autoridad con controles reales**; **RED cleanup** del commit final | fsync 1/2/5/8, pwrite64 600; staging 1/1/17 tras error/restart |
| Resultado tras transmisión, crash/intención → INDETERMINATE, no doble login | **PASS acotado** con proveedor controlado calls=1; no todos los proveedores | outcome-both-errors y complete-inflight-crash |
| Bootstrap/audit perdidos, intento completado y pérdida en vuelo + restart | **PASS acotado**: cierre rc4, replacement=0 y restitución exacta | labs heredados y complete-inflight-{bootstrap,audit} |
| Bootstrap/audit retirados con custodio vivo | **RED nuevo**, admite nueva autenticación; corrección requiere autorización | live-{bootstrap,audit}1; segundo intento cancelado antes del proveedor |
| Vault perdido, completado/en vuelo/en caliente | **RED heredado**, SQLite sustituto; corrección no autorizada | gate-red-vault, complete-inflight-vault y live-vault1 |
| Canarios activos/históricos en canales propios y UID agente | **PASS acotado**, inventario cerrado y controles scanner/vm/ptrace; cobertura global **no demostrada** | complete-canaries, matriz y todos los inflight finales |
| Purge/outbox de revisión purgada | **RED heredado separado de gates** | gate-red-purge: QueryReturnedNoRows, pending/signed-headers=4 |
| Windows VirtualLock/WER y macOS nativo | Diferido | Sin evidencia nativa nueva; seams no acreditan soporte |
| Check completo y build limpio | **PASS** | rc0 en 42.98/43.54 s, logs de fase 5 |
| Barrida de los 36 casos de integración | **Sin regresión de rc**: 33 rc0, único mismatch TUI conocido, 2 RED heredados separados | local-results.json/summary, BASELINE_CHANGES=0 |
| Integración/revisión independiente y cierre de 28/G7 | **Pendientes**, fuera de esta entrega | Rama propia publicada; PR #1 borrador sin fusionar, ticket sin cambio de estado |

Siguiente acción: el orquestador revisa esta evidencia e integra la rama propia
con sus gates, sin fusionar PR #1. Solicitar decisión/autorización específica
para staging preparado y retirada de custodia en caliente; conservar RED y
fallback SQLite/purge mientras tanto. Después continuar el inventario de memoria
restante en su alcance separado. Esta entrega no acredita cierre de G7 ni
soporte nativo Windows/macOS.

## Result-sync — método discriminante 2026-10-03

Alcance autorizado: clasificar únicamente el FAIL intermitente de
`inflight result-sync` sobre la integración `055fd9e`, sin integrar ni cambiar
producto/fallbacks/tickets. Cwd `.worktrees/g7-result-sync`; cada comando de
Cargo/check/lab bajo `flock /tmp/pm-cargo-window.lock`, liberado entre corridas.
Se conserva el control sin fallo, segundo fsync, EIO/ENOSPC, vaults nuevos,
una sola llamada al proveedor, hashes completos y plazos 8/15 segundos.

La discriminación compara dos observaciones del mismo vault: recuperación de
una copia cruda DB/WAL/SHM y snapshot SQLite de su vista viva confirmada. La
conexión fuente se abre `mode=ro`, se inicializa durante la pausa del syscall
y se conserva para fijar el WAL index original; nunca escribe ni checkpointa
el vault. El snapshot usa backup SQLite en un único paso; busy/incomplete falla
sin retry. Se confirma primero que el writer lock está ocupado en el syscall.
Tras reanudar se adquieren los locks Unix WAL writer/checkpoint/recovery
(bytes 120..122 en SQLite 3.53.2 fijado), dentro de los mismos 8 segundos, y
se confirma SIGSTOP en **todos** los tasks del custodio antes de observar.
La adquisición sólo cerca la observación y no escribe contenido. Los demás
modos conservan la copia cruda que identifica frames pendientes de syscall.
La instrumentación registra sólo categorías, booleanos y orden, sin payloads.

### Clasificación y cronología del FAIL

**(b), carrera del fixture/observación de SQLite.** El texto
`partial state settlement after fsync failure` sólo acredita desigualdad del
hash completo de `authentication_attempts` frente a la intención previa; no
identifica el campo ni prueba que se haya asentado únicamente parte de una
transacción. En el control discriminante, intento **y** audit de la copia cruda
son exactamente los pendientes del syscall. La vista viva confirmada, después
del rollback, conserva ambos hashes originales y autoridad exacta, calls=1.

La condición antigua `running/provider_sent=1` + proceso no detenido se podía
cumplir antes de retornar del syscall/terminar el rollback. `pause_owned`
comprobaba sólo el task líder. Además, abrir la copia DB/WAL/SHM sin los locks
vivos del original reconstruye su WAL index desde los frames: puede observar
el commit marker no confirmado del fsync fallido. La quiescencia por sí sola,
o abrir una fuente nueva después de cerrar/recuperar ese index, no demuestra
qué veía la conexión original. Por eso se conserva una fuente `mode=ro`
inicializada **antes** de reanudar el syscall, sin una transacción de lectura
congelada: cada SELECT/snapshot observa la vista confirmada actual.

Evidencia discriminante `/tmp/pmrs-pinned-red.log` (rc1): el control sin fallo
completa antes del caso EIO; en EIO aparecen `writer-busy=1`,
`state-equals-pending=1`, `audit-equals-pending=1` para la observación antigua.
Tras liberar los locks y detener todos los tasks, la fuente fijada muestra
`state-exact=1 audit-exact=1 authority-exact=1 provider-calls=1`. Se conserva
la aserción antigua y su rc1, aunque el snapshot discrimine su falsa lectura.
No se atribuye este RED al producto. La instrumentación/fixture exactos están
preservados en `/tmp/pmrs-pinned-red.patch` (SHA256
`665ca7333aad8f62460addb4efe5083c712472046165d2dcf7ccd136a670cac5`), aplicable
a la base `055fd9e`; copias `/tmp/pmrs-pinned-red-{result-sync,fault-matrix}.py`.

Cronología sin borrar diagnósticos anteriores:

- Base sin cambios, 30 invocaciones completas del modo: **1/30 FAIL (3.33%)**,
  iteración 16, mismo mensaje. `/tmp/pmrs-before-results.json`,
  `/tmp/pmrs-before-summary.log`, `/tmp/pmrs-before-16.log`; las otras 29 pasan.
- Primera instrumentación: 1/30, iteración 29,
  `/tmp/pmrs-diagnose-{results.json,summary.log,29.log}`. Registró writer libre
  y copia igual al pending; no bastaba para separar recuperación del WAL de
  estado confirmado. Una fuente reabierta después también dejó 1/30,
  iteración 20, `/tmp/pmrs-committed-diagnose-{results.json,summary.log,20.log}`.
  Esas observaciones no fundamentan una acusación de atomicidad del producto.
- Control RO fijado antes del syscall: RED discriminante anterior, con vista
  confirmada íntegra en el mismo caso, antes de modificar la aserción/observación.
- Corrección exclusiva del fixture: fuente RO fijada, fence de locks, todos los
  tasks detenidos y snapshot confirmado. Las aserciones de hashes, autoridad,
  calls=1, INDETERMINATE y resultado vacío se conservan. GREEN enfocado rc0,
  `/tmp/pmrs-focused-green.log`, para control, EIO y ENOSPC; cleanup errors=0.

Comando RED (con fixture diagnóstico preservado) y GREEN (con fixture corregido):

```sh
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh inflight result-sync
# RED: /tmp/pmrs-pinned-red.log; GREEN: /tmp/pmrs-focused-green.log
python3 /tmp/pmrs-repeat.py before > /tmp/pmrs-before-summary.log 2>&1
python3 /tmp/pmrs-repeat.py after > /tmp/pmrs-after-summary.log 2>&1
# El runner adquiere/libera flock en cada una de sus 30 invocaciones.
```

El interposer C y el producto son idénticos a la integración; el control sigue
verificando PID, WAL exacto, contador secuencial, offset=2 y una inyección por
fault. Proveedor detenido, journal calls=1 y fuente viva íntegra excluyen una
segunda llamada/recuperación compitiendo como causa de este control. La ventana
Cargo se serializa en todas las corridas; no se ha demostrado interferencia
externa/CPU como causa. Estos hechos clasifican el FAIL estudiado, no prueban
atomicidad universal ni cierran G7.

Se conservan los fallbacks inspeccionados de `linux.rs::serve_loop` (descarta
el error de `run_provider_once` y continúa el worker), y
`linux.rs::run_provider_once` (descarta error de settle AUTHORITY_REVOKED y
retorna Ok), ya inventariados en la integración. No se corrigen ni se usan para
justificar éxito; tampoco se cambia la semántica de intentos. Los fallbacks de
provider/cleanup históricos de fase 5 siguen intactos.

### Quiescencia del tramo tras reinicio

La primera corrección completó las comprobaciones de atomicidad en 30/30, pero
el **modo completo** quedó 29/30 rc0: `/tmp/pmrs-after-12.log` (rc1) falla
posteriormente en `settlement-historical-restarted`, por
`unclassified process file/temporary resource`. `/tmp/pmrs-after-results.json`
y `/tmp/pmrs-after-summary.log` conservan **1/30 FAIL**, sin reinterpretarlo
como GREEN. El log no identificaba la categoría del descriptor; la rotación
de sidecars durante el cierre de conexiones es una explicación compatible,
no una ruta concreta demostrada por ese log.

La observación final conserva también la fuente RO original desde la readiness
tras reiniciar, aplica el mismo fence de locks y detiene todos los tasks antes
de snapshot/scan. Mantiene los 15 segundos para observar INDETERMINATE y el
presupuesto previo de **5 segundos** para detener al custodio; no añade una
espera fija ni tolera archivos desconocidos, sidecars ausentes/deleted o lecturas
parciales. El scanner y su aserción no se modifican. GREEN enfocado final rc0:
`/tmp/pmrs-final-focused-green.log`, control + EIO + ENOSPC, calls=1, ambos hashes
exactos tras cada fault, autoridad exacta y cleanup errors=0. La repetición del
candidato final usa `/tmp/pmrs-after-final-{results.json,summary.log}` y logs
`/tmp/pmrs-after-final-01.log` … `30.log`; los resultados se registran abajo.

```sh
PYTHONDONTWRITEBYTECODE=1 flock /tmp/pm-cargo-window.lock ./scripts/verify-ticket28-custody-loss.sh inflight result-sync
# /tmp/pmrs-final-focused-green.log
python3 /tmp/pmrs-repeat.py after-final > /tmp/pmrs-after-final-summary.log 2>&1
```

La segunda tanda (`after-final`) conserva **1/30 FAIL**, iteración 03,
`/tmp/pmrs-after-final-03.log`: `sqlite3.OperationalError: database is locked`
al inicializar la fuente nueva tras readiness, durante el control sin fallo.
No alcanza el caso EIO y no es una pérdida de atomicidad. El timeout=0 añadido
al observador era más estricto que los **5 segundos** heredados de `query`.
Se restablecen explícitamente esos 5 segundos de espera SQLite por lock para
la fuente RO; la inicialización ahora cuenta **dentro** del deadline original
de 15 segundos. El backup sigue siendo un único paso: busy/incomplete falla
inmediatamente, sin repetir backup. No se reenvía start/login ni se repite un get fallido para ocultar
un error ni se repite el modo dentro de una aserción; cada repetición externa
mide un vault nuevo. El candidato definitivo y sus logs usan el prefijo
`/tmp/pmrs-candidate-`, distinto de ambas tandas intermedias fallidas.

### Repetición final y gates

Candidato definitivo: **0/30 FAIL (0%)**, frente a **1/30 (3.33%)** en la base
sin cambios, mismo modo/oráculo/plazos y un flock distinto por invocación.
`/tmp/pmrs-candidate-results.json` y `/tmp/pmrs-candidate-summary.log`;
30 logs `/tmp/pmrs-candidate-01.log` … `30.log`. Cada invocación completa
control + EIO + ENOSPC sobre vaults nuevos: **90 casos, 60 faults y 30 controles**.
Los 60 faults conservan hashes exactos de intento/audit, todos los casos
terminan INDETERMINATE/result vacío/calls=1; 90 teardown con errors=0.
El GREEN enfocado del candidato está en `/tmp/pmrs-candidate-focused-green.log`.
Las tandas intermedias fallidas anteriores no se incluyen en ese 0/30 ni se
borran. Una tasa 0/30 es evidencia acotada, no prueba de ausencia universal.

```sh
export PYTHONDONTWRITEBYTECODE=1
export PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
export PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
python3 /tmp/pmrs-repeat.py candidate > /tmp/pmrs-candidate-summary.log 2>&1
# Cada comando del runner siguiente adquiere su propio flock, cwd este worktree.
python3 /tmp/pmrs-run-gates.py > /tmp/pmrs-gate-summary.log 2>&1
```

El runner de gates enumera los mismos 34 casos no excluidos del baseline
`/tmp/pmint3-local-results.json`: check, clean-offline-build, 26 wrappers Linux,
publication backup/plaintext/attachment, custody audit/sqlite-sync/bootstrap
completed. No repite vault-loss ni purge/outbox, fuera de gates. Añade los seis
modos requeridos: matrix, inflight result-sync/bootstrap/audit/crash y canaries.
El rc1 esperado de TUI y matrix sólo coincide si conserva **también** la causa
original: exact-duplicates=1 con preview recortado y los mismos dos RED de
staging commit-outbox-audit EIO/ENOSPC, respectivamente. Todos los modos G7
exigen teardown errors=0. Los resultados completos se registran al terminar
este barrido; un rc igual aislado no se usa como evidencia de no regresión.

Resultado del barrido final: **40 casos, 38 rc0, cero regresiones**, runner rc0,
417.92 segundos acumulados. Los 34 casos comparables conservan exactamente
los rc de `/tmp/pmint3-local-results.json`; los dos RED conocidos adicionales
vault/purge se excluyeron explícitamente. Evidencia por comando y causa:
`/tmp/pmrs-gate-results.json`, `/tmp/pmrs-gate-summary.log` y logs individuales
`/tmp/pmrs-gate-*.log`.

| Comprobación | Resultado observado | Log en `/tmp/` |
| --- | --- | --- |
| check.sh | PASS rc0, 70.169 s | `pmrs-gate-final-check.log` |
| clean-offline-build.sh | PASS rc0, 43.224 s | `pmrs-gate-final-clean.log` |
| 26 wrappers Linux | 25 PASS; TUI operations mismo FAIL `exact-duplicates=1`/preview recortado | `pmrs-gate-lab-*.log`; `pmrs-gate-lab-tui-operations.log` |
| publication backup/plaintext/attachment | 3/3 PASS | `pmrs-gate-publication-*.log` |
| audit/sqlite-sync/bootstrap completed | 3/3 PASS | `pmrs-gate-{custody-audit,sqlite-sync,bootstrap-completed}.log` |
| matrix | Mismo rc1 y exactamente los dos RED staging EIO/ENOSPC; sin nuevos defectos ni cleanup errors | `pmrs-gate-g7-matrix.log` |
| inflight result-sync | PASS control/EIO/ENOSPC, rc0 5.034 s, calls=1 y estado/audit exactos | `pmrs-gate-g7-inflight-result-sync.log` |
| inflight bootstrap/audit/crash | 3/3 PASS, custodia restaurada exacta/crash sin core, calls=1 | `pmrs-gate-g7-inflight-*.log` |
| canaries | PASS rc0, canales/controles completos en el alcance del lab | `pmrs-gate-g7-canaries.log` |

Preservación final: `git diff --check`, AST de los 29 fixtures, enlaces locales
de este documento y allowlist de tres paths pasan; registro
`/tmp/pmrs-preservation.log`. Únicamente cambian `g7_result_sync.py`, el modo
explícito de snapshot de `g7_fault_matrix.py` y este documento. El modo crudo
sigue identificando frames pendientes; no se cambia su oracle ni los demás
métodos. Producto/Rust, interposer C, Cargo/dependencias, workflows, deadlines,
KDF, fallbacks y estados de tickets permanecen intactos. La raíz sigue en
`b3577d2` con sus cambios ajenos y no se editó el worktree de integración.

El FAIL estudiado queda clasificado y el fixture verificado localmente. G7 y
el ticket 28 siguen parciales; aceptación global conserva TUI/staging y los
otros RED fuera de gates, memoria restante, gates humanos/reboot/FDE y targets
no acreditados. No hay integración ni merge del PR. Siguiente acción del
orquestador: revisión independiente de la rama `codex/pm-g7-result-sync` y,
si se acepta, integración/verificación por el merger designado.


## W3 — vault y admisión cerrada, 2026-10-03

Base `ee3c1fd31cad59060e4120f3e2518b1196a90c1a`; worktree propio
`.worktrees/w3-g7-failclosed`, rama `codex/pm-w3-g7-failclosed`.
Autorización explícita de W3: puntos (2), (7), (6), (5), en ese orden;
se conserva el estado `claimed` del ticket y el PR borrador #1 sin integración.
SHA del código/fixtures comprobados: `4913a86d97d1a1e9ba302c5a2fbf9dd1acee470f`.
La actualización posterior de este informe es sólo documental.
El alcance entregado de producto es **(2)/(7)**. Se detiene (6) por la
composición descrita debajo; (5) y el inventario opcional posterior no avanzan
antes de esa decisión. No se presenta W3 ni G7 como completos.

### Cambios y método aplicado

(2): todas las aperturas de un vault existente en human, authorization,
attempts, audit, passkey, backup y las dos seams de conexión del reducer
eliminan exclusivamente `SQLITE_OPEN_CREATE` de los flags originales de
rusqlite. Se conservan READ_WRITE, NO_MUTEX y URI; no se alteran PRAGMAs,
reductor/purge/export ni transacciones. La creación inicial sigue exclusivamente
en `PendingVault::persist` y su publicación privada existente. Una ruta ausente
no prueba primera inicialización ni permite generar otra base; el estado ya
inicializado conserva bootstrap/custodia y abre exclusivamente almacenamiento
existente. No se añade un marcador alternativo ni reparación automática.

(7): `custody_admission::CustodyAdmission` conserva paths y fingerprints internos
de la custodia válida cargada al arrancar. La función acotada
`agent_wire::verify_admission_custody` comprueba los opcodes de admisión
30/33/40/41 antes de construir el intento. Relee bootstrap con el mismo parser
nativo; audit con los controles de owner/tipo/modo/nlink del arranque y destino
locked antes de recibir sus bytes. Ausencia, ilegibilidad, corrupción o identidad
sustituida propagan `Failure::Unavailable`. La apertura delegada posterior
continúa comprobando el paquete de auditoría ligado al vault/device. No crea
archivos, generaciones, otra revisión ni un segundo request de proveedor.
Los hashes privados nunca se imprimen ni se serializan a diagnóstico.

Se conserva el engine compartido Linux/macOS/Windows. Los callers nativos
aportan el mismo guard; Windows usa el reader DPAPI existente. Linux x86_64 es
el único target ejecutado. No se acredita build/ejecución macOS o Windows,
VirtualLock/WER, reboot/FDE ni firma por inspeccionar esas seams.

Se reutilizan §§1–4, los fixtures de fase 5 y result-sync completos, sin editar
oráculos, interposer, scanner, límites o plazos. Los tests adicionales de función
cubren ilegibilidad del vault ya inicializado, pérdida con handle delegado vivo,
restore exacto y pérdida/ilegibilidad/corrupción/reemplazo de custodia. Son
cobertura adicional del mismo criterio §3; no se inventa un RED separado para
comportamiento que ya rechazaba archivos ilegibles.

### RED y GREEN preservados

Todos los comandos siguientes se ejecutan desde este worktree, con
`PYTHONDONTWRITEBYTECODE=1` y `flock /tmp/pm-cargo-window.lock`; `V` abrevia
únicamente `./scripts/verify-ticket28-custody-loss.sh`.

| Punto / comando después de flock | RED válido antes de producto | GREEN enfocado |
| --- | --- | --- |
| (2), `"$V" vault completed` | `/tmp/pmw3-red-vault-completed.log`, rc1: SUCCEEDED/calls=1, replacement=1, closed=1, restore exacto, cleanup=0 | `/tmp/pmw3-green-vault-completed.log`, rc0: replacement=0, closed=1, calls=1, restore exacto |
| (2), `"$V" inflight vault` | `/tmp/pmw3-red-inflight-vault.log`, rc1: intención running/provider_sent=1, replacement=1, calls=1 | `/tmp/pmw3-green-inflight-vault.log`, rc0: replacement=0, mismo ID INDETERMINATE/calls=1 |
| (2), `"$V" inflight-live vault` | RED heredado de fase 5 conservado; no se atribuye otro RED a este cambio | `/tmp/pmw3-green-inflight-live-vault.log`, rc0: cierre y ausencia de reemplazo |
| (7), `"$V" inflight-live bootstrap` | `/tmp/pmw3-red-inflight-live-bootstrap.log`, rc1: accepted=1, rc0; fixture cancela antes del segundo login | `/tmp/pmw3-green-inflight-live-bootstrap-2.log`, rc0: accepted=0, rc4, calls=1 |
| (7), `"$V" inflight-live audit` | `/tmp/pmw3-red-inflight-live-audit.log`, rc1: accepted=1, rc0; misma contención | `/tmp/pmw3-green-inflight-live-audit-2.log`, rc0: accepted=0, rc4, calls=1 |
| (6), `"$V" matrix` | `/tmp/pmw3-red-matrix.log`, rc1: exactamente los dos RED commit-outbox-audit EIO/ENOSPC, staging 1/1/17 tras error/restart, autoridad íntegra | **No GREEN**; bloqueado por la composición siguiente |
| (5), errores SSH/agente | **No RED nuevo ejecutado**; inventario heredado de fase 4 | **No implementado**, detrás de (6) |

La primera composición del guard omitió declarar su módulo en el binario:
`pmw3-green-inflight-live-{bootstrap,audit}.log` terminan rc101/E0433. Son
bookkeeping de compilación, **no RED**. El módulo se declaró sin cambiar
oráculos; los logs `-2` preservan el GREEN. `/tmp/pmw3-focused-custody.log`
termina rc0, 7/7 funciones, incluidos los dos nuevos controles. Después se
preservaron los flags originales salvo CREATE y se ejecuta el gate final de
ese código. El primer runner de gates leyó un nombre de baseline equivocado:
`/tmp/pmw3-gate-summary.log` falla antes de invocar un gate; no es RED de producto.
La corrida real usa `/tmp/pmw3-gate-summary-2.log`.

### Decisión concreta pendiente de (6)

La autorización exige limpiar transaccionalmente el staging **sin perder
intenciones durables ni autoridad**, componiendo G7 con preparado/receipt G4.
El preparado actual conserva en human_staging/streams/chunks el payload cifrado
referenciado por el body firmado. `HumanVault::commit` valida ese payload y lo
elimina dentro del commit final; un rollback lo conserva. La regresión existente
`audit_failure_rolls_back_every_commit_part_and_lost_response_recovers_receipt`
en `crates/pm-vault/tests/human_transactions.rs` exige explícitamente repetir
el **mismo** commit preparado después de un fallo sin efectos, y recuperar el
receipt tras perder la respuesta. Borrar esos payloads al fallar, sin otra
representación durable confirmada, rompería ese comportamiento. Challenge y
body_hash solos no permiten reconstruir ciphertext/stream.

Opciones elevadas al orquestador/usuario, sin implementación anticipada:

1. **Recomendada:** distinguir intención cifrada durable, íntegra y ligada al
   challenge/body/expected_state, de staging temporal; conservar replay exacto y
   receipts. Definir su recuperación, retención y transición terminal antes de
   implementar; no basta renombrar residuos para satisfacer los conteos.
2. Abortar de forma durable el preparado tras un fallo, limpiando el staging y
   exigiendo preparar/firmar de nuevo. Reduce el flujo de replay existente y
   requiere aprobación explícita de esa semántica.
3. Entregar (2)/(7) y resolver esta composición en el siguiente despacho.

La instrucción del usuario “Si algo exige decidir diseño o semántica no cubierta
por lo anterior, detente y repórtalo” determina esta pausa. No se cambia el test
G4, se descarta el preparado, se fabrica receipt ni se reinterpreta el RED de
staging como éxito. (5) queda pendiente porque el orden solicitado lo sitúa
tras (6); no está bloqueado técnicamente por los cambios de (2)/(7).

### Archivos, composición y fallbacks

Producto: `pm-vault/src/{authorization,human,attempts,audit,passkey,backup,reducer}.rs`
(exclusivamente política de apertura); `pm-custody/src/{agent_wire,linux,windows,lib,main}.rs`
y el módulo nuevo `custody_admission.rs`. Test: `audit_custody_tests.rs`.
Documento: este método. Cargo/lock/dependencias, fixtures existentes, workflows,
TUI/layout, provider None y loops listener/dispatcher permanecen idénticos a la base.

W1: posibles conflictos en lib/main/windows por declaraciones/callers, sin
cambios de TUI. W2: composición mecánica de flags en human/backup/reducer;
las dos ediciones del reducer son conexiones, no cambios de purge/sync ni de
su fallback kind. W4: nuevos campos en VaultService/AgentService y una llamada
acotada antes de admitir el intento. Al componer su dispatcher/multiagente debe
conservarse esa llamada en el engine común; no depende de un agent UID único
ni cambia la identificación de agentes.

Fallbacks adicionales identificados en W3: la creación implícita de SQLite
estaba también en attempts, audit, passkey (7 aperturas), backup y reducer
(2 aperturas), además de human/authorization; activaba al perder main-vault y
sustituía ausencia por una DB vacía. Se retira exclusivamente ese flag bajo (2).
Los demás fallbacks heredados de fases 1–5/result-sync se conservan, incluidos
reducer kind alternativo, getters a vacío, diagnósticos browser con sustitutos,
provider serve/handlers, Browser::stop, ProcessTlsTransport::put, sync_stage,
from_utf8_lossy, WindowsServerPipe/DestroyWindow y los errores SSH/agente de (5).
No se incorporan rutas alternativas ni salidas de éxito ante fallo.


### Reanudación de W3 — verificación y publicación, 2026-10-03

Se reconstruyeron `git status`, `git log ee3c1fd..HEAD`, `git show --stat HEAD`
y `git diff` antes de ejecutar o editar. Se preservaron el commit local
`4913a86d97d1a1e9ba302c5a2fbf9dd1acee470f` y todo el borrador anterior de este
informe. La publicación de ese SHA se hizo **después** de la verificación enfocada
y `check.sh`; `origin/codex/pm-w3-g7-failclosed` se comprobó por `ls-remote`.
No se integra W3, modifica un worktree ajeno, cambia tickets ni fusiona el PR #1.

RED actual: copia detached propia de `ee3c1fd` en
`/tmp/pmw3-resume-baseline-ee3c1fd`, sin cambios de producto ni fixtures.
GREEN actual: este worktree en `4913a86`. Se usan exactamente los mismos
fixtures/oráculos; sólo cambia el código de ese commit. El baseline y los logs
se conservan para revisión. Todas las llamadas Cargo/check/build/lab usan
`flock /tmp/pm-cargo-window.lock`, un bloque por vez; la espera del lock está
incluida en las duraciones, sin ampliar deadlines del producto o fixture.
Artefactos y `PYTHONDONTWRITEBYTECODE=1` son los indicados arriba.

`V` sigue siendo `./scripts/verify-ticket28-custody-loss.sh`. Cada comando de
esta tabla está precedido por `flock /tmp/pm-cargo-window.lock`.
Los nombres de logs se expanden desde `/tmp/pmw3-resume-`.

| Punto / comando | RED fresco en ee3c1fd | GREEN fresco en 4913a86 |
| --- | --- | --- |
| (2), `V vault completed` | rc1, reemplazo SQLite=1; control SUCCEEDED, calls=1, rechazo y restitución exactos. `red-vault-completed.log` | rc0, reemplazo=0, cerrado, calls=1, restitución exacta. `green-vault-completed.log` |
| (2), `V inflight vault` | rc1, reemplazo=1 tras intención running/provider_sent=1. `red-inflight-vault.log` | rc0, reemplazo=0, mismo ID INDETERMINATE/calls=1. `green-inflight-vault.log` |
| (2), `V inflight-live vault` | rc1 por reemplazo en recuperación; la admisión viva ya rechazaba. `red-inflight-live-vault.log` | rc0, ninguna sustitución y rechazo; no se atribuye un nuevo RED a la admisión viva. `green-inflight-live-vault.log` |
| (7), `V inflight-live bootstrap` | rc1, accepted=1; segundo intento cancelado antes del proveedor. `red-inflight-live-bootstrap.log` | rc0, accepted=0, rc4, calls=1. `green-inflight-live-bootstrap.log` |
| (7), `V inflight-live audit` | rc1, accepted=1; misma contención. `red-inflight-live-audit.log` | rc0, accepted=0, rc4, calls=1. `green-inflight-live-audit.log` |
| (6), `V matrix` | rc1, exactamente los dos RED EIO/ENOSPC de commit/outbox/audit; staging 1/1/17 tras error y restart. `red-matrix.log` | **No GREEN**: mismo RED en `gate-g7-matrix.log`, atomicidad/autoridad intactas |
| (5), propagación SSH/agente | Sin RED nuevo; inventario estático heredado | **Pendiente**, no se cambia producto tras la frontera de (6) |

Los cinco GREEN verifican cleanup `errors=0`, autoridad y una sola llamada del
proveedor. La matriz verifica cleanup del fixture en todos sus casos; ese
cleanup correcto no convierte el staging residual productivo en PASS.

Regresión adicional, con los mismos prerrequisitos y fixtures del método:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-custody --lib linux::audit_custody_tests --locked --offline -- --nocapture
# /tmp/pmw3-resume-custody-function.log: rc0, 7/7
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault --test human_transactions audit_failure_rolls_back_every_commit_part_and_lost_response_recovers_receipt --locked --offline -- --exact --nocapture
# /tmp/pmw3-resume-g4-same-prepared.log: rc0, 1/1
```

La segunda prueba confirma **observablemente** el replay existente del mismo
preparado tras un fallo sin efectos. Por inspección, borrar su única representación
cifrada impediría ese replay: no se ejecutó una variante productiva que lo borrara.
El contrato G4
[§9](../design/agent-identity.md#9-cierre-de-comandos-humanos-y-autoridad-distribuida)
referencia esos objetos por hash; `human.rs::load_staging` y
`validate_staged` requieren el paquete/streams/chunks, no sólo challenge/body_hash.
Los borrados dentro del commit final se revierten al fallar esa transacción.
La autorización de (6) no permite perder el preparado o fabricar un receipt.
Se mantiene la decisión concreta descrita arriba: **recomendada**, representación
cifrada durable diferenciada de los parciales, con replay/receipt íntegros y
recuperación/retención/transición terminal definidas; alternativa, aborto durable
y preparar/firmar de nuevo, que reduce el flujo existente y exige aprobación.
No se resuelve ese conflicto renombrando residuos para eludir el oráculo.
La instrucción explícita de detenerse ante semántica no cubierta delimita
este checkpoint; (5) y el inventario opcional posterior quedan pendientes.

El primer runner de reanudación olvidó reconocer el marcador
`PM28_SQLITE_SYNC_CLEANUP` y paró tras un RED válido de inflight. El log del
producto se conservó y sólo se corrigió el reconocimiento del marcador del
resumen, sin repetir ese caso ni editar el fixture/oráculo. Historia:
`focused-summary.log`, `focused-results-initial.json`; continuación y resultados
completos: `focused-summary-2.log`, `focused-results.json` (14 invocaciones).
No se cuenta el error del runner como RED de producto.

### Gates reejecutados y comparación de causas

Runner `/tmp/pmw3-resume-run-gates.py`; resultados
`/tmp/pmw3-resume-gate-results.json` y resumen
`/tmp/pmw3-resume-gate-summary.log`. Enumera los 40 casos de
`/tmp/pmrs-gate-results.json` y ocho modos adicionales. Sólo reutiliza el
`check.sh` fresco anterior (misma versión de producto), indicado explícitamente
como `reused_log=true`; los otros 47 comandos se ejecutan de nuevo con su flock.

| Comprobación | Resultado actual | Log en `/tmp/pmw3-resume-` |
| --- | --- | --- |
| `check.sh` | PASS rc0, 47.216 s; fmt/check/test/clippy locked/offline | `check.log` |
| `clean-offline-build.sh` | PASS rc0, 72.562 s con espera de lock | `gate-final-clean.log` |
| 26 wrappers Linux | 25 rc0; mismo FAIL TUI `exact-duplicates=1` con preview recortado, sin cambio de oráculo | `gate-lab-*.log`, `gate-lab-tui-operations.log` |
| Publication backup/plaintext/attachment | 3/3 rc0 | `gate-publication-*.log` |
| Audit/sqlite-sync/bootstrap completed | 3/3 rc0 | `gate-custody-audit.log`, `gate-sqlite-sync.log`, `gate-bootstrap-completed.log` |
| Matrix EIO/ENOSPC | **rc1**, exactamente los mismos dos RED staging; no hay otro defecto ni cleanup fallido del fixture | `gate-g7-matrix.log` |
| Inflight result-sync/bootstrap/audit/crash y canaries | 5/5 rc0; controles/canales completos en el alcance del método | `gate-g7-inflight-*.log`, `gate-g7-canaries.log` |
| Vault completed/inflight vault y tres inflight-live | 5/5 rc0, GREEN nuevos dentro del barrido | `gate-g7-extra-vault-completed.log`, `gate-g7-extra-inflight-vault.log`, `gate-g7-extra-inflight-live-*.log` |
| Matrix trace | rc0, control de fronteras íntegro | `gate-g7-extra-matrix-trace.log` |
| Bootstrap/vault, modos ambiguos sin `completed` | **rc1 diagnóstico**, sólo cambia el conteo audit: unchanged=(1,0,1,1,1), replacement=0, closed=1, cleanup errors=0; conserva la limitación de reconciliación ya documentada en fase 2 | `gate-g7-extra-bootstrap.log`, `gate-g7-extra-vault.log` |

Comparación de los **40 casos originales: 38 rc0, cero regresiones de rc o
causa frente al baseline**. Barrido ampliado: **48 casos, 44 rc0**; los cuatro
rc1 son TUI, matriz staging y los dos modos ambiguos anteriores. El runner rc0
significa coincidencia con las causas conocidas, **no** gates G7 todos verdes.
Los GREEN de vault-loss y retirada en caliente sí están en el barrido; staging
no está corregido. No se modifica W1, purge/sync de W2 o dispatcher/proveedor
W4 para cambiar estos resultados. No se reintenta un login ni se relaja un plazo.

### Fallback adicional inspeccionado al reanudar

`agent_wire.rs::serve_agent`, respuesta inicial de discovery: cualquier error
propagado por `DelegatedVault::discover`, incluidos Storage, Integrity o
Vault(ResourceUnavailable), se convierte en frame `[1]` igual al rechazo de
identidad/autoridad. Puede ocultar la causa de indisponibilidad como rechazo genérico.
Hallazgo **estático**, sin RED propio ni corrección; está antes de la función
acotada de nueva admisión. Los fallbacks SSH/read_frame/consumer ya inventariados
en fase 4 son precisamente (5), que sigue pendiente. Getters a vacío,
diagnóstico browser con sustitutos, etiqueta binaria TUI, provider serve/handlers,
Browser::stop, ProcessTlsTransport::put, sync_stage, from_utf8_lossy,
WindowsServerPipe y DestroyWindow se conservan en su alcance heredado.

### Estado vigente de criterios 28/G7 — W3 (5) verificado (checkpoint parcial)

Esta tabla sustituye la tabla de fase 5 e incorpora W3 (5); conserva
[spec §15](../../.scratch/passwordmanager/spec.md), G4/G7 y `Status: claimed`.

| Criterio | Estado y alcance vigente | Evidencia |
| --- | --- | --- |
| Records/AuthRecord/serializers, CSV/JSON/PMF1 y passkey 32 bytes | PASS acotado heredado, regresión workspace | Fases 1–4; check fresco |
| Frames/responses y requests propios custody/web/HTTP/JSON/CDP | PASS acotado heredado; no todo SSH ni heaps de terceros | Fases 1–4; labs y check frescos |
| Owners TUI split y requests restore/rotate | PASS acotado heredado; no presentación integral | Fase 4; labs TUI excepto FAIL conocido |
| Memoria propia integral, wires/presentación/ZIP/DEFLATE restantes | **FAIL de inventario**; bloque opcional no avanzado | Inventario fase 4 preservado |
| Presupuesto agregado 32 MiB y overhead físicos | **No demostrado**; contador test-only PASS, host 8 MiB sin modificar | Fase 2; check fresco |
| Guardas Linux/core/dumpable/stdin y crash real propio | PASS acotado, sin core en SIGABRT | Labs fault-safety/protected-input/inflight crash |
| 17.º RATE_LIMITED y CLOCK_UNTRUSTED | PASS acotado heredado | check y autorización frescos |
| Otros límites, incluido techo custodial 128 | **No demostrado integralmente** | Sin matriz nueva de esos techos |
| ENOSPC físico y spill WAL real EIO/ENOSPC | PASS acotado de rollback/restart | storage-fault/matrix frescos |
| Matriz WAL/staging/commit/outbox/audit | PASS atomicidad/autoridad; **FAIL cleanup (6)**, staging 1/1/17 | matrix RED fresco y gate; composición G4 pendiente |
| Replay del mismo preparado después de fallo, receipt tras pérdida de respuesta | PASS existente; limita la limpieza de (6) | `g4-same-prepared.log` y check |
| Resultado tras transmisión/intención/crash, INDETERMINATE sin doble login | PASS acotado con proveedor controlado calls=1 | inflight result-sync/crash frescos; no todos los proveedores |
| Bootstrap/audit ausentes con restart/ilegibilidad/restauración | PASS acotado heredado y regresión de función | audit, bootstrap completed, inflight, 7/7 función |
| (2) Vault perdido completado/en vuelo/con custodio vivo e ilegibilidad | **PASS acotado Linux**, rechazo sin SQLite sustituto; primera creación conserva su camino | Tres RED/GREEN frescos de vault y función; incluido en gates |
| (7) Retirada de bootstrap/audit con custodio vivo | **PASS acotado Linux**, nuevas admisiones cerradas, calls=1 | RED/GREEN inflight-live y gates |
| (5) Categorías/propagación SSH y agente | **PASS acotado Linux**, RED/GREEN y gates sin regresión; wire existente conservado | W3 (5) al final; causas tipadas y estado/logs seguros, sin ampliar W4 |
| Canarios/canales propios, activos/históricos y UID agente | PASS acotado de controles/scanner; cobertura global **no demostrada** | canaries/matrix/inflight frescos |
| Purge/outbox de revisión purgada | **Pendiente de W2**, RED heredado no reejecutado ni corregido por W3 | Fase 5/integración; fuera de este workstream |
| macOS/Windows, VirtualLock/WER, reboot/FDE, firma y aceptación humana | **Diferido/no acreditado**; seams del engine común preparadas | No CI nativa ejecutada por W3 |
| Check/build limpio/barrido Linux | PASS check/build; **48 casos, 44 rc0, cero regresiones** frente al baseline; aceptación global sigue **FAIL** | Gates W3 (5) finales frescos, mismos cuatro rc1 conocidos |
| Integración/revisión independiente y cierre de 28/G7 | **Pendientes**, fuera de esta entrega | Rama propia publicada; PR #1 borrador, ticket claimed |

macOS conserva el mismo engine y readers Unix de bootstrap/audit; Windows
conserva el mismo guard con sus readers DPAPI. Los futuros laboratorios nativos
deben repetir inicialización, pérdida/ilegibilidad/restauración exacta, admisión
viva cerrada, calls=1 y limpieza del fixture. Inspección de esas seams y PASS
Linux no acreditan compilación o aceptación de los targets nativos.

Archivos/posibles conflictos siguen siendo los detallados en W3 arriba:
W1 lib/main/windows; W2 sólo composición de flags de apertura en
human/backup/reducer; W4 campos de VaultService/AgentService y llamada acotada
`verify_admission_custody` antes de cada nueva admisión, que debe conservar.
Al reanudar no se cambió ningún Rust/fixture: sólo se completa este informe.
Siguiente acción: resolver la composición durable de (6) conservando G4,
observar su GREEN sin tocar el oráculo, continuar (5), repetir gates tras
producto nuevo y entregar al merger/revisor independiente. W3 y G7 siguen
**incompletos**.

## W3 (5) — método acotado de errores SSH/agente, 2026-10-03

El despacho posterior autoriza únicamente (5); (6) sigue pendiente de decisión.
Se conservan el discovery inicial `[1]`, listener/dispatcher/admisión W4,
TUI W1 y purge/sync W2. No hay categorías públicas nuevas del protocolo agente.
`RESOURCE_UNAVAILABLE` ya está previsto por G7 §2.1; la frontera pública de
custodia conserva `CUSTODY_UNAVAILABLE` y sus frames existentes.

Método para (a): controles de frame y copia protegida pequeños antes de bajar
RLIMIT_MEMLOCK sólo en un hijo de test; con límite cero, header completo sin
body y copia de password deben conservar `RESOURCE_UNAVAILABLE`, separada de
I/O. Método para (b): servidor SSH real, peer UID admitido y control de referencia
inexistente `[1]`; luego errores de header o parseo deben retornar error en vez
de desaparecer en el loop. Método para (c): se extrae sin cambiar comportamiento
el loop de requests de `serve_agent`, después del discovery; errores de lectura,
frame truncado/malformado y memoria deben terminar con error, nunca `Ok`.
La clasificación interna debe conservar origen/fase sin imprimir mensajes del
SO, payloads, rutas, destinos ni identificadores privados. Se comprueban también
lecturas válidas, códigos públicos fijos y ausencia de canarios en diagnósticos.

REDs sobre los seams heredados → GREENs enfocados → check/build limpio → los
48 comandos de `/tmp/pmw3-resume-gate-results.json`, en secuencia y cada uno
bajo `flock /tmp/pm-cargo-window.lock`, desde este worktree. Logs propios
`/tmp/pmw3c-*.log`; artefactos Keycloak/CFT absolutos del despacho. Comparación
por rc y causa, conservando los cuatro rc1 conocidos y cleanup errors=0.
No se altera el oráculo de staging, el estado de tickets ni ningún otro fallback.

### Inventario y cambio de (5)

| Punto | Seam exacto heredado | Resultado del candidato |
| --- | --- | --- |
| (a) | `crates/pm-ssh-client/src/lib.rs::read_frame`, `authenticate` (copia de password), `serve` (brazo del proveedor) | `Error::Memory(CryptoError)` conserva la causa; `Display/Debug=RESOURCE_UNAVAILABLE`. El fallo llega tipado al brazo de `serve`, registra RESOURCE_UNAVAILABLE/cause=protected-memory y conserva el frame3 indeterminado del wire existente. No lee body cuando falla el owner. |
| (a), cadena del firmante | mismo archivo, `CustodySigner::auth_sign` → `authenticate_publickey_with` en `authenticate` | El `SignError` vacío y su conversión final a Protocol también perdían el fallo de `read_frame`. El firmante usa el mismo `Error` y conserva memoria/I/O/SendError hasta la frontera SSH. |
| (b) | mismo archivo, `serve`, brazo consumer: `let Ok(read_frame) else continue` y parser `.ok()` | Lectura y `parse_consumer_reference` retornan error tipado desde `serve`; diagnóstico interno de causa y ninguna respuesta de éxito. Referencia inexistente conserva `[1]`. |
| (c) | `crates/pm-custody/src/agent_wire.rs::serve_agent`, loop de lectura posterior al discovery | Loop extraído `serve_agent_requests`; `read_agent_frame` conserva I/O original y fase header/body, memoria y frame inválido. En la frontera existente registra sólo clasificación segura y retorna `Failure::Unavailable`, nunca `Ok` tras error. |

`Error::Io`/`Ssh` conservan sus fuentes originales por `std::error::Error::source`.
Los mensajes públicos/Debug contienen sólo códigos; logs internos tienen fase,
ErrorKind, errno, categoría criptográfica o discriminante de russh de la versión
fijada, nunca `Display/Debug` del I/O/SSH upstream. No se serializa una fuente
upstream. `main.rs` sólo adapta la construcción del runtime al nuevo error I/O.
La lectura agente conserva exactamente el límite heredado 18 MiB; SSH conserva
128 KiB, IO_TIMEOUT, host-key pinning, métodos, checks y sus frames existentes.
La propagación de lectura/parseo del consumidor sale de `serve` como error
terminal, con rc4/código fijo. En el proveedor, el frame3 indeterminado conserva
el contrato existente mientras la causa de memoria queda tipada y registrada.
No añade reintentos ni reparación de conexiones.

El discovery inicial de `serve_agent` sigue convirtiendo **cualquier** error de
`DelegatedVault::discover` (storage/integridad/memoria incluidos) en `[1]`.
Es separable: se preservó íntegramente su código previo al loop, sin corregirlo.
Listener, dispatcher, admisión, handlers de intentos/proveedor, W1/W2/W4 y (6)
no se modificaron. El clasificador `human_wire::FrameReadFailure` queda intacto.

### RED/GREEN de (5)

Desde este worktree, comandos completos (sin instalar ni usar red):

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-ssh-client --lib error_propagation_tests --locked --offline -- --nocapture
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-custody --lib agent_wire::error_propagation_tests --locked --offline -- --nocapture
```

| Punto | RED conductual previo al cambio de producto | GREEN enfocado |
| --- | --- | --- |
| (a) | `/tmp/pmw3c-red-ssh.log`, rc101: controles válidos; frame y copia password con memlock=0 observan SSH_UNAVAILABLE | `/tmp/pmw3c-green3-ssh.log`, rc0: ambos RESOURCE_UNAVAILABLE; servidor conserva frame3, causa interna ResourceUnavailable y sigue vivo antes de body |
| (b) | mismo RED SSH, rc101: control `[1]` del servidor vivo, después header mayor al máximo descartado (`returned=false`) | mismo GREEN SSH final, rc0: header, parseo y EOF parcial retornan error (`returned=true`), referencia desconocida mantiene `[1]` |
| (c) | `/tmp/pmw3c-red-agent.log`, rc101: timeout del reader produce `success=true` en el loop real posterior al discovery | `/tmp/pmw3c-green3-agent.log`, rc0: timeout/I/O/UnexpectedEof/header/body truncados/frame inválido `success=false`; memoria tipada, frame válido y cierre ordenado explícito cubiertos |

La extracción de `copy_password` y del loop conservó literalmente la semántica
heredada para ejecutar los RED: no era una corrección previa ni fallo de setup.
Los GREEN iniciales `green-ssh.log`/`green-agent.log` también se conservan; el
segundo tenía un warning corregido sin cambiar comportamiento. El check inicial
`/tmp/pmw3c-gate-final-check.log` pasó tests y falló únicamente en Clippy
(semicolon/let-else/single-match); **no es RED conductual**. Las correcciones son
de estilo, sin cambiar límites ni aserciones. Dos entradas `ignored` nuevas son
hijos memlock ejecutados obligatoriamente por sus padres, no casos omitidos.
Los controles adicionales de servidor, fuentes tipadas y canarios no se atribuyen
como REDs separados. Los logs GREEN no contienen el password sintético ni el
canario de path/payload del I/O; fixtures sockets propios restantes=0.

### Fallbacks heredados adicionales inspeccionados

- `pm-ssh-client::serve`, `channel_open_session`: ante error SSH devuelve `[1]`,
  igual que referencia inexistente. Conserva ese contrato; ahora registra sólo
  clasificación interna segura de la causa SSH. No se convierte en éxito.
- `pm-ssh-client::consume`: cualquier respuesta diferente de `[0]` se convierte
  en `AUTH_REJECTED`, incluidos frames inválidos. Conservado sin corrección.
- `pm-ssh-client::Profile::read_installed`: errores de metadata/read se agrupan
  en `INVALID_PROFILE`; el getter `Profile::value` devuelve `""` si falta la
  clave. Conservados; parser cerrado y validaciones previas no cambian.
- `CustodySigner` perdía fuentes en `SignError` y Protocol; se corrigió sólo la
  cadena necesaria de (a). Sus owners Vec propios de firma no se migran aquí.

Los demás fallbacks excluidos expresamente por el despacho siguen intactos.
No se detecta necesidad de otra categoría pública del protocolo del agente.

### Checkpoint publicado antes del barrido completo

Tras las correcciones de estilo, `/tmp/pmw3c-gate2-final-check.log` termina rc0
(38.290 s, incluye lock), fmt/check/test/clippy locked/offline.
`/tmp/pmw3c-gate2-final-clean.log` termina rc0 (45.465 s, incluye lock), clean y
build workspace/all-targets locked/offline. Producto y pruebas enfocados quedan
verificados; el runner `/tmp/pmw3c-run-gates2.py` está ejecutando los otros 46
comandos y conserva resultados por invocación, sin reutilizar logs.
Este checkpoint no declara el barrido aceptado ni el cierre de W3/G7.

### Corrección de compatibilidad observada en el primer barrido

El checkpoint inicial `eba30006ca6019e745e9f8dc7a408a543e2f118b` tenía check y
clean verdes, pero el barrido detectó dos regresiones reales. Sus gates parciales
`/tmp/pmw3c-gate2-results.json` y logs se conservan; **no** son aceptación.

- `lab-adapter-protected-frame` rc1: el candidato cerraba el adaptador SSH por
  memoria en vez de devolver su frame3 existente. Se corrigió exclusivamente
  el brazo `Error::Memory`: conserva ese wire y el servicio vivo, con causa
  tipada ResourceUnavailable y diagnóstico seguro diferente de I/O/SSH.
- `lab-attempts`/`lab-authorization` (y otros consumidores del mismo helper)
  rc1: el nuevo diagnóstico imprimía UnexpectedEof ante el cierre ordenado
  entre requests, vulnerando su stderr vacío. El reader ahora reconoce un
  `read` exitoso de cero bytes antes del header como `Ok(None)`; el loop lo
  termina normalmente sin log. Un Err real, timeout, header/body parcial o
  alloc/mlock sigue propagando fallo, con su causa y fase. Interrupted conserva
  la semántica de `read_exact`, sin modificar deadlines ni inventar otro canal.

No se cambió ningún lab/oráculo heredado. Los tests nuevos mantienen la
aserción de denegar cada **error** de lectura y agregan el control de EOF limpio.
El control nuevo de servidor SSH ahora exige el frame existente, causa de
memoria exacta y servicio vivo. No se atribuye el primer GREEN del checkpoint
inicial a la aceptación del wire ni a preservación de stderr normal.

El runner inicial se detuvo sólo después de terminar su caso activo
`lab-passkey-login` (log preservado); no se interrumpió su lab, no se señaló
ningún proceso ajeno ni se reutilizan resultados parciales para el gate final.
La corrida final usa `/tmp/pmw3c-run-final.py`, se detiene entre casos ante
cualquier regresión, reejecuta los 48 comandos y conserva un log nuevo por caso.

El contrato real TLS precisa otro control: `rustls` devuelve UnexpectedEof si
un cliente cierra sin close_notify; los clientes existentes no envían siempre
ese cierre TLS. No se convierte ese **Err** en éxito. Antes de producir el
Failure público se conserva el error original en `LAST_READ_FAILURE`, estado
interno acotado al último fallo del hilo de conexión. Sólo UnexpectedEof **antes
de recibir el primer byte** del siguiente header queda sin stderr; el mismo
error después de empezar header/body se diagnostica. Este estado guarda la
fuente tipada original sin clones ni serialización de mensajes upstream; no es
un historial durable. Timeout, I/O, memoria y frame inválido siguen retornando
Failure::Unavailable. Ok(None) existe exclusivamente por un read exitoso de
cero bytes. Se comprueba que el error EOF observado conserva source y estado,
y se repiten adapter-protected-frame, authorization y attempts antes del gate.
No se cambia el cliente, su protocolo ni el dispatcher W4 para este control.

Los checks intermedios `/tmp/pmw3c-gate3-final-check.log` y
`/tmp/pmw3c-gate4-final-check.log` acabaron rc101 exclusivamente por Clippy
(needless_continue y match_same_arms). No ejecutaron labs ni son RED de
comportamiento. `/tmp/pmw3c-corrective2-clippy.log` pasa rc0 sobre el correctivo.
Los GREEN definitivos enfocados son `green3-ssh.log` y `green3-agent.log`,
3/3 padres por crate, hijos memlock incluidos. Los labs correctivos
`corrective-adapter.log`, `corrective-authorization.log`, `corrective-attempts.log`
pasan rc0 con sus aserciones originales y stderr normal vacío.

### Checkpoint correctivo verificado

El correctivo pasa `check.sh` (19.153 s, rc0) y clean/offline
(41.526 s, rc0), con logs `/tmp/pmw3c-final-final-check.log`
y `/tmp/pmw3c-final-final-clean.log`. Los GREEN enfocados y tres labs correctivos anteriores
también pasan. El manifiesto `/tmp/pmw3c-final-source-manifest.json` y patch
`/tmp/pmw3c-final-code.patch` identifican los cuatro Rust bajo este gate;
no se modifica producto durante el barrido. Los 48 casos siguen en ejecución
con logs frescos; este checkpoint sustituye el candidato incompatible eba3000,
pero no adelanta aceptación integral.


### Gates finales de W3 (5) y entrega al coordinador

Código verificado y publicado: `daada55` (correctivo de `eba3000`), sobre
`1df6319`. El commit documental final no modifica esos cuatro Rust.
Runner `/tmp/pmw3c-run-final.py`, resultados `/tmp/pmw3c-final-results.json`,
resumen `/tmp/pmw3c-final-summary.log`. Los **48 casos se reejecutaron**,
ningún log reutilizado, una invocación local por bloque bajo el mismo flock.
El manifiesto de fuentes permaneció exacto desde el inicio hasta el fin.
Artefactos PM_KEYCLOAK_DIST y PM_CFT_DIR absolutos del despacho.

| Gate | Resultado final frente a `/tmp/pmw3-resume-gate-results.json` | Log propio |
| --- | --- | --- |
| `scripts/check.sh` | rc0, fmt/check/test/clippy workspace/all-targets locked/offline | `/tmp/pmw3c-final-final-check.log` |
| `scripts/clean-offline-build.sh` | rc0, build limpio locked/offline | `/tmp/pmw3c-final-final-clean.log` |
| 26 wrappers funcionales Linux, incluido SSH | 25 rc0; TUI operations conserva su rc1 y causa exact-duplicates=1/preview recortado | `/tmp/pmw3c-final-lab-*.log` |
| Wrapper publication, tres modos backup/plaintext/attachment | 3/3 rc0; juntos con los anteriores cubren los 27 wrappers `test-linux-*-lab.sh` existentes | `/tmp/pmw3c-final-publication-*.log` |
| Custody audit, sqlite-sync, bootstrap completed | 3/3 rc0 | `/tmp/pmw3c-final-custody-audit.log`, `final-sqlite-sync.log`, `final-bootstrap-completed.log` |
| Matrix EIO/ENOSPC | rc1, exactamente los dos RED staging commit-outbox-audit; ningún otro defecto, cleanup errors=0 | `/tmp/pmw3c-final-g7-matrix.log` |
| Inflight result-sync/bootstrap/audit/crash y canaries | 5/5 rc0, causes/control/scanners completos dentro del método vigente | `/tmp/pmw3c-final-g7-inflight-*.log`, `final-g7-canaries.log` |
| Vault completed/inflight vault, tres inflight-live | 5/5 rc0; se preservan los GREEN (2)/(7) | `/tmp/pmw3c-final-g7-extra-*.log` |
| Matrix trace | rc0, control de fronteras conservado | `/tmp/pmw3c-final-g7-extra-matrix-trace.log` |
| Bootstrap/vault sin completed, modos ambiguos | mismos dos rc1 diagnósticos: unchanged=(1,0,1,1,1), replacement=0, closed=1, cleanup errors=0 | `/tmp/pmw3c-final-g7-extra-bootstrap.log`, `final-g7-extra-vault.log` |

Total: **48 casos / 44 rc0 / cero regresiones de rc o causa**. Duración agregada
390.101 s (cada invocación incluye espera de lock); rc0 del runner acredita
coincidencia con el baseline, **no** aceptación global de G7. El RED de (6)
sigue intacto y no hay implementación de staging. Las comprobaciones
enfocadas adicionales de (5) no se agregan artificialmente al conteo de 48.
Los GREEN enfocados definitivos no contienen canarios de password/path/payload,
no tienen warnings y los fixtures de sockets propios restantes son cero.
No hubo cambios de aserciones/oráculos heredados, límites/KDF/deadlines,
dependencias, credenciales reales, estados de tickets ni otros worktrees.

Archivos de este despacho y conflictos previsibles:

- `crates/pm-ssh-client/src/lib.rs`: errores, firmante y brazo consumidor.
- `crates/pm-ssh-client/src/main.rs`: conversión del error del runtime.
- `crates/pm-ssh-client/src/error_propagation_tests.rs`: nuevas regresiones Linux.
- `crates/pm-custody/src/agent_wire.rs`: sólo loop/reader/causa de lectura y tests;
  `AgentService`, discovery, dispatcher de opcodes y admisión quedan iguales.
- `docs/verification/ticket-28.md`: método, evidencia y tabla vigente.

W1/W2 no comparten Rust tocado por este despacho. W4 puede entrar en conflicto
textual en `serve_agent`/loop de conexión; conservar discovery existente, campos
actuales, `verify_admission_custody` y la propagación/estado acotados de lectura.
El informe común ticket-28 requiere composición documental con los otros
workstreams. No se integra ninguna rama ni se fusiona el PR borrador #1.

Siguiente acción: revisión e integración por el coordinador/merger independiente
del **HEAD final completo** de esta rama, comprobando el net diff desde 1df6319;
no seleccionar sólo eba3000. (6) queda para decisión del usuario y su despacho
posterior. W3/G7 globales siguen incompletos y 28 conserva `claimed`.
macOS/Windows/VirtualLock/WER/reboot/FDE/firma y aceptación humana no se
acreditan con esta ejecución Linux x86_64.

El único bytecode generado por los labs correctivos sin PYTHONDONTWRITEBYTECODE,
`crates/pm-custody/tests/__pycache__/linux_lab.cpython-314.pyc`, se verificó como
archivo regular owned del worktree inicialmente limpio y se retiró por esa
ruta exacta junto al directorio ya vacío; no se barrió ninguna ruta ajena.
