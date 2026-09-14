# Ticket 28 — método de fallos operativos, canarios y crash safety

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
