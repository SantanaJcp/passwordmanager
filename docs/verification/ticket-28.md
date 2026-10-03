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

### Estado vigente de criterios 28/G7 — fase 3 (checkpoint parcial)

Esta tabla sustituye el estado vigente de fase 2, sin borrar su cronología.

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
