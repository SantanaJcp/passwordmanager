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

## Fallbacks heredados fuera del cambio sin autorización

- `pm-process-runner::TemporaryDirectory::drop` descarta el error de
  `remove_dir_all`; puede dejar un directorio de evidencia aunque la observación
  ya fue devuelta.
- `pm-custody` descarta fallos al retirar la privada si `keygen` no publica su
  pública, al retirar `.partial` después de fallo de descarga y al retirar un
  archivo nuevo después de fallo de write/fsync.

Esos fallbacks se informaron antes de tocar código. El cleanup de `persist_new`
se corrige en el cambio separado ya autorizado y se compondrá antes del gate
integral; este ticket no duplica esa edición.

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
