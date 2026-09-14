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
