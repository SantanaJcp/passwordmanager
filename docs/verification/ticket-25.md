# Ticket 25 — método de verificación TUI de operaciones

## Método escrito

El laboratorio se ejecuta en Linux x86_64 dentro del `user namespace`
desechable ya documentado para los tickets 17 y 23. Usa procesos reales con
UID distintos, el custodio y motor SQLite reales, el canal humano TLS 1.3/RPK,
una PTY `tmux` real a 80x24 y exclusivamente eventos de teclado. Todos los
archivos y credenciales son fixtures sintéticos privados del directorio
temporal; no se modifica el host.

La prueba debe observar por la TUI, y luego comprobar en el motor o en archivos
durables, los siguientes recorridos completos:

1. importar CSV y 1PUX mediante selección de fichero, previsualización sin
   valores, resumen de nuevos/duplicados/candidatos/excluidos y mapeo elegido;
   cancelar no muta, y una confirmación escrita distinta de `IMPORT` no muta;
2. exportar plaintext sólo tras advertencia y `EXPORT`, crear backup nativo,
   restaurarlo y rotar maestra/recuperación sólo después de mostrar el alcance;
3. crear emparejamiento para el pin RPK observado, sincronizar con el proceso
   opaco TLS real, mostrar corte offline como error explícito sin declarar
   éxito, y retirar el dispositivo elegido mediante evento causal firmado;
4. consultar auditoría sin secretos y purgar únicamente el rango mostrado tras
   confirmación escrita `PURGE AUDIT`, conservando el marcador de hueco;
5. descargar un attachment seleccionado de más de 16 MiB por frames acotados a
   un destino nuevo 0600, con digest y longitud exactos. No se materializa el
   attachment completo en el frame humano ni en memoria.

Las pantallas deben mostrar advertencias sobre plaintext persistente, copias y
backups ya expuestos, recovery histórico, clipboard fuera de custodia, estado
offline y el alcance exacto de cada acción destructiva. La selección y las
previsualizaciones no muestran secretos. Esc cancela antes del commit. Un
destino existente, un fichero fuente inválido, pin incorrecto, servidor caído,
confirmación incorrecta o fallo de streaming produce fallo explícito y no una
ruta alternativa, retry oculto, éxito parcial ni borrado del origen.

## Criterio de éxito y regresión

El laboratorio enfocado debe terminar con `PASS tui-operations` y comprobar
import, export, backup, restore, ambas rotaciones, pairing/sync/offline/retire,
audit/purge y attachment streaming. Después deben pasar `scripts/check.sh`,
`scripts/clean-offline-build.sh`, todos los `scripts/test-linux-*-lab.sh` y
`git diff --check`, sin skips, mocks de aceptación ni ampliación de deadlines.
La evidencia sólo acredita Linux x86_64; los demás targets pertenecen a los
tickets nativos y de distribución.

Comandos exactos del cierre, ejecutados desde la raíz del worktree y con el
toolchain local fijado por los scripts:

```bash
./scripts/test-linux-tui-operations-lab.sh
./scripts/check.sh
./scripts/clean-offline-build.sh
set -u
failures=0
for lab in $(find scripts -maxdepth 1 -type f -name 'test-linux-*-lab.sh' | sort); do
  name=${lab##*/}; name=${name%.sh}
  log="/tmp/pm25-final3-${name}.log"
  if "$lab" >"$log" 2>&1; then
    cat "$log"
  else
    rc=$?
    printf 'FAIL %s rc=%s log=%s\n' "$lab" "$rc" "$log" >&2
    failures=$((failures + 1))
  fi
done
test "$failures" -eq 0
git diff --check
```

La barrida es secuencial, conserva un log por laboratorio y no reintenta un
fallo. Se ejecuta una sola vez dentro de la ventana Linux exclusiva; no usa
`--test-threads=1`, sleeps nuevos, skips ni cambios de timeout del producto.

### Extensión aprobada del fixture de token exchange

La barrida de integración exclusiva posterior al merge conservó un RED real:
19 de 20 laboratorios pasaron y `test-linux-token-exchange-lab.sh` terminó en
rc 1 al desaparecer `vault.sqlite3-shm` entre `is_file()` y `read_bytes()`
durante el escaneo de canarios (`/tmp/pm25-integration-final-test-linux-token-exchange-lab.log`).
No se reintentó esa barrida. Se aprobó estabilizar exclusivamente el fixture:
debe enviar `SIGSTOP` al PID exacto del custodio propio, esperar que ese mismo
hijo quede detenido, enumerar y leer todos los archivos del estado mientras
está quiescente —incluidos los sidecars WAL/SHM presentes, sin ignorar
`ENOENT`— y reanudar garantizadamente el mismo PID con `SIGCONT`, incluso si
una lectura o aserción falla. El estado detenido y continuado se clasifica con
`waitpid` no bloqueante y el límite monotónico de 20 segundos ya usado por el
fixture para esperar recursos; cada observación comprueba también si el hijo
terminó. Este polling sólo reconoce el estado del PID propio: no repite una
operación ni amplía un deadline del producto.

El `finally` debe intentar detener todos los procesos propios aunque falle uno,
reanudar primero al custodio si quedó pausado, eliminar estrictamente sólo el
directorio temporal creado por este laboratorio y comprobar su ausencia. Sus
errores se agregan y propagan; no se usa `ignore_errors` ni se acepta ausencia
como sustituto de un unlink fallido. Los tres `PASS` sólo pueden imprimirse
después de completar y verificar ese cleanup. El RED anterior es la regresión
TDD; el verde enfocado debe recorrer el Keycloak/CFT y custodio reales antes de
repetir `check`, build limpio y una única barrida secuencial de los 20 labs en
una ventana local coordinada sin otros Cargo/labs.

## Evidencia TDD

La prueba de retiro se escribió primero contra dos dispositivos reales. El
primer rojo rechazó `device-retire` en el `CHECK` de `human_staging`. Tras
admitir el tipo, el reductor siguió rechazando el evento: el commit humano
usaba como `previous` la cabeza global, que podía pertenecer al otro
dispositivo. El seam corregido conserva la cabeza global para vistas y
auditoría, pero encadena cada evento firmado con la cabeza de su
`issuer_device` y generación; los tips observados del dispositivo retirado se
mantienen como padres causales. La regresión recorre dos dispositivos y las
permutaciones/convergencia existentes sin retirar validaciones de autoridad.

En el laboratorio PTY, el primer intento de preparar el segundo dispositivo
con el recorrido compuesto `human-content-flow` sobre una bóveda ya poblada
acabó en `CUSTODY_UNAVAILABLE`; no se aisló cuál de sus comprobaciones internas
falló y no se le atribuye una causa. El método final levanta un segundo proceso
`serve-vault` con ID de dispositivo y custodia de auditoría propios, publica un
CRUD humano completo y firmado por ese proceso, restaura la custodia del
owner, reinicia el servicio y ejecuta por teclado
`y` → `3` → `<device>|RETIRE`. El verde observa el mensaje de alcance y la fila
`device-retire` con el sujeto exacto. Esto acredita el retiro TUI contra
historia real local; el caso de réplicas completas y orden de sync continúa en
la regresión causal de `pm-sync`, no se sustituye por el fixture PTY.

Otros rojos observados y conservados fueron: rechazo explícito de una fuente
CSV inexistente sin cerrar la TUI; confirmación de import distinta de `IMPORT`
sin mutación; y el primer `scripts/check.sh`, que pasó los tests pero detuvo
Clippy por documentación de errores, brazos iguales, `chunks_exact` constante
y sentencias sin punto y coma. Se corrigió el código, no los umbrales ni las
aserciones. Un rojo posterior del harness esperaba una línea larga sin tener
en cuenta el wrap real a 80 columnas; se sincronizó con el fragmento visible
sin repetir la operación de retiro.

El verde enfocado termina con:

```text
PASS tui-operations keyboard=1 pty=1 tls-rpk=1 import=csv+1pux+preview+mapping+duplicates+confirm backup=native plaintext=warn+confirm restore=1 rotation=master+recovery sync=pair+pinned-real+job-id+restart+idle-lock+bounded-unavailable+retire-second-device+offline-explicit audit=query+purge attachment=streamed-large source-unchanged=1 no-secrets-preview=1
```

El harness sólo imprime esa línea después de terminar su `finally`: comprueba
que el servidor `tmux` propio ya no existe, exige que `kill-server` tenga el
resultado esperado, espera y comprueba el cierre de cada proceso y thread que
creó, elimina sin supresión de errores exclusivamente su directorio temporal y
confirma su ausencia. No usa `ignore_errors`, no ignora un cleanup fallido y no
toca namespaces ni recursos ajenos. Cada cleanup se intenta aunque falle uno
anterior y un `ExceptionGroup` propaga todas las causas antes de cualquier
`PASS`. Tras cerrar normalmente la última sesión, `tmux` puede informar rc 1
como `no server running`, `failed to connect` o `server exited unexpectedly`;
son los únicos estados sin servidor aceptados, siempre con stdout vacío. Otro
rc/mensaje o un `kill-server` fallido rompe el laboratorio.

Una verificación de código terminó con `scripts/check.sh` y
`scripts/clean-offline-build.sh` en exit 0 después de corregir los rojos de
Clippy descritos arriba. Una primera barrida de los 19 laboratorios terminó
en exit 1 (`count=19 failures=5`): `passkey`, `passkey-login`,
`token-exchange` y `web-auth` devolvieron rc 1 sin contenido en sus logs, y
`recovery` agotó los 15 segundos existentes al ejecutar
`human-master-rotate`. Los otros 14, incluido `tui-operations`, pasaron. Los
logs, incluso los vacíos, se conservan; no se atribuye causa sin un
discriminante. Para los cuatro fallos web el discriminante posterior fue
exacto: las variables de artefactos no estaban definidas, los paths por defecto
dentro del worktree no existían y cada script terminó en su guard silencioso
`test -x` antes de Cargo. No fue una falla de producto ni se atribuye a
contención. La causa del timeout de `recovery` no quedó aislada; no se cambió
su timeout ni polling.

La primera repetición enfocada después de endurecer cleanup llegó al final de
los recorridos de producto, pero terminó RED: al haber cerrado la última sesión,
`tmux list-sessions` devolvió rc 1 con `server exited unexpectedly`, estado que
el clasificador aún no reconocía. Además, esa excepción detenía el `finally`
antes de intentar los cleanups restantes. El ajuste anterior clasifica sólo
esa salida exacta de ausencia y agrega errores sin omitir las demás limpiezas;
no repite ninguna operación de producto ni relaja sus aserciones.

En la ventana Linux exclusiva final se verificaron previamente los artefactos
compartidos sin copiarlos ni descargarlos: Keycloak `26.7.3`, Chrome for
Testing `153.0.8010.36` y su SHA-256
`79a4ebf6da53e4ceab11844257aabc5166f17b595dc694d6382cbee8ff50565f`.
Se exportaron sus paths absolutos aprobados. El laboratorio enfocado terminó
con el `PASS` exacto anterior; `scripts/check.sh` terminó en exit 0;
`scripts/clean-offline-build.sh` eliminó 12,625 archivos/4.2 GiB y reconstruyó
desde limpio en 41.49 segundos con exit 0; y la barrida secuencial final
terminó `SUMMARY count=19 failures=0`. `recovery` también pasó sin cambios.
Los logs finales están en `/tmp/pm25-final3-test-linux-*-lab.log` y ningún
laboratorio fue reintentado dentro de esa barrida.

## Extensión acordada: trabajo sync observable

El backoff ya aprobado del motor (`1,2,4,8,16,30` segundos para el mismo hash
idempotente) puede exceder el timeout de 15 segundos del canal humano. No se
amplía ese timeout: iniciar sync debe autorizar y persistir un trabajo sobre
ciphertext,
devolver un ID inmediatamente y ejecutar `SyncReplica` en un worker del mismo
custodio sin conservar `HumanVault` ni `K_H`. La TUI consulta por ID estados
cerrados (`queued`, `pushing`, `pulling`, `succeeded`, `unavailable`) y sigue
procesando teclado, idle y lock. Sólo `succeeded` muestra contadores; ningún
estado intermedio o fallo se presenta como éxito.

La configuración secreta transferida por el humano se conserva únicamente en
un fichero custodial sensible nuevo 0400 bajo el directorio privado de la
bóveda, con creación sin colisión y escritura durable. El contenedor firmado
`to_protected_bytes` autentica la pertenencia al vault, pero **no cifra** la
clave de pairing; la protección real en reposo es custodia nativa por
owner/modo/directorio privado. Un reinicio recupera exactamente el
trabajo no terminal desde ese fichero; no vuelve a autenticar al humano ni
crea otro trabajo. Al terminar se elimina la configuración secreta y queda un
estado durable sin secretos consultable por el mismo ID. Fallos de integridad,
backpressure, disponibilidad y journal/cleanup conservan categorías visibles
distintas. Un crash entre estado terminal y cleanup se reconcilia antes de
recuperar trabajo; si el journal o cleanup falla no se anuncia éxito ni se
bloquea el daemon, y el estado queda como fallo explícito. Una petición nueva se
rechaza mientras haya trabajo pendiente. Los paths y pins se vuelven a validar
antes de cada ejecución; no se elige otro binario, endpoint o credencial.

Las regresiones unitarias del journal se escribieron contra los bordes de fallo
antes de cerrar el seam: una escritura de estado fallida deja el job terminal
en `journal failure`, nunca activo ni exitoso; un reinicio reconcilia un estado
terminal cuya configuración sensible aún existe; y un cleanup imposible se
vuelve fallo visible sin impedir que el daemon atienda otros requests. Los tres
casos pasaron en los targets de biblioteca y binario. La escritura secundaria
del propio diagnóstico es best effort sólo después de saber que el journal está
roto; el estado en memoria ya es terminal y explícito, no una ruta alternativa
ni un éxito oculto.

La regresión debe demostrar con proceso real: inicio no bloqueante; consulta de
progreso; lock/idle mientras el worker continúa; caída del endpoint a mitad de
sync seguida de todos los backoffs contractuales y estado final
`unavailable`; restart durante el trabajo y recuperación del mismo ID; y sync
feliz final con una sola publicación lógica. Las consultas no repiten la
operación ni alteran los deadlines.

## Evidencia de integración independiente

El merger compuso `2a01905` sobre la raíz con 24 ya aceptado. El primer loop
exclusivo conservado terminó `count=20 failures=1`: el laboratorio token
exchange levantó `FileNotFoundError` para `vault.sqlite3-shm` exactamente en
la carrera descrita en la extensión del método; los otros 19 pasaron. No se
aceptó ni se reintentó ese loop. Después de la corrección aprobada, dos verdes
enfocados sucesivos acreditaron primero el seam de pausa/cleanup y luego su
reconocimiento acotado; el segundo terminó en 35 segundos y sus tres `PASS`
aparecieron sólo tras cleanup verificado. Los logs son
`/tmp/pm25-fixture-focused-token-exchange.log` y
`/tmp/pm25-fixture-focused-token-exchange-bounded.log`.

Sobre la variante final, `scripts/check.sh` terminó rc 0 en 75 segundos
(`/tmp/pm25-fixture-final-check.log`) y `scripts/clean-offline-build.sh`
terminó rc 0 en 44 segundos, eliminando 11,754 archivos/4.1 GiB y compilando
offline desde limpio (`/tmp/pm25-fixture-final-clean-offline.log`). La barrida
secuencial final se ejecutó una sola vez, sin otro Cargo/lab local activo, y
terminó `SUMMARY count=20 failures=0 elapsed=617s`. Sus logs individuales
están en `/tmp/pm25-final4-test-linux-*-lab.log`; token exchange, las tres TUI,
recovery, passkey y web auth quedaron incluidos. No se cambiaron los deadlines,
Argon, aserciones ni recorridos de producto y no hubo skips o retries ocultos.
La evidencia acredita sólo Linux x86_64, no soporte nativo ni revisión formal.
