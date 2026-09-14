# Ejecución de la especificación v1.0

## Autorización y roles

El usuario solicitó explícitamente `implement-spec` después de publicar la especificación: autoriza pasar de documentación a implementación del alcance aprobado, sin cambios funcionales ni publicación en un destino inventado. La excepción de autorización posterior de AGENTS.md queda satisfecha por esta solicitud. La base histórica de la spec permanece; sus frases sobre ausencia de autorización describían la fase de síntesis.

- Astra (`gpt-6-astra`): coordinación de DAG y revisión; no delegar revisión de seguridad al mismo implementador que produjo el cambio.
- Sol (`gpt-5.6-sol`, esfuerzo `medium`): implementación con complejidad criptográfica, autoridad, protocolos, persistencia, nativos o integración sensible.
- Luna (`gpt-5.6-luna`, esfuerzo `max`): cambios acotados/mecánicos sobre contratos y seams ya presentes. Escalar a Sol si afecta garantías de seguridad; no hacer avanzar tickets bloqueados para ocupar agentes.
- Merger separado: integrar serialmente y verificar suite completa, manteniendo la rama unificada verde.

El usuario fijó explícitamente los esfuerzos anteriores después de actualizar sus acuerdos de trabajo. Toda nueva delegación especifica el esfuerzo; no heredar silenciosamente los niveles históricos. No introducir fallbacks. Si se detecta uno existente, informar ubicación, activación y comportamiento sustituido antes de solicitar autorización para cambiarlo.

## Base e integración

- Base documental: `a7597bef21e6d6ebe0a03e492b8f96a89fdf1ae4` en `master`.
- Rama unificada: `codex/implement-passwordmanager`.
- Cada implementador: worktree propio bajo `.worktrees/<ticket>` y rama `codex/pm-<ticket>` creada desde HEAD verificado de la rama unificada. Nunca implementar en el checkout compartido del coordinador.
- Frontera: solo tickets cuyos `Blocked by` estén resueltos con entregables requeridos integrados y comprobados. El primer ticket debe establecer toolchain/build y seam real antes de depender de ellos.
- Prompts de despacho: rutas absolutas del worktree, spec, ticket, contratos y skills; no transcribir especificaciones gigantes.
- TDD: conservar evidencia de red/green, checks y revisión por ticket; no considerar ausencias de dependencias como prueba roja válida de comportamiento.
- Integración: merger verifica commit/alcance, integra rama sin reescritura destructiva, ejecuta suite/configuración disponibles y reporta evidencia. Solo entonces resolver ticket y recalcular frontera.
- Worktree se retira solo tras integrar y verificar, si está limpio; conservar rama/commit para trazabilidad. Nunca borrar archivos de otro agente activo.
- No ejecutar review formal Astra por ticket: el usuario indicó «do the review at the end of all tickets not ticket by tickets». Cada ticket conserva TDD, checks, comprobación propia e integración verificada por merger; estos controles no son la revisión formal de código.
- Revisión final Astra por dos ejes aislados (`Standards` y `Spec`) conforme `code-review`; no anunciar implementación completa por resolver un subconjunto.

## Condiciones de entrega

El usuario autorizó crear repositorio público y publicar documentación/código: [SantanaJcp/passwordmanager](https://github.com/SantanaJcp/passwordmanager). Origin configurado; base documental subida a master. PR borrador [#1](https://github.com/SantanaJcp/passwordmanager/pull/1) creado; aún no declara producto implementado. No publicar credenciales ni información ajena al proyecto. Un Markdown con enlace previsto no es un PR creado.

El push ordinario de `01a74a7` anunció una excepción de administrador al ruleset activo `main` (ID 23168096, `~ALL`). Se pausó la publicación para aclararlo. El usuario confirmó que creó esa protección para terceros y autorizó explícitamente continuar usando nuestra excepción de administrador. Se reanudan los pushes ordinarios autorizados; no cambiar las reglas, usar force push ni ampliar esa autorización a otras acciones destructivas.

Solo Linux x86_64 está observado en este host. El usuario confirmó disponibilidad de este Linux/Omarchy y una Mac Apple Silicon; acceso/ejecución en la Mac aún no verificados. Linux ARM64, macOS Intel y Windows x64/ARM64 no tienen entorno confirmado. El usuario asumirá la validación final del gate 34 y pidió que Astra también verifique todo lo posible: pruebas/review del agente son evidencia técnica, no auditoría externa certificada ni sustitución de la aceptación humana pendiente. Las pruebas nativas, Chromium propio y firma/notarización necesitan sus entornos/artefactos. No simular resultados ni retirar esas puertas del alcance; documentar evidencia real y qué no se ejecutó.

El usuario autorizó preparar el [método CI nativo efímero](../../docs/verification/native-ci.md) y su workflow manual para cinco runners estándar compatibles, sin coste, secrets de firma ni publicación automática. La preparación separa preflight de entorno de validación del producto y no cambia el estado de evidencia anterior. GitHub exige que un workflow con `workflow_dispatch` exista primero en la rama por defecto `master`; integrar este archivo solo en la rama unificada o un PR no habilita todavía su ejecución. Un merger/publicador separado colocará el mismo workflow manual mínimo en `master` y después elegirá el ref confiable que también contiene workflow y scripts, sin fusionar por ello el PR de producto ni cambiar protecciones. No se modifica `master` desde el worktree de preparación.

Después del run 34761618195 fallido, el usuario autorizó explícitamente instalar
Rust `1.98.1` como etapa obligatoria en los cinco jobs, fijar
`RUSTUP_AUTO_INSTALL=0` antes de toda llamada a Rustup sin fallback de versión,
corregir la cardinalidad PowerShell bajo StrictMode y fijar checkout oficial a
una revisión que declare Node 24. La remediación usa checkout v7.0.1 en
`3d3c42e5aac5ba805825da76410c181273ba90b1`, verificado contra el tag y
`action.yml` oficiales. No autoriza caches, artifacts, secrets, larger runners,
gasto, otros cambios de producto ni el fallback pendiente de TUI 23.

La especificación y contratos están en [spec.md](spec.md). Este documento registra ejecución, no sustituye el estado de diseño de §15 ni redefine contratos.

## Preparación comprobada

Rust instalado de forma local en `.toolchain/`, sin modificar PATH/configuración global. Comandos futuros deben establecer `RUSTUP_HOME=<raíz-del-repo>/.toolchain/rustup`, `CARGO_HOME=<raíz-del-repo>/.toolchain/cargo` y anteponer ese `cargo/bin` al PATH; worktrees no deben crear instalaciones divergentes ni usar su propio PWD como raíz de toolchain.

Verificado en este host: `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`; rustfmt/clippy instalados para el mismo toolchain. Bootstrap oficial rustup-init validado SHA-256 `dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71`. [Manifest oficial del toolchain](https://static.rust-lang.org/dist/channel-rust-1.98.1.toml), [bootstrap checksum](https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256). Esta comprobación inicial de versiones no acreditaba build del proyecto. Posteriormente, 01 entregó workspace/lockfile y runner; el merger verificó clean offline build y 9 tests en Linux x86_64. Evidencia en [ticket 01](issues/01-build-reproducible-y-runner-de-procesos.md); no acredita todavía bóveda funcional, seguridad ni otros targets.

Astra entregó [propuesta de DAG de 35 tickets](implementation-plan.md), comprobada con IDs consecutivos/dependencias previas/sin ciclos y criterios/punteros presentes. El usuario aprobó granularidad/orden con «autorizado»; [35 tickets publicados](issues/README.md) conforme `to-tickets`. La frontera inicial es 01; no se puede ejecutar tickets descendientes en paralelo antes de integrar sus dependencias.

## Cuatro ajustes de desbloqueo autorizados

El usuario confirmó conjuntamente estos cuatro ajustes después del informe de
preflight 5/5 y aceptación macOS todavía fallida:

1. TUI 23: seleccionar explícitamente el campo a revelar/copiar, sin sustituir
   una contraseña ausente por notas; conservar todos los campos accesibles.
2. Windows 27: compilar libsodium 1.0.22 desde la fuente fijada mediante MSVC,
   de forma explícita, sin recurrir al fallback de binarios precompilados.
3. macOS 26: raíz efímera única `/private/var/tmp/passwordmanager-ticket26`,
   padre root con modo `01777`, colisiones rechazadas, raíz propia `0711` y
   subdirectorios privados `0700`; no cambiar permisos del home del runner ni
   seleccionar otra ruta si falta un requisito.
4. Verificación: observar el estado contractual estable admitiendo únicamente
   estados intermedios documentados, sin repetir autenticaciones ni ampliar
   los plazos existentes; conservar código de salida y diagnósticos seguros
   para fallos antes indeterminados. Documentar el método concreto antes de
   ejecutar las pruebas modificadas; no convertir errores en éxito.

La autorización no elimina gates, no cambia el modelo de seguridad y no
adelanta la revisión formal de Astra: continúa al final de todos los tickets.

## Método concreto de observación asíncrona autorizado

El 2026-09-13 el usuario autorizó ajustar únicamente el método de observación y
los tres laboratorios que tenían carreras de asentamiento; no se autoriza tocar
el motor productivo, reautenticar, repetir una operación del proveedor ni
ampliar sus plazos. Primero se conserva la corrida base roja y su diagnóstico;
después cada laboratorio debe ejecutar la misma operación sobre el mismo
`attempt_id` hasta observar el estado contractual final. La espera se hace por
la consulta pública de estado ya existente, con los límites ya definidos por
cada laboratorio, y no por un `sleep` fijo que anuncie éxito. Un estado o razón
fuera de la lista permitida falla inmediatamente; tampoco se convierte un
error de proceso en éxito.

Las únicas transiciones intermedias admitidas son:

* **Intentos (ticket 08):** el mismo `get` puede observar `RUNNING` sin razón
  mientras el worker ejecuta una solicitud nueva, o `RUNNING` con razón
  `provider-challenge-ref` mientras asienta un desafío. Después de reiniciar el
  custodio, también puede observar `RUNNING` con razón `INDETERMINATE` mientras
  el worker reclama la reconciliación; solo el estado terminal esperado
  satisface cada comprobación (`WAITING_FOR_HUMAN`, `SUCCEEDED`, `FAILED` o
  `INDETERMINATE`, según la operación). La consulta no vuelve a enviar
  credenciales y el journal debe conservar una única llamada del proveedor.
* **Passkey expirada (ticket 14):** después de que la confirmación TTY
  rechazada devuelve el código existente, el mismo estado puede observar
  `RUNNING` con razón `PASSKEY_HUMAN_CONFIRMATION` mientras se asienta en
  `WAITING_FOR_HUMAN`; el resultado debe seguir siendo nulo y no se envía otra
  confirmación ni reautenticación. La cancelación se mantiene como operación
  posterior separada y terminal.
* **Token exchange (ticket 11):** se conserva la aserción final de audiencia
  no autorizada (`FAILED`, sin resultado). Si el `auth start` inicial retorna
  error antes de publicar el intento, el laboratorio conserva su código,
  `stdout` y `stderr` en un diagnóstico acotado y sintético, sustituyendo el
  token de sujeto, secreto de requester y contraseña maestra por
  `<REDACTED>` antes de mostrarlo. No se reintenta el `start` ni el POST.

El diagnóstico base anterior a la extracción del worker registró, en el
laboratorio de intentos, una lectura `RUNNING/INDETERMINATE` en 1 de 8 corridas
después del restart; la variante actual con el worker extraído terminó verde en
8 de 8 corridas; en passkey la ventana
`RUNNING/PASSKEY_HUMAN_CONFIRMATION` fue legítima y no reprodujo un fallo
adicional; en token exchange la negativa de audiencia original retornó un
código distinto de cero sin `stdout`/`stderr`, sin reproducción en nueve
corridas posteriores. Los tickets 08, 11 y 14 ya estaban resueltos con su
evidencia de producto y este ajuste de método no los reabre ni sustituye esa
evidencia. Tampoco cierra las puertas nativas todavía pendientes de 26--32: la
corrida modificada debe conservar la evidencia roja, demostrar la espera
contractual y volver a terminar con las aserciones finales intactas.


## Integración del método asíncrono — 2026-09-13

Merger Sol distinto integró el candidato Luna `2f92f69` como `d1d8b1f` y corrigió atribución del baseline/estados documentales en `9af3770` y `461058c`. No cambió el motor ni reabrió 08/11/14. Config, Python AST de los tres labs, diff, `scripts/check.sh` y clean locked/offline (41.641 s) pasaron.

La primera barrida tuvo un fallo de `passkey-login` al iniciar el intento de cuenta (`CUSTODY_UNAVAILABLE`), no una lectura de estado intermedio. El loop de esa primera barrida no propagó el fallo; su exit 0 **no se acepta como suite verde**. Una repetición enfocada pasó y una nueva barrida completa con acumulación explícita de errores terminó `count=17 failures=0`. Esta última es la evidencia de integración, sin ocultar la falla intermitente anterior ni atribuirle una causa todavía no demostrada. No se repitió autenticación dentro de una misma aserción ni se aumentaron deadlines.

23 quedó integrado sin conflictos textuales como `c74aba0` y resuelto tras
verificación independiente del merger: check, clean locked/offline y 18/18 labs
Linux con propagación explícita de fallos. La selección de campo 51–53 es la
única exposición; 47/48 se rechazan y `primary_human_secret` no existe. Esto
habilita recalcular la frontera de 24/25, pero no los implementa ni convierte
sus flujos CLI en TUI; tampoco cierra la UX streaming pendiente para attachments
mayores que el frame humano. La evidencia nativa reciente está en
[native-ci.md](../../docs/verification/native-ci.md); la revisión formal
permanece al final de los 35 tickets.


## TUI23 integrada — frontera24/25

Candidato `f1c375e` integrado sin conflictos como `c74aba0`, resolución23 en `0b897c1`. Merger distinto verificó `check.sh`, clean locked/offline (43.067 s) y barrida robusta de18labs, `count=18 failures=0`, sin reintentos. 47/48 y `primary_human_secret` retirados; exposición por catálogo51 e índice52/53, con negativas reales. Estado:23/35.24 y25 ahora tienen sus dependencias integradas;24 se asigna a Sol medium,25 espera slot libre. El flujo TUI streaming de adjuntos grandes se conserva como pendiente explícito de composición25, no queda validado por enumerar su descriptor.

25 asignado a Sol medium en worktree propio, en paralelo con24. Sol23 deja candidato Windows27 `6bef3bc` congelado; corrida nativa34799533393 pendiente. Luna mantiene26; root coordina nuevas corridas sin editar candidatos activos.


## Composición25: sync observable sin ampliar plazos

La implementación encontró read-timeout humano de15s frente al backoff idempotente ya aprobado de sync. No se autorizó el timeout propuesto de75s: no cubre request30s por intento ni múltiples hashes/páginas, y puede dejar UI fallida con publicación todavía activa.25 debe separar inicio autorizado de trabajo cifrado observable por ID/estado/progreso en el motor único, preservando outbox/backoff y lock/idle sin retener HumanVault/KH tras bloqueo. Consultar estado no repite autenticaciones ni operaciones. Este ajuste de implementación satisface los contratos existentes; no reabre el backoff de [G5](../../docs/design/synchronization.md) ni crea gestión de sesiones de negocio. Exige método y pruebas de indisponibilidad durante sync, estado final y bloqueo/reinicio sin éxito inventado antes de aceptar25.

## TUI24 — RED de cleanup en integración

El merger separado integró `36934b3` sin conflicto como `77a5198` y obtuvo PASS
en `git diff --check`, `scripts/check.sh`, clean locked/offline (44.43 s) y los
19 cuerpos funcionales Linux en una única barrida. El gate no se acepta: el
nuevo `tui_access_lab.py` usa `shutil.rmtree(root, ignore_errors=True)` y ocultó
un fallo real, dejando `/tmp/pm-tui-access-linux-lab-c4d1o_6i` con fixtures
sintéticos de UIDs mapeados aunque devolvió 0. La resolución provisional se
revirtió en `3205ae9`; 24 permanece claimed hasta corregir el lab y volver a
verificar sin convertir cleanup fallido en éxito. No se repitió la barrida ni
se atribuye este hallazgo al motor productivo.


## Ventana local coordinada de verificación

Los worktrees comparten `.toolchain/`, artefactos y CPU. Antes de ejecutar
`scripts/check.sh`, clean builds o barridas de labs pesadas, root concede una
única ventana Linux local; otros worktrees detienen esas ejecuciones hasta el
handback. Native CI en runners separados puede continuar. No se cambian el
producto ni sus plazos para ocultar contención del host.

## TUI24 — cleanup corregido e integración aceptada

El RED de `ignore_errors=True` se corrigió en raíz sin tocar producto: limpieza
cerrada por ruta/owner y UID mapeado, propagación de todos los errores y PASS
solo después de verificar ausencia de la raíz propia. La primera variante
estricta rechazó correctamente el `terminal.raw` todavía no inventariado; tras
registrarlo, la regresión enfocada pasó sin añadir residuos y sin tocar el RED
original. En ventana local exclusiva, `git diff --check`, `scripts/check.sh`,
clean locked/offline (1m 01s; 11,644 archivos/4.0 GiB) y una única barrida final
pasaron con `count=19 failures=0 ticket24-cleanup-set-changed=0`. No quedaron
procesos o residuos propios nuevos. 24 queda resuelto; no acredita nativos,
Chromium de producto, ticket25 ni revisión formal Astra.

## TUI25 — integración y fixture SQLite quiescente

El candidato `2a01905` se compuso sobre 24 por merger distinto. Una barrida
exclusiva preservó RED `count=20 failures=1`: token exchange intentó leer
`vault.sqlite3-shm` después de que el custodio lo eliminara; los otros 19 labs
pasaron. Con autorización explícita se estabilizó sólo el fixture: `SIGSTOP` y
`SIGCONT` al PID custodial propio con reconocimiento `waitpid` no bloqueante y
límite monotónico existente de 20 s, escaneo completo quiescente sin ignorar
`ENOENT`, reanudación garantizada y cleanup estricto/agregado antes de `PASS`.

En la ventana final sin otro Cargo/lab local activo pasaron el token enfocado,
`scripts/check.sh` (75 s), clean locked/offline (44 s; 11,754 archivos/4.1 GiB)
y una única barrida secuencial `count=20 failures=0` (617 s), con logs
`/tmp/pm25-final4-test-linux-*-lab.log`. No hubo skips, retries de producto ni
cambios de deadline. 25 queda integrado y resuelto para Linux x86_64; no
acredita nativos ni la revisión formal final.

## Propagación de errores de cleanup — integración distinta

El candidato `4400ffb6af241dcb03e806abb594359a71e49762` se integró sobre la
raíz limpia `9db150c` por un merger distinto. Hubo un único conflicto textual
en `crates/pm-custody/src/linux/tui.rs`; la resolución conservó el flujo de
acceso/pendientes y reautenticación de 24 junto con los guardas de cleanup del
candidato. No se tocaron otros worktrees, gates nativos, `master` ni la
revisión formal.

La honestidad TDD queda explícita: `cd320084951b3a8e1328c7367c8882a43eafe456`
era un checkpoint de especificación que no compilaba por helpers ausentes,
no un RED conductual. Los fallos posteriores de compilación/Clippy fueron
defectos del harness o del código en desarrollo; no prueban una regresión
conductual previa. Las comprobaciones finales de inyección de fallos sí
quedaron verdes, pero no se inventa una transición red→green de comportamiento.

En la única ventana Linux exclusiva, después de dos filtros enfocados, pasaron
`scripts/check.sh` (rc 0), `scripts/clean-offline-build.sh` (rc 0) y una sola
barrida secuencial de los 20 laboratorios con los artefactos absolutos fijados:

```text
PM_KEYCLOAK_DIST=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/keycloak/keycloak-26.7.3
PM_CFT_DIR=/home/santana/Documents/ChatGPT/passwordmanager/.scratch/lab-artifacts/cft/chrome-linux64
SUMMARY count=20 failures=0
```

Los logs son `/tmp/pm-cleanup-check-final.log`,
`/tmp/pm-cleanup-clean-final.log` y
`/tmp/pm-cleanup-final-test-linux-*-lab.log`. El filtro enfocado de cleanup
quedó en 3 tests de `pm-vault` y 4 de `pm-custody`; la corrección adicional
del test de publicación enumera y verifica sus seis rutas propias (target y
temporary, cada una con WAL/SHM), sin glob ni ignorar errores distintos de
`NotFound`. Los ocho sidecars regulares `0600`, UID-1000, de los PIDs
`3809446`, `3811566`, `3827457` y `3832552` se verificaron como residuos
propios de tests/checks previos de esta ventana y se eliminaron por ruta
exacta. Seis pares más antiguos (`3682543`, `3692174`, `3697766`, `3729529`,
`3743420` y `3748215`) no tienen proveniencia demostrable en los logs
disponibles y se dejaron intactos; no se afirma que el directorio temporal
global esté vacío. El filtro final y la barrida final no dejaron nuevas rutas.

La evidencia acredita sólo Linux x86_64. Las líneas `LIMIT` de los laboratorios
siguen siendo límites de aceptación para browser de producto, targets nativos,
cross-platform y servicios externos; no se convierten en gates cerrados.

## Evidencia nativa y memoria — checkpoint 2026-09-14

La raíz conserva 25/35 tickets integrados. Los siguientes resultados pertenecen
al trabajo aislado de 26–28, no cierran tickets ni sustituyen la integración
por merger o la revisión global final.

- **macOS:** el [run 34847582724](https://github.com/SantanaJcp/passwordmanager/actions/runs/34847582724)
  en `6c3c5e0` falló antes del harness: cinco `expect` nuevos exigían `Debug`
  para `Failure`. La corrección de test `a247340` mantuvo el error opaco.
  El [run 34848148030](https://github.com/SantanaJcp/passwordmanager/actions/runs/34848148030)
  compiló y ejecutó correctamente el test AppKit en biblioteca y binario,
  tanto Intel como Apple Silicon. El primer arranque TUI mediante `forkpty`
  devolvió `CUSTODY_UNAVAILABLE` antes de pedir contraseña en ambos targets.
  No se acredita la aceptación TUI. El candidato con documentación `7d3bba5`
  pasó check completo y clean build Linux; la causa nativa sigue en diagnóstico.
- **Windows:** `5d64bc2` pasó check y clean build Linux, que no compilan los
  bloques Windows. El run `34848390243` fue cancelado por root tras detectar
  estáticamente la falta de `Send` en el pipe transferido al worker; no es RED
  de compilación ni conductual. La corrección `0a0ec3d` pasó 6 tests nativos y
  1 contrato de pipe en el [run 34848533955](https://github.com/SantanaJcp/passwordmanager/actions/runs/34848533955).
  Se verificaron `RUNNING` con STOP, detención SCM, ausencia del PID anterior,
  reinicio con PID distinto y probes de ambos roles antes del primer unlock.
  `human-lock` volvió a fallar en el límite de auditoría vacía ya identificado;
  segundo STOP y crash/restart posteriores no se ejecutaron. Cleanup retornó
  sin error, pero el harness aún no consulta ausencia final de servicio,
  usuario y directorio después de borrarlos. Las tres apariciones de `args-ok`
  en consola reflejan dos generaciones y una reimpresión de la historia, no
  tres arranques. Cambiar la API pública de unlock para exigir custodia de
  auditoría estable sigue pendiente de autorización; su WIP está aislado.
- **Memoria (28):** `3b9a34f` pasó tests enfocados crypto/CLI y una ejecución
  del lab de fallos, tras RED real que mostraba lectura antes de proteger la
  primera línea. Este corte protege el buffer antes de la confirmación, no
  durante su lectura inicial. El test posterior `6063859` mantiene stdin
  abierto y envía cero bytes: reprodujo que el cliente espera entrada antes
  de reservar memoria bloqueada. Su corrección está en verificación separada;
  no se declara G7 cerrado ni se amplían sus excepciones de memoria.

Los cuatro errores de cleanup heredados adicionales ya señalados y el cambio
público de custodia de auditoría permanecen pendientes de aprobación. No se
alteran por deducir permiso de autorizaciones anteriores con otro alcance.

### Autorización posterior del checkpoint

2026-09-14 — El usuario respondió «autorizado» a la pregunta explícita sobre
ambos cambios pendientes: `HumanVault::unlock` recibirá custodia de auditoría
estable explícita, adaptando sus consumidores sin reducir los flujos CLI/TUI;
y se propagarán los cuatro errores de limpieza ya identificados en
`TemporaryDirectory::drop`, keygen de clave privada parcial,
`rpc_download_atomic` y `write_new`. Se preservan el error primario, los
fallos de cleanup y la propiedad de recursos; no autoriza fallbacks, borrar
recursos ajenos ni modificar otras omisiones heredadas. Las menciones de
«pendiente» en el checkpoint anterior son históricas desde esta aprobación.

### Integración de unlock auditado y resultados nativos posteriores

2026-09-14 — El merger distinto integró el cambio común en `a9eb4b8`:
`HumanVault::unlock` exige custodia estable explícita, registra `HumanUnlock`
atómicamente y conserva la rotación humana autenticada de generación. Check,
build limpio offline y la barrida final de **20/20 labs Linux** pasaron.
Los fallos e intentos intermedios se conservan en
[el informe de integración](../../docs/verification/audit-unlock.md): el trigger
de atomicidad se corrigió para alcanzar el commit y permitir la reconexión para
receipt, no para eludir la nueva auditoría del unlock.

El candidato Windows aislado `50dd1bf` pasó el
[run 34853430364](https://github.com/SantanaJcp/passwordmanager/actions/runs/34853430364):
6 tests nativos, contrato de pipe, unlock/lock auditado, STOP/restart,
crash deliberado y consultas de ausencia final de recursos propios. Esto no
acredita la TUI completa ni resuelve 27. Su launcher ConPTY sigue en preparación.

macOS `f1a1a51` alcanzó copia TUI, pero su log no distinguía rc0 de
extracción. El diagnóstico posterior sobre binario normal `73e9175`,
[run 34858597883](https://github.com/SantanaJcp/passwordmanager/actions/runs/34858597883),
**confirmó exposición del canario en ambos CPU**: el agente devolvió el valor
exacto y el humano conservaba la copia antes/después. Las identidades eran las
esperadas, pero ambos procesos compartían el dominio launchd humano. El
laboratorio no satisface G1 por cambiar sólo UID mediante sudo; el siguiente
fixture debe probar un dominio agente separado real y conservar este resultado
como evidencia del perfil inseguro. No se afirma aislamiento ni cierre de 26.

Se mantienen **25/35 tickets integrados**. Los cuatro cleanups recién
autorizados siguen en 28; este checkpoint no los declara implementados ni
sustituye la revisión unificada final.

### Integración de los cuatro cleanups autorizados y corte nativo actual

2026-09-14 — Merger distinto integró `a4b7704..f3fe05d` sobre `168573d`,
commit `b467d0e`: cierre comprobado del directorio de evidencia y propagación
de fallos de limpieza en keygen, `write_new` y `rpc_download_atomic`. Conserva
el error primario y todos los errores tipados de cleanup, sin reintentos ni
borrado de recursos ajenos. El informe distingue el RED conductual de este
candidato de los fallos de compilación de un candidato anterior y declara la
sobrescritura accidental de un log histórico, sin inventar su recuperación.

Check, build limpio offline, focalizados y barrida secuencial final de
**22/22 labs Linux x86_64** pasaron; evidencia en
[cleanup-errors](../../docs/verification/cleanup-errors.md). Los dos casos
`ignored` son entradas de subprocesos ejecutadas por sus tests padres.
Los dos alcances de la última autorización quedan integrados. Esto no cierra
el ticket 28 ni constituye revisión formal o certificación de seguridad.

- **macOS:** el [run 34862828726](https://github.com/SantanaJcp/passwordmanager/actions/runs/34862828726)
  sobre `d514233` falló antes de ejecutar el nuevo probe de dominio aislado:
  Apple Silicon no observó la selección en la segunda TUI a 80×24;
  Intel no obtuvo el cierre esperado de la primera TUI. El control compartido
  volvió a mostrar extracción en ARM; en Intel expiró el probe sin medirla.
  No invalida la exposición confirmada en ambos CPU por la corrida anterior,
  ni acredita el nuevo aislamiento. Falta además la matriz completa TUI.
- **Windows:** el launcher ConPTY real de `7998eba` ya demostró el RED de
  producto: `tui` termina con `INVALID_ARGUMENT` antes del criterio de vida
  ([run 34857970004](https://github.com/SantanaJcp/passwordmanager/actions/runs/34857970004)).
  El [run 34864402493](https://github.com/SantanaJcp/passwordmanager/actions/runs/34864402493)
  de `a6ddb89` pasó 8 tests nativos, 1 pipe, 6 observer y 1 sync, pero falló al
  encontrar modo de foco 1004 en el observador. `9e50f51` reconoce ese modo
  estáticamente; no tiene verificación nativa y el movimiento mecánico de la
  TUI compartida no implementa aún la TUI Windows completa.
- **G7:** el candidato de lectura nativa en memoria protegida tiene evidencia
  Linux parcial; la nueva fixture ENOSPC `33516bb` sólo pasó comprobaciones
  estáticas y requiere primero componer la API actual de auditoría. No hay
  aceptación integral de memoria, disco lleno o crash-safety.

Se mantienen **25/35 tickets integrados** y el PR en borrador. Los worktrees
26–28 quedan preservados sin procesos de verificación activos en este corte.
La revisión Astra global se ejecutará después de integrar todos los tickets.

### Continuación integral: checkpoint G7 y ports en ejecución

2026-09-14 — El usuario pidió continuar hasta terminar todos los tickets.
Merger distinto integró `96dd37a` por merge normal `3ca41ee` y documentó
la evidencia en `3fbd7eb`: raíces y entrada CLI en memoria protegida,
`NativeStdin` común sin prefetch, primer password de custodia protegido y
ENOSPC real con rollback/restart. Check, build limpio offline, focalizados y
**25/25 labs Linux x86_64** pasaron. Evidencia y límites en
[ticket-28](../../docs/verification/ticket-28.md). No se atribuye protección al
inventario plaintext restante ni a macOS/Windows; 28 sigue `claimed`.

El RED header-only de custodia era insuficiente: `stdin.lock()` precargaba el
canario antes de reservar su destino. La regresión socketpair/FIONREAD lo
reprodujo y la lectura nativa compartida lo corrigió. ENOSPC ya pasaba sobre
el producto previo; se registra como cobertura existente, no RED fabricado.

El [run macOS 27](https://github.com/SantanaJcp/passwordmanager/actions/runs/34869338454)
en `a3db150` confirmó nuevamente la exposición del control compartido en ambos
CPU; falló después por secuencia VT incompleta al terminar ese control con
SIGTERM. No llegó al probe aislado. Se prepara cierre normal de la sesión de
control sin tolerar errores del parser ni salidas no cero.

Windows progresa hacia una TUI y handler únicos. Los runs
[26](https://github.com/SantanaJcp/passwordmanager/actions/runs/34868629220) y
[27](https://github.com/SantanaJcp/passwordmanager/actions/runs/34869286841)
fallaron en compilación de la extracción compartida, no son RED de producto
ni aceptación nativa. Las correcciones y el adapter 1PUX por HANDLE están en
worktree y requieren check local/nativo; aún falta sync Windows completo.

Se mantienen **25/35 tickets integrados**. Los gates externos de firma real,
Windows 11 x64/reboot/FDE y validación humana no se simulan; se solicitó al
usuario disponibilidad de certificados y responsables de firma sin pedir
claves privadas. La revisión global continúa reservada para el final.

### Composición 26–28: evidencia parcial, sin cierres anticipados

2026-09-14 — El recorrido básico TUI macOS pasó en Intel y Apple Silicon;
la ampliación a contenido completo aún debe discriminar repaint parcial de
fallo real de expiración. Windows compila sus seams compartidos, pero el primer
prompt ConPTY sigue sin aceptación. Commits, corridas y alcance exacto en el
[estado nativo](../../docs/verification/native-ci.md#composición-nativa-posterior--2026-09-14).

En el worktree 28, los owners protegidos de descifrado de revisiones/chunks,
leases y entrada de adaptadores pasaron pruebas enfocadas y check/clean Linux.
También pasó la lectura protegida de campos secretos posteriores por stdin;
el RED válido comprobó password y metadata pública antes del header secreto,
descartando fixtures que fallaban antes de ese seam. No están integrados aún
ni acreditan serializers, respuestas, todos los frames TLS, inventario de
registros o la matriz completa de fault injection.

Se continúa esa frontera; no se abre 29 antes de integrar 26/27 ni se resuelve
28 por sus checkpoints. **25/35 integrados**, PR borrador, revisión unificada
al final y validación humana separada pendiente.
