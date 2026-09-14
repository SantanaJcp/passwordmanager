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
