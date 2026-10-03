# W4 — concurrencia, agentes y proveedor ordinario

Base autorizada: `ee3c1fd31cad59060e4120f3e2518b1196a90c1a`.
Worktree `.worktrees/w4-agents-provider`, rama `codex/pm-w4-agents-provider`.
No integración, merge del PR ni cambio de estado de tickets.

## Método antes de ejecutar

Se aplica el método Linux de [03](ticket-03.md), [07](ticket-07.md),
[24](ticket-24.md) y [composición](integration-26-28.md), con procesos reales,
UIDs kernel separados y datos sintéticos. Toda invocación local de
Cargo/check/build/lab adquiere `flock /tmp/pm-cargo-window.lock`, desde este
worktree; toolchain compartido exacto, locked/offline, sin dependencias nuevas.
Logs propios `/tmp/pmw4-*.log`.

Concurrencia: el nuevo `scripts/test-linux-concurrency-lab.sh` arranca
**serve-vault ordinario** una sola vez, enrola la identidad A por el canal
humano y abre la TUI real en tmux. Discovery debe responder con la TUI abierta
y conservar el mismo PID. Después prueba conexiones del mismo rol: tres
conexiones nativas incompletas del UID agente no impiden un cuarto cliente
TLS/RPK válido; cuatro ocupadas hacen rechazar el quinto sin desalojarlas.
Al cerrarlas se recupera admisión. Los sockets incompletos prueban la reserva
pre-handshake; no se presentan como cuatro handshakes autenticados. Los plazos
existentes no se amplían. El teardown sigue el inventario estricto de 24 y el
PASS se imprime solo después de eliminar la raíz propia.

El modo explícito `scripts/test-linux-concurrency-lab.sh multiagent` demuestra
el siguiente RED: A y B se enrolan, A descubre y B intenta descubrir contra
ese mismo proceso/bootstrap, sin reinicio. Para pasar debe recibir el mismo
conjunto. No se cambia el producto para obtener ese resultado hasta acordar
el binding confiable.

El lab 24 mantiene sus comprobaciones anteriores y consulta además discovery
con la TUI abierta. El protocolo por conexión continúa serial: no se añade
cola de requests ni ejecución concurrente dentro de una misma conexión; hay
un request activo, por debajo del máximo 16. Los límites de intentos 16/agente
y 128/custodio permanecen en `AttemptVault::start` y se verifican con los gates
existentes. Dentro del rol humano se conserva la serialización actual; esta
evaluación no afirma concurrencia entre dos canales humanos persistentes.

Gate final: ejecutar los 40 comandos exactos de
`/tmp/pmrs-gate-results.json`, conservar logs/rc/oráculos y comparar caso por
caso (baseline: 38 rc0, TUI operations y G7 matrix rc1), más el nuevo lab.
No aceptar fallo de build como RED de comportamiento ni repetir un fallo sin
hipótesis. CI nativa conforme [native-ci.md](native-ci.md): un dispatch normal
macOS y Windows sobre la rama verificada, registrando `headSha`, URLs y logs;
sin caches/artifacts/secrets ni cambios de workflow.

## Fronteras y decisiones identificadas

El siguiente correctivo requiere un binding nativo confiable por RPK.
`AgentEnrollment::environment_binding` es un texto de hasta 256 bytes: el
contrato lo trata como etiqueta, y los enrolamientos existentes usan
`linux-lab`, no UID/SID. El único binding nativo actual está en el bootstrap.
No se inferirá autoridad de etiquetas ni se aprenderá UID/SID del primer
cliente. Antes de implementar multiagente deben decidirse formato,
provisión confiable y migración de ese registro.

Proveedor ordinario: `serve_vault` conserva `provider: None`; el worker y la
recuperación solo se componen con `Some`. Los adaptadores reales usan procesos
con configuración instalada; el tipo `ControlledProvider` describe un
socket/UID y también transporta llamadas a adaptadores reales en los labs.
No se instalará el proveedor controlado de laboratorio en producción.

## Fallbacks heredados observados y conservados

* `linux.rs::accept_one` y `windows.rs::serve_role`: ante error del handler se
  descarta el resultado y se sigue aceptando; `accept_one` también descarta
  errores de accept/configuración. La política de errores no es este fix.
* `linux.rs::serve_loop`: falla `DelegatedVault::open` durante recuperación y
  se omite recuperación; el worker descarta errores de `run_provider_once`.
  `run_provider_once` descarta un fallo de settle AUTHORITY_REVOKED.
* `agent_wire::serve_agent` y handlers humanos: fallo de lectura se trata como
  cierre normal; no se distingue EOF de error/integridad.
* `authorization_lab.py`: `shutil.rmtree(..., ignore_errors=True)` oculta
  cleanup fallido. No se cambia ni se usa como evidencia de cleanup seguro.
* `WindowsServerPipe::create`/Drop: resultados LocalFree/DisconnectNamedPipe/
  CloseHandle descartados. No se corrigen liberaciones nativas aquí.

Los demás inventarios heredados de [26](ticket-26.md), [27](ticket-27.md) y
[composición](integration-26-28.md) conservan su alcance y pendientes.

## RED/GREEN de concurrencia

* RED, base sin cambios de producto: `flock /tmp/pm-cargo-window.lock
  ./scripts/test-linux-concurrency-lab.sh`, rc1,
  `/tmp/pmw4-concurrency-red.log`. Setup/discovery inicial/TUI desbloqueada
  funcionan; el discovery con TUI abierta agota el límite original de 15 s.
* Primera ejecución posterior: `/tmp/pmw4-concurrency-green.log`, rc1.
  Discovery con TUI abierta y comprobaciones del pool pasan; falla el fixture
  al llamar `close_tui` desde Content en vez de su precondición Access. Se
  corrigió únicamente esa precondición del nuevo lab, sin cambiar el oráculo
  ni los plazos. La corrida no se considera GREEN.
* GREEN: `flock /tmp/pm-cargo-window.lock bash -c
  './scripts/cargo-local.sh fmt --all && ./scripts/test-linux-concurrency-lab.sh'`,
  rc0, `/tmp/pmw4-concurrency-green2.log`: TUI abierta, mismo PID, cuarto
  cliente válido con tres handshakes incompletos, quinto rechazado, admisión
  restituida y cleanup estricto verificado.

La política común `connection_dispatch::AgentConnections` admite hasta cuatro
handlers y rechaza inmediatamente exceso; no cola ni desplaza conexiones.
Spawn/panic del dispatcher son fallos fatales. La política heredada de errores
de cada handler permanece explícitamente conservada. Linux y Darwin usan el
mismo accept loop humano/agente; Windows mantiene sus dos carriles nativos y
usa el mismo pool para el agente. Windows conserva un acceptor durante el
relevo del pipe: cuatro workers y hasta dos handles transitorios de acceptor,
con idéntica DACL/SID; esos acceptores no ejecutan TLS/operaciones. La parada
SCM señala el evento y espera todos los workers propios, agregando errores.

### Requisito nativo del pool Windows

Al permitir instancias adicionales, el ACE heredado `GRGW` concede también
`FILE_CREATE_PIPE_INSTANCE` al cliente. [Microsoft documenta la equivalencia
con FILE_APPEND_DATA y recomienda derechos individuales](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
La DACL agente y `CreateFileW` del cliente deben usar explícitamente todos los
derechos de lectura/escritura requeridos salvo ese bit de creación de servidor.
Humano y sync conservan sus máscaras existentes. No se modifica una capacidad
delegada: crear un servidor impostor no es una operación de agente del contrato.

Antes de ejecutar CI se extiende la prueba nativa: primer pipe conserva
FIRST_PIPE_INSTANCE, otro primer propietario se rechaza, cinco instancias
adicionales del propietario confiable se admiten y una séptima se rechaza.
El helper de prueba representa al dueño confiable con GA y conserva el ACE
específico del cliente; se comprueba que la máscara del cliente no contiene
FILE_CREATE_PIPE_INSTANCE y mantiene los demás derechos read/write. El lab
real del servicio sigue probando discovery con token agente restringido y
los controles SCM/SID/RPK. La prueba de seis handles nativos no afirma seis
conexiones delegadas: el dispatcher mantiene su máximo de cuatro handlers.
Las aserciones nativas y guards anteriores permanecen intactos.

## Reanudación y checkpoint — 2026-10-03

Se reconstruyeron status, diff, archivos nuevos y logs sin descartar trabajo
previo. La rama continúa en la base `ee3c1fd` antes del primer checkpoint.
El RED previo llega al discovery con TUI abierta y falla por su timeout
original de 15 s; no es un error de compilación. Su GREEN previo se revalidó:

```text
flock /tmp/pm-cargo-window.lock bash -c \
  './scripts/cargo-local.sh test -p pm-custody connection_dispatch --locked --offline && ./scripts/test-linux-concurrency-lab.sh'
```

Resultado rc0, `/tmp/pmw4-resume-concurrency-green.log`: dos regresiones del
dispatcher pasan en lib y bin; proceso ordinario estable, TUI abierta,
concurrencia del mismo agente, exceso rechazado y cleanup comprobado.
Esto verifica compilación Linux y el correctivo enfocado; la barrida completa
y la ejecución nativa todavía no están acreditadas en este checkpoint.
El primer gate previo falló en un guard estático de FIRST_PIPE_INSTANCE; el
segundo quedó interrumpido durante tests. Ninguno se presenta como gate verde.

Multiagente conserva RED rc1 en `/tmp/pmw4-multiagent-red2.log`: A descubre,
B enrolado recibe `CUSTODY_UNAVAILABLE` contra ese mismo daemon/bootstrap.
La decisión sobre bindings confiables permanece pendiente; no se interpreta
`environment_binding=linux-lab` como UID/SID ni se amplía el listener.

### Revalidación independiente del RED previo

Sin sustituir archivos del worktree, se exporta `ee3c1fd` a una raíz propia
`/tmp/pmw4-red-source-*`. Desde el cwd W4 y dentro del mismo flock se construyen
pm-custody/pm-cli con `cargo-local.sh build --manifest-path ... --target-dir ...
--locked --offline`; después el lab W4 actual recibe esos dos binarios bajo
el mismo user/mount namespace, UIDs y límites del wrapper. La exportación solo
contiene fuentes versionadas; no instala dependencias ni modifica otra rama.
El RED válido debe completar setup/discovery/control humano y fallar en el
discovery con TUI abierta. Un error de build/setup no satisface el criterio.

## Decisiones necesarias antes de los correctivos 2–3

### 2. Binding nativo por agente

Verificado en `pm-vault/src/authorization.rs::AgentEnrollment::new`: solo
comprueba longitud de `environment_binding`; el evento humano firma ese texto
y `human.rs` lo persiste, pero no define un principal nativo. Unix y Windows
seleccionan respectivamente `bootstrap.agent_uid`/`agent_sid` y su SPKI único.
G1 exige principal confiable y G4 concesión vigente; ninguno permite inferir
UID/SID del texto libre ni aprenderlo de la primera conexión.

Opciones para decidir:

| Opción | Consecuencia |
| --- | --- |
| Registro local instalado y versionado RPK → principal nativo, ligado a bóveda/dispositivo | Conserva la concesión humana y su revocación como autoridad; el instalador provisiona el entorno y el daemon valida ambas fuentes. No cambia eventos sincronizados existentes. Requiere definir provisión/reload y migración explícita del bootstrap. **Recomendación.** |
| Binding nativo tipado en una nueva versión del enrolamiento firmado | Alta humana reúne concesión y vínculo en una transacción; exige representación por dispositivo, cambios de wire/evento/reductor y migración de etiquetas anteriores. Mayor superficie fuera del listener. |

En ambas: no adoptar etiquetas antiguas como identidad, no activar TOFU ni
permitir RPK nuevas solo por compartir UID/SID. La migración debe convertir
explícitamente el par bootstrap ya confiable, verificarlo y mantener la
continuidad de las instalaciones existentes; no elegir esa política sin el
usuario. Tras decidir: peer obtenido de TLS, admisión vigente antes de operar,
revocación caliente, aislamiento A/B y pool por identidad, con hook W3 previo
a admisión. El RED A/B ordinario ya existe; los labs 07/24 aún alternan bootstrap
y esa parte **no se declara corregida**.

### 3. Composición del proveedor ordinario

Verificado: `serve_vault` asigna `provider: None`; el worker y recover_inflight
se habilitan exclusivamente con Some. `ControlledProvider` contiene un único
socket/UID; el protocolo también se usa con pm-web-auth/pm-ssh-client reales
desde `serve-attempt-lab`. pm-web-auth instala un perfil cerrado por proceso;
P1/P2/P4/P5 y SSH necesitan endpoints/configuración propios. No existe registro
de producción ni política de selección/provisión del daemon ordinario.

| Opción | Consecuencia |
| --- | --- |
| Registro instalado de adaptadores reales por integración/perfil y binding nativo | Daemon usa worker/recuperación de 08, el adaptador mantiene su perfil privado y lifecycle externo. Config ausente/invalidada falla explícitamente; no deriva a lab. **Recomendación.** |
| Daemon posee y supervisa procesos de adaptador desde configuración instalada | Control directo de readiness/parada, pero amplía lifecycle, permisos y empaquetado; exige decisiones adicionales por plataforma. |

Antes de implementar deben fijarse schema/ubicación/owner de configuración,
selección por integración/perfil y provisión de los endpoints confiables.
Por el orden aprobado, el correctivo 3 queda pendiente tras el bloqueo del 2;
no hay RED/GREEN real contra serve-vault para el proveedor ni P4 actualizado.
Los PASS actuales de P1–P4 son regresión de los entrypoints existentes.

Fallbacks adicionales inspeccionados, conservados: pm-web-auth `provider::serve`
continúa tras accept/read fallidos e ignora write_frame fallido; `handle_github`
y `handle_browser` sustituyen fallos de parsing por respuesta pública 4;
`handle_exchange` sustituye reloj no convertible por respuesta 3 y agrupa
errores de proveedor. `browser::Browser::stop` ignora kill/wait/removal de
perfil, y sus diagnósticos de formulario sustituyen campos ausentes por
false/"?"/vacío. No se usan para afirmar cleanup seguro ni se corrigen aquí.

## CI nativa del checkpoint de concurrencia

Repositorio público y workflows manuales activos verificados por API;
[gratuidad de runners estándar públicos](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
y derechos individuales de [pipes Windows](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
revalidados en fuentes primarias. Inputs normales, sin cambios de workflow,
caches, artifacts o secrets. Ref de rama comprobado antes/después del dispatch;
ambos headSha corresponden a `e4a8f49e62f1081875e821ea53b1dbe83d6fc7cc`.

* [macOS 37123539350](https://github.com/SantanaJcp/passwordmanager/actions/runs/37123539350):
  pasteboard_diagnostic=false, final_phase_only=false; resultado pendiente.
* [Windows 37123541543](https://github.com/SantanaJcp/passwordmanager/actions/runs/37123541543):
  diagnostic_only=false, service_diagnostics=false, tui_conpty_red=true.
  FAIL de compilación E0282 en `windows.rs::serve_role`, antes del lab:
  el cierre Result necesita tipo explícito para agregar Failure::merge.
  Log `/tmp/pmw4-native-windows-concurrency.log`, metadata `.json` del mismo
  prefijo. No es RED conductual ni evidencia de ejecución del pool.

Se anota `Result<(), Failure>` en ese cierre, sin cambiar comportamiento,
errores, límites ni código Linux/macOS. Esa diferencia justifica una nueva
corrida Windows en otro SHA; no se repite macOS por un cambio cfg(windows).
