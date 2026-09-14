# Método CI nativo efímero

Estado: método adicional autorizado. La primera corrida falló en cinco targets;
la remediación autorizada se integró y la segunda corrida pasó los cinco
preflights nativos de entorno. **No es aceptación del producto**, no resuelve
26--32 ni sustituye laboratorios humanos, reboot/FDE o firma real.

## Alcance y fuente de verdad

Este método añade un laboratorio hospedado, nativo, efímero y de un solo boot
al método por procesos reales ya usado por el proyecto. Sirve primero para
comprobar el entorno y, cuando existan los ports y entrypoints de cada ticket,
para ejecutar la parte automatizable de su aceptación. Compilar para otra CPU
no es ejecutarla allí: WSL, Rosetta, QEMU, WoW64 y cross-compilation no cuentan
como evidencia nativa.

G1 exige Linux kernel 6.1/glibc 2.36/systemd 252 en x86-64 y AArch64, macOS 13+
en Intel y Apple silicon, y Windows 11 en x64 y ARM64. Los perfiles completos
están en [aislamiento](../design/isolation.md), los artefactos en
[distribución](../design/distribution.md) y los controles de crash/clipboard en
[operaciones de seguridad](../design/security-operations.md). La aceptación
por target sigue en los tickets
[26](../../.scratch/passwordmanager/issues/26-custodia-y-canal-humano-macos.md),
[27](../../.scratch/passwordmanager/issues/27-custodia-y-canal-humano-windows.md),
[28](../../.scratch/passwordmanager/issues/28-fallos-operativos-canarios-y-crash-safety-integral.md),
[29](../../.scratch/passwordmanager/issues/29-paquetes-tuf-mantenimiento-y-fuente-correspondiente.md),
[30](../../.scratch/passwordmanager/issues/30-evidencia-nativa-linux-en-dos-arquitecturas.md),
[31](../../.scratch/passwordmanager/issues/31-evidencia-nativa-macos-en-dos-arquitecturas.md)
y [32](../../.scratch/passwordmanager/issues/32-evidencia-nativa-windows-en-dos-arquitecturas.md).

GitHub documenta que los runners estándar son gratuitos e ilimitados en
repositorios públicos y que cada label salvo `ubuntu-slim` obtiene una VM nueva.
Linux/macOS tienen `sudo` sin contraseña y Windows se ejecuta como administrador
con UAC desactivado. Los límites actuales son 6 horas por job y, en GitHub Free,
20 jobs estándar concurrentes con máximo 5 macOS. No se usan larger runners,
cachés ni artefactos: larger siempre se cobra, y almacenamiento tiene cupos y
precio propios. Fuentes primarias:
[runners hospedados](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[límites](https://docs.github.com/en/actions/reference/limits),
[facturación](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
e [imágenes](https://github.com/actions/runner-images).

## Targets de preparación

El workflow manual
[`native-environment-preflight.yml`](../../.github/workflows/native-environment-preflight.yml)
usa exactamente estos cinco targets estándar:

| Target | Label fijado | Recursos estándar públicos | Mínimo G1 | Alcance |
| --- | --- | --- | --- | --- |
| Linux x86-64 | `ubuntu-24.04` | 4 CPU, 16 GB RAM, 14 GB SSD | Sí | Entorno solamente. |
| Linux AArch64 | `ubuntu-24.04-arm` | 4 CPU, 16 GB RAM, 14 GB SSD | Sí | Entorno solamente. |
| macOS Intel | `macos-15-intel` | 4 CPU, 14 GB RAM, 14 GB SSD | Sí | Entorno solamente; GitHub [anunció](https://github.com/actions/runner-images/issues/13045) fin de esta última imagen Intel para agosto de 2027. |
| macOS Apple silicon | `macos-15` | M1 3 CPU, 7 GB RAM, 14 GB SSD | Sí | Entorno solamente; sin nested virtualization ni UUID/UDID estático. |
| Windows 11 ARM64 | `windows-11-vs2026-arm` | 4 CPU, 16 GB RAM, 14 GB SSD | Sí | Entorno solamente; exige PowerShell y toolchain ARM64, no proceso emulado. |

Los labels fijan familia de OS y CPU, **no** `ImageVersion`; GitHub actualiza
las imágenes regularmente. Cada corrida debe conservar el commit, label,
`ImageOS`, `ImageVersion`, versión/build del OS, CPU y host Rust observados.
El workflow instala obligatoriamente `1.98.1-<host-nativo>` con perfil `minimal`
y `--no-self-update`, y el preflight exige Rust/Cargo 1.98.1 antes de compilar,
inspeccionar y ejecutar un binario mínimo de la arquitectura nativa.
`RUSTUP_AUTO_INSTALL=0` se fija globalmente antes de cualquier invocación de
Rustup: una selección ausente falla, nunca descarga otra versión implícitamente.
También comprueba privilegio administrativo,
gestor de servicios y herramientas nativas necesarias. Un preflight verde solo
significa que el entorno es candidato; no demuestra custodia, aislamiento,
crash-safety, empaquetado ni soporte.

Esta instalación de entorno usa los homes efímeros provistos por el runner. No
prepara ni acredita el build offline del producto: esa fase distinta seguirá
usando `scripts/cargo-local.sh` y los homes `<repo>/.toolchain` fijados por el
repositorio cuando exista el workflow de aceptación correspondiente.

Windows x64 queda fuera: los runners estándar x64 publicados son Windows Server
2022/2025, no el Windows 11 requerido por G1. El Windows 11 Desktop x64 de larger
runners es pagado y no está autorizado. No se ejecutará Windows Server como
sustituto. La imagen Windows ARM puede incluir herramientas x64; por eso no
basta `RUNNER_ARCH`: el host Rust, PowerShell y el PE producido tienen que ser
ARM64.

## Seguridad y coste de la preparación

- Único trigger: `workflow_dispatch`; no hay `push`, PR, schedule ni ejecución
  automática.
- `permissions: contents: read`; `actions/checkout` se fija al commit
  `3d3c42e5aac5ba805825da76410c181273ba90b1` de v7.0.1 y no persiste
  credenciales. Su `action.yml` declara `runs.using: node24`; se verificaron el
  tag y commit en el repositorio oficial de
  [`actions/checkout`](https://github.com/actions/checkout/releases/tag/v7.0.1)
  y el [manifiesto fijado](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml#L116).
- No hay secrets propios, credenciales/certificados de firma, datos reales,
  cache, artifact upload, publicación ni larger runner.
- No se imprime el entorno completo. Solo metadata de runner/OS/CPU/usuario,
  versiones de herramientas y el canario público `PM_NATIVE_CI_PROBE`.
- Un comando, versión, arquitectura o prerrequisito ausente termina el job en
  error. Fuera de la instalación obligatoria del toolchain exacto no se
  descarga una alternativa, no se cambia de label y no se acepta emulación.
- `fail-fast: false` permite observar los cinco resultados independientes; un
  fallo de cualquier instancia mantiene fallido el workflow completo y no se
  convierte en éxito.

## Método de ejecución y evidencia

Prerrequisito de plataforma: GitHub solo entrega `workflow_dispatch` cuando el
archivo del workflow existe en la rama por defecto. El repositorio usa
`master`. Publicar este archivo solo en una rama/PR no habilita el dispatch.
El paso de publicación autorizado debe colocar **este mismo archivo**, sin
triggers adicionales, en `master`; el ref elegido manualmente debe contener el
mismo workflow y sus dos scripts de preflight. Eso habilita seleccionar el ref
confiable sin fusionar el PR de producto ni cambiar protecciones. Esta exigencia está documentada en
[workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onworkflow_dispatch)
y [manual runs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

Secuencia después de satisfacer ese prerrequisito:

1. Seleccionar `Native environment preflight` mediante dispatch manual sobre el
   ref confiable y registrar el commit exacto que resuelva GitHub.
2. Confirmar cinco instancias, los cinco labels exactos y ausencia de larger
   runners.
3. Guardar URLs de workflow/job y los hechos emitidos por cada preflight. Logs y
   job summaries no se subirán como artifacts.
4. Exigir cinco conclusiones `PASS ... scope=environment-only
   product-validation=NOT_RUN`. Cualquier target fallido permanece fallido y
   se registra con su error exacto.
5. Registrar resultados observados en evidencia versionada separando entorno
   de producto. No convertir disponibilidad del runner en cierre de tickets.

Validación local previa a publicar:

```text
./scripts/verify-native-ci-config.sh
git diff --check
```

El primer comando valida trigger manual, permisos, cinco labels, SHA de checkout,
ausencia de secrets/cache/artifacts/larger/emulación y enlaces al método. La
sintaxis YAML se comprueba además con un parser local disponible, sin instalar
dependencias; esto no sustituye el parser de GitHub, que solo será observado
tras la integración en `master` y el dispatch autorizado.

## Futura aceptación de producto

No se crea ahora un workflow de aceptación porque los ports y entrypoints de
26/27 aún no existen. Cuando cada ticket entregue su laboratorio real y su
nombre quede documentado, el workflow de aceptación deberá:

1. comprobar que el entrypoint requerido existe y es ejecutable; si falta,
   terminar en error antes de anunciar ninguna prueba;
2. construir y ejecutar en el mismo target nativo, y comprobar arquitectura del
   artefacto/proceso antes de interpretar resultados;
3. instalar identidades reales separadas de custodio, humano y agente; el
   runner admin solo orquesta, y el proceso agente debe usar un token/UID no
   privilegiado real;
4. ejecutar servicio, canal/peer, permisos, negativas, crash/recovery y
   mantenimiento de un solo boot que el ticket defina, con canarios únicamente
   sintéticos;
5. fallar ante falta de puerto, herramienta, identidad restringida o resultado,
   sin skip, mock, inspección estática como sustituto ni cambio de plataforma.

Esta clase CI nunca contará como evidencia de `install -> reboot FDE`, TTY
humano auténtico, Ghostty/Terminal.app/Windows Terminal, clipboard humano
completo, firma/notarización/Authenticode real o Windows 11 x64. Esas pruebas
siguen requiriendo laboratorios nativos distintos; su ausencia mantiene los
tickets abiertos.

Limitación conocida a comprobar antes de pruebas multi-UID Linux: una
[incidencia abierta de runner-images](https://github.com/actions/runner-images/issues/14649)
documenta `XDG_RUNTIME_DIR` global apuntando al UID de `runner` en Ubuntu 24.04
x64/ARM64. Si afecta una sesión requerida, la prueba falla y el entorno queda
no apto; este método no corrige la imagen ni sustituye la sesión real.


## Primera ejecución observada — 2026-09-13

Preparación integrada en `cb023233c5680bb20854a610ffc602801c1c8ff4`, con
`check.sh`, validación YAML/config/bash, clean offline y 17 labs Linux verdes.
La sintaxis/ejecución real de PowerShell no se había validado localmente.
El bootstrap `78d5f0f` publicó exclusivamente el workflow y sus dos scripts en
`master`, sin fusionar el PR de producto. El workflow se despachó manualmente
sobre la rama unificada, no sobre otro commit de aplicación.

[Run 34761618195](https://github.com/SantanaJcp/passwordmanager/actions/runs/34761618195)
terminó con **failure** en los cinco jobs. No hubo canario nativo final PASS ni
pruebas de producto. Se observaron estos fallos, que no se descartan como una
corrida de éxito:

| Target | Resultado observado |
| --- | --- |
| Linux x86-64 | Ubuntu 24.04, kernel 6.17.0-1022-azure, glibc 2.39, systemd 255; el script termina por toolchain `1.98.1-x86_64-unknown-linux-gnu` no listado como previamente instalado. |
| Linux AArch64 | Misma familia/versiones Linux; termina por toolchain `1.98.1-aarch64-unknown-linux-gnu` no listado como previamente instalado. |
| macOS Intel | macOS 15.7.9, kernel 24.6.0; termina por toolchain `1.98.1-x86_64-apple-darwin` no listado como previamente instalado. |
| macOS Apple silicon | macOS 15.7.9, kernel 24.6.0; termina por toolchain `1.98.1-aarch64-apple-darwin` no listado como previamente instalado. |
| Windows ARM64 | La comprobación previa de OS y PowerShell ARM64 pasó; el script falla en línea 35 porque la propiedad `Count` no existe en el resultado de la consulta de toolchains. |

Los logs también muestran que la llamada Rustup disparó sincronización y
descarga automática de componentes, pese a la intención del preflight de no
instalar. Además, GitHub avisó que `actions/checkout@v4.4.0`, declarado para
Node 20, fue ejecutado forzosamente con Node 24. Son comportamientos implícitos
observados, no cambios que este documento presente como aprobados o correctos.

Se informó al usuario y se solicitó autorización para una preparación explícita
del toolchain exacto, bloquear las descargas implícitas, corregir la cardinalidad
de PowerShell y usar una versión fijada de checkout que declare Node 24
nativamente. No repetir el mismo workflow ni contabilizar entornos aptos hasta
corregir y verificar estos puntos. Esta solicitud de CI no sustituye la
aprobación independiente pendiente del fallback de la TUI 23.

## Remediación autorizada después de la primera ejecución

El usuario autorizó explícitamente, el 2026-09-13, estas correcciones acotadas:

1. instalar en cada job solamente `1.98.1-<host-nativo>` mediante
   `rustup toolchain install`, perfil `minimal` y `--no-self-update`, como etapa
   obligatoria y visible;
2. fijar `RUSTUP_AUTO_INSTALL=0` a nivel del workflow antes de cualquier llamada
   a Rustup, de modo que la selección/verificación no pueda instalar una
   versión ausente como comportamiento implícito;
3. materializar las salidas PowerShell en arrays con `@(...)` antes de consultar
   `Count`, evitando el fallo de StrictMode para cero o un resultado;
4. sustituir checkout v4 por el commit exacto
   `3d3c42e5aac5ba805825da76410c181273ba90b1` de v7.0.1, cuyo manifiesto
   oficial declara Node 24.

No se autorizó caché, artifacts, secrets, larger runners, una versión Rust
alternativa, gasto, validación de producto ni el fallback pendiente de TUI 23.
El checker local requiere las dos instalaciones exactas (una etapa matricial
Unix y una Windows), la variable global, el SHA/Node correctos y la conversión
PowerShell segura; conserva las prohibiciones de instalaciones dentro de los
scripts de verificación, sustituciones de éxito, emulación y acciones no
fijadas. La remediación aún requiere integración/publicación separada y una
nueva corrida manual; no convierte el run fallido anterior en evidencia verde.

La comprobación se cambió primero y se ejecutó contra el workflow anterior:

```text
./scripts/verify-native-ci-config.sh
# RED exit 1: native preflight has an unexpected action reference
# (mostró las dos referencias checkout v4.4.0 anteriores)
```

Después de aplicar solamente la remediación autorizada:

```text
./scripts/verify-native-ci-config.sh
sh -n scripts/ci/native-preflight-unix.sh scripts/verify-native-ci-config.sh
git diff --check
# GREEN: exit 0
```

PyYAML 6.0.3, ya disponible localmente, también cargó el workflow y comprobó
dos jobs, cinco targets y `RUSTUP_AUTO_INSTALL=0`; no se instaló nada para esa
comprobación. No hay `pwsh` en el host Linux actual, por lo que no se inventa
una ejecución PowerShell local: su sintaxis y comportamiento corregido deben
observarse en la nueva corrida Windows ARM64. El tag v7.0.1 se resolvió en el
remoto oficial al SHA fijado y su `action.yml` observado declara
`runs.using: node24`.

## Segunda ejecución observada — 2026-09-13

[Run 34763094631](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763094631)
ejecutó `ef81db72e8c2f6aec20511f14fa59a16bdfe3446` y terminó **success 5/5**.
El merger separado verificó config/YAML/shell, `check.sh`, clean offline y los
17 labs Linux antes de publicar. El bootstrap mínimo de tres archivos quedó
en `master` como `a583678`; el PR de producto no fue fusionado.

| Target | Job | OS e imagen observados | Resultado |
| --- | --- | --- | --- |
| Linux x86-64 | [103739225302](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763094631/job/103739225302) | Ubuntu 24.04, kernel 6.17.0-1022-azure, glibc 2.39, systemd 255; ubuntu24 20260907.300.1 | PASS |
| Linux AArch64 | [103739225310](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763094631/job/103739225310) | Mismas versiones base Linux; ubuntu24-arm64 20260907.118.1 | PASS |
| macOS Intel | [103739225256](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763094631/job/103739225256) | macOS 15.7.9, kernel 24.6.0; macos15 20260824.0482.1 | PASS |
| macOS Apple silicon | [103739225318](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763094631/job/103739225318) | macOS 15.7.9, kernel 24.6.0; macos15 20260907.0337.1 | PASS |
| Windows ARM64 | [103739225200](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763094631/job/103739225200) | Windows 11 Enterprise 10.0.26200; win11-vs2026-arm64 20260907.151.1 | PASS |

Cada job instaló Rust/Cargo 1.98.1 explícitamente, comprobó el host exacto,
compiló/inspeccionó/ejecutó el canario de su CPU y emitió
`scope=environment-only product-validation=NOT_RUN`. Las descargas registradas
pertenecen a la etapa explícita de instalación; no se observaron descargas en
la etapa de verificación ni sustitución Node 20 -> 24. PowerShell real ejecutó
la consulta de arrays sin el error `Count` anterior.

Windows reportó `uac_enable_lua=1`, aunque la documentación genérica hospedada
mencionada arriba describe UAC desactivado. Prima el hecho observado: el token
pasó la comprobación administrativa, pero ningún laboratorio debe asumir UAC
desactivado. No se ejecutó custodia, clipboard de producto, reboot/FDE ni
firma; los gates nativos y Windows 11 x64 continúan pendientes.

## Laboratorio macOS de candidato — evidencia parcial

El workflow manual `macOS custody acceptance` se habilitó mediante bootstrap
`c4e8779` en `master`; el código de producto se publicó únicamente en
`codex/pm-26`, sin integrarlo en la rama unificada ni fusionar el PR.

| Corrida | Commit candidato | Resultado observado |
| --- | --- | --- |
| [34763192705](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763192705) | `3409f5b` | Falló compilación de 1PUX en ambas CPU por anchuras distintas de tipos Darwin. |
| [34763755579](https://github.com/SantanaJcp/passwordmanager/actions/runs/34763755579) | `7f63429` | 1PUX compiló; falló el canal ancillary por campos Darwin `u32` frente a `usize`. |
| [34764564812](https://github.com/SantanaJcp/passwordmanager/actions/runs/34764564812) | `45af206` | Ambas CPU compilaron y ejecutaron nueve tests nativos; binarios Mach-O correctos. Falló la preparación multi-UID: raíz temporal privada del runner impedía `keygen` del agente. |
| [34765246514](https://github.com/SantanaJcp/passwordmanager/actions/runs/34765246514) | `8b54d20` | Ambas CPU compilaron. ARM rechazó explícitamente el prerrequisito de traversal de `/Users/runner/work/_temp` para el custodio; no se modificaron permisos ajenos. Intel llegó a launchd y falló el primer probe del agente con `CUSTODY_UNAVAILABLE`; causa aún no aislada. |

Los nueve tests por CPU no representan toda la suite: varios tests conservan
`cfg` Linux y ejecutaron cero casos. Ninguna corrida pasó la aceptación de
custodia completa; no acreditan TUI compuesta, reboot/FDE, firma ni los gates
26/31. Los ajustes de anchuras y preparación siguen en el candidato aislado.
Después de esta evidencia, el usuario autorizó una raíz efímera única
`/private/var/tmp/passwordmanager-ticket26`, con padre root `01777`, colisiones
rechazadas, raíz propia `0711` y privados `0700`, sin fallback ni cambios en
homes ajenos. El candidato `aa19385` documenta y aplica ese método; su corrida
[34795572781](https://github.com/SantanaJcp/passwordmanager/actions/runs/34795572781)
falló en el guard de modo del padre: `%Lp` de BSD stat descarta el sticky bit. La autorización consta en
[execution.md](../../.scratch/passwordmanager/execution.md).


### Continuación macOS — 2026-09-13

- [Corrida6, 34796307975](https://github.com/SantanaJcp/passwordmanager/actions/runs/34796307975), candidato `f6be582`: el modo se lee completo con `%p` y `stat.S_IMODE`; metadata, traversal entre UIDs y UID de launchd pasan. Sigue fallando el primer probe en ambas CPU.
- [Corrida7, 34797022111](https://github.com/SantanaJcp/passwordmanager/actions/runs/34797022111), candidato `678319b`: diagnóstico limitado a feature `macos-ticket26-diagnostics`, apagada por defecto y con opt-in del fixture. Perfil/clave/conexión/peer y configuración TLS pasan; la primera I/O posterior falla. Nueve tests nativos por CPU no sustituyen aceptación integral.
- Hipótesis concreta: Darwin hereda el modo nonblocking del listener al socket aceptado, mientras el camino rustls usa I/O blocking. [Apple accept(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/accept.2.html) y [Linux accept(2)](https://man7.org/linux/man-pages/man2/accept.2.html) documentan la diferencia. Se prepara normalización explícita y regresión, sin cambiar políticas TLS ni plazos. No se considera causa confirmada hasta nueva evidencia nativa. La aceptación deberá repetirse con binario normal, no solo diagnóstico.

### Windows ARM64 — evidencia parcial, 2026-09-13

El bootstrap de workflow manual quedó en `master` como `5f099f8`, sin fusionar el producto. El candidato continúa aislado en `codex/pm-27`.

- [Corrida1, 34796411705](https://github.com/SantanaJcp/passwordmanager/actions/runs/34796411705), `1f9a383`: la conversión de finales de línea del checkout cambió la firma; hash falló antes de compilar. `9b32e58` fija `-text` para los dos inputs, sin cambiar hashes ni normalizar como alternativa.
- [Corrida2, 34796755222](https://github.com/SantanaJcp/passwordmanager/actions/runs/34796755222), `9b32e58`: hashes/Minisign pasan; falló el nombre supuesto del metadata MSVC. `f45ce78` usa el archivo estándar `Microsoft.VCToolsVersion.default.txt`, exige 14.5x y fija la versión efectiva.
- [Corrida3, 34797085446](https://github.com/SantanaJcp/passwordmanager/actions/runs/34797085446), `f45ce78`: fuente 1.0.22 autenticada, compilación nativa ReleaseLIB ARM64 `/MT` con v145/14.51.36231, inspección ARM64 y test de versión enlazada PASS. La custodia no arrancó por conversión PowerShell array a booleano en guard administrativo.
- [Corrida4, 34797595176](https://github.com/SantanaJcp/passwordmanager/actions/runs/34797595176), `49ec89ad`: guard `WindowsPrincipal.IsInRole` PASS; etapa MSVC PASS otra vez; DPAPI y ConPTY pasan (2 tests). `clipboard_sequence_never_clears_a_newer_owner` falla en `second.clear_if_owned()` (2/3 tests). No se ejecutó aún la custodia completa; el diagnóstico del clipboard continúa sin relajar ownership ni omitir la aserción.

Nada de esta evidencia cierra 26/27 ni los gates integrales 30–34. Los fallos previos se conservan; no se presenta solo la última corrida como validación global.


### Nuevos discriminantes nativos — 2026-09-13

- macOS [corrida8, 34798902550](https://github.com/SantanaJcp/passwordmanager/actions/runs/34798902550), `87dc908`: ambas CPU observaron socket aceptado `nonblocking-before=1` y `after=0`; el cliente llegó a READY y servidor a request/ALPN/READY. Esto confirma la causa del fallo anterior y la corrección del modo de I/O. El lab no pasó completo: la negativa de servidor impostor agotó cinco segundos esperando `accept`. Se investiga el fixture sin convertir timeout en éxito; sigue pendiente aceptación normal sin diagnóstico.
- Windows [corrida5, 34798532966](https://github.com/SantanaJcp/passwordmanager/actions/runs/34798532966), `40b8ec9`: diagnóstico test-only confirmó que la secuencia guardada antes de CloseClipboard quedaba obsoleta (2→5 y7→10), con owner HWND nulo. No se cambió comportamiento en esa corrida.
- Windows [corrida6, 34799143030](https://github.com/SantanaJcp/passwordmanager/actions/runs/34799143030), `7829c12`: HWND propio por lease y captura final verificada con owner bajo lock corrigen la regresión original, que pasa; DPAPI/ConPTY también pasan. La nueva negativa de pérdida entre publicación/captura falla al crear el escritor concurrente (3/4 tests). Se investiga interferencia entre casos que comparten clipboard, preservando la carrera intencional dentro de la prueba. Ninguna corrida acredita custodia completa.


### Estado al continuar24/25 — 2026-09-13

- Windows [corrida7, 34799533393](https://github.com/SantanaJcp/passwordmanager/actions/runs/34799533393), `6bef3bc`: 4/4 unit tests nativos (dos clipboard, DPAPI y ConPTY) y contrato de pipes PASS. Mutex exclusivamente test-only separa los dos casos que comparten clipboard y conserva la carrera interna. El build siguiente falla en19 errores de portabilidad de archivos en `pm-vault` (`onepux.rs`/`reducer.rs`), actualmente dependientes de APIs Unix. Se prepara equivalencia Windows sin desactivar importación/reductor ni sustituir garantías.
- macOS [corrida9, 34799626677](https://github.com/SantanaJcp/passwordmanager/actions/runs/34799626677), `249cbd8`: el fixture impostor ahora permite conexión real para comprobar rechazo por UID antes de TLS y cero bytes. Intel termina el lab diagnóstico: launchd, peer/RPK, ACL, suspensión/restart, TTY/AppKit. ARM termina tests/probe pero falla `human-authorization --action setup` con exit4; causa pendiente.
- Limitación detectada del harness Mac: `finally` usa `check=False` en limpieza y anuncia PASS antes de ella. Esto no demuestra que la limpieza haya fallado, pero tampoco propaga un error si sucede. Root informó al usuario y solicitó autorización explícita para hacerlo visible preservando recursos propios; pendiente de respuesta, comportamiento no cambiado. El resultado Intel no acredita por sí solo limpieza satisfactoria, binario normal, TUI compuesta, reboot/FDE o firma.


Windows [corrida8, 34802741744](https://github.com/SantanaJcp/passwordmanager/actions/runs/34802741744), candidato `6434449`: el seam de archivos nativo elimina los19errores; `pm-vault`, `pm-custody` y `pm` compilan en ARM64. Permanecen verdes4unit tests y contrato de pipes. El lab falla ahora al crear servicio, `SC CreateService1057`, antes de arrancar custodia. El harness suministra password vacío a una cuenta virtual, mientras [CreateService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea) exige NULL para ese tipo de cuenta. Además apareció LNK4098 por conflicto de CRT; no se suprimirá el warning sin alinear runtimes y verificar el binario. Estos dos hallazgos siguen pendientes; compilar no equivale a aceptar servicio/TUI/aislamiento.

### Continuación nativa — 2026-09-14

- Windows [corrida9, 34804746619](https://github.com/SantanaJcp/passwordmanager/actions/runs/34804746619), `8e22acd`: alta SCM y configuración de SID del servicio PASS al omitir el argumento de password de la cuenta virtual. Build sin LNK4098 observado tras alinear CRT estático de Rust/C. El nuevo bloqueo es de preparación del fixture: sella ACL a SYSTEM y al rol antes de generar claves/bóveda, impidiendo el acceso posterior del instalador; falla explícitamente con AccessDenied. Se corrige el orden de aprovisionamiento manteniendo privacidad desde creación y sellado antes del arranque. La inspección PE/CRT automatizada del candidato `0cacb51` todavía no se ha ejecutado nativamente. No hay aceptación del servicio completo.
- macOS [corrida10, 34804041166](https://github.com/SantanaJcp/passwordmanager/actions/runs/34804041166), `cf71815`: Intel vuelve a pasar el laboratorio diagnóstico. ARM alcanza `server-human-unlock-frame` y falla en `client-human-unlock`. Esto acota la fase, no demuestra timeout, fallo de contraseña ni insuficiencia de CPU. Se mantienen los plazos y parámetros criptográficos. Continúan pendientes diagnóstico causal, limpieza verificable, binario normal y composición TUI.
