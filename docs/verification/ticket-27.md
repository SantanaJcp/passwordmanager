# Ticket 27 — composición Windows pendiente de ejecución nativa

Fecha: 2026-09-13. Estado: **implementación sin acreditar, no candidato
aceptado**. Este documento no acredita Windows ni resuelve el ticket. No se
ejecutó Windows, no se instaló servicio y no se modificó el host Linux.

## Método del checkpoint `pm-vault` Windows (escrito antes de implementar)

La corrida nativa `34799533393` dejó el canal/laboratorio Windows anterior en
verde y falló al compilar `pm-vault` con 19 usos de APIs Unix en
`crates/pm-vault/src/onepux.rs` y `crates/pm-vault/src/reducer.rs`. Este
checkpoint se limita a esos seams de filesystem; no cambia el motor, la TUI,
libsodium ni los contratos G7. Antes de modificar código se fija el siguiente
método:

1. El comportamiento Unix existente se conserva: apertura sin seguir enlaces,
   descriptor no heredable, rechazo de enlaces duros, identidad estable,
   preflight de capacidad, staging privado y publicación atómica. En Windows
   cada requisito se implementa mediante su API nativa, no mediante `cfg` que
   retire la validación, `Unavailable`, un stub o una ruta alternativa.
2. La apertura Windows usa un handle con `FILE_FLAG_OPEN_REPARSE_POINT` y
   rechaza el atributo de reparse observado en ese handle. La identidad y el
   conteo de enlaces se obtienen con `GetFileInformationByHandle`: volumen más
   índice de archivo y `nNumberOfLinks`, respectivamente. La capacidad usa
   `GetDiskFreeSpaceExW` y la ruta UTF-16 terminada en NUL. Los modos ZIP son
   constantes del formato POSIX con tipo `u32`, no constantes `libc` cuyo tipo
   cambia por plataforma. La persistencia continúa usando el hard-link
   atómico común y deberá probarse de nuevo en Windows; no se sustituye por
   copia ni por renombrado. La creación de cada stage usa `CreateFileW` con un
   descriptor de seguridad explícito para que su DACL privada se aplique en la
   misma operación que `CREATE_NEW`, sin una ventana intermedia de permisos
   heredados. `FILE_FLAG_OPEN_REPARSE_POINT` protege el
   componente final; el método conserva como precondición el directorio padre
   privado y su DACL/propietario confiables del contrato G7, y no presenta el
   flag como una validación de todos los ancestros.
3. La regresión se escribe y ejecuta primero en Linux contra los seams públicos
   existentes (lector 1PUX, staging de reductor y publicación), con archivos y
   bytes sintéticos. Se comprueba que una fuente normal se identifica y se
   relee, que un hard-link no pasa, que el lector rechaza una entrada ZIP con
   tipo no regular/directorio, que el preflight conserva sus límites y que el
   export/reduce no acepta un stage que cambió o es un enlace. Después se
   ejecutan `check.sh`, el lab 1PUX y los labs Linux de sync/reducer. La
   ejecución Windows ARM64/x64 posterior debe compilar el mismo código y
   repetir esas negativas con reparse points y hard-links reales, además de
   persistencia por reinicio; la falta del target Windows en este host no se
   suplirá con `RUSTFLAGS`, cross-compilation ni mocks.
4. Cualquier fallo de API nativa, metadato ausente, ACL/integridad, capacidad,
   hard-link o cleanup conserva el estado fallido y detiene la prueba. No se
   amplían plazos, no se silencian errores y no se declara evidencia Windows a
   partir de los checks Linux.

Este método es la evidencia de alcance y no una aceptación del ticket: la
corrida Windows nativa, incluida la compilación del producto y las pruebas de
custodia, sigue pendiente.

## Método nativo que deberá ejecutarse

Este método extiende el [método CI nativo autorizado](native-ci.md). El futuro
entrypoint será `scripts/test-windows-custody-lab.ps1` y deberá fallar antes de
probar producto salvo que observe Windows 11 nativo, proceso/PE de la CPU del
job y Rust 1.98.1. No acepta Windows Server, WoW64, WSL, emulación, mocks ni
cross-compilation como evidencia.

La protección de fixtures forma parte del método antes de cualquier ejecución:
el workflow debe pasar el flag explícito `-EphemeralCI` y el lab exige además
las señales `GITHUB_ACTIONS=true` y `CI=true` del entorno efímero autorizado.
Comprueba que no existan ya el servicio, las cuentas sintéticas ni la raíz
descartable antes de crear nada. Registra propiedad solo después de cada
creación exitosa y el cleanup elimina exclusivamente esos recursos propios.
Cualquier fallo de cleanup mantiene el job en error y no se imprime `PASS`
antes de terminarlo.

El workflow manual preparado es
`.github/workflows/ticket-27-windows.yml`. Instala Rust 1.98.1 ARM64 en los
homes `.toolchain` del repositorio, ejecuta el preflight aprobado, hace
`cargo fetch --locked`, prepara libsodium desde la fuente autenticada y solo
entonces entra al lab con builds `--offline`. No se ha publicado ni despachado
desde este worktree.

La preparación autorizada es un único camino explícito:

1. `scripts/prepare-windows-libsodium.ps1 -EphemeralCI` acepta únicamente el
   runner Windows 11 ARM64 nativo ya validado y el tarball comprometido
   `third_party/libsodium/LATEST.tar.gz`; comprueba los SHA-256 fijados del
   archivo y su `.minisig`, y ejecuta el verificador Rust mínimo con
   `minisign-verify 0.2.5` y la clave pública upstream fijada. Resuelve Cargo
   únicamente con `rustup which --toolchain` para el toolchain exacto ya
   instalado, exige su ruta bajo `RUSTUP_HOME` y comprueba que su PE sea ARM64;
   no supone que `cargo.exe` exista en `CARGO_HOME/bin`.
2. Extrae a una raíz nueva bajo `RUNNER_TEMP` con guardia de colisión y exige
   `libsodium 1.0.22`, el proyecto
   `builds/msvc/vs2026/libsodium/libsodium.vcxproj`, toolset `v145`,
   configuración `ReleaseLIB|ARM64` y runtime estático `/MT`.
3. Resuelve una única instalación Visual Studio 2026 `[18.0,19.0)` mediante el
   `vswhere.exe` fijo del instalador. Enumera como diagnóstico únicamente los
   nombres de metadata `Microsoft.VCToolsVersion*.txt`, y lee el archivo
   estándar `Microsoft.VCToolsVersion.default.txt` documentado por Microsoft;
   exige que su versión sea v145 y la fija también como `VCToolsVersion` de
   MSBuild. Después exige los ejecutables ARM64-host/ARM64-target de MSBuild y
   Dumpbin bajo esa versión. La ausencia o ambigüedad de cualquier prerrequisito
   falla; no busca otra versión, host o herramienta. Referencias primarias:
   [Microsoft Learn](https://learn.microsoft.com/en-us/cpp/overview/acquire-msvc)
   y [vswhere Find VC](https://github.com/microsoft/vswhere/wiki/Find-VC).
4. Compila `ReleaseLIB|ARM64`, exige exactamente `libsodium.lib` en el output
   esperado, verifica con Dumpbin que sus objetos son ARM64 y publica solo ese
   directorio mediante `SODIUM_LIB_DIR`. El lab vuelve a exigir el directorio,
   el archivo y que no estén presentes `SODIUM_SHARED`,
   `SODIUM_USE_PKG_CONFIG` ni `SODIUM_DIST_DIR` antes de invocar Cargo.

Así `libsodium-sys-stable` toma la biblioteca estática fuente-verificada por su
frontera explícita y no puede alcanzar su fallback MSVC de ZIP precompilado.
No se acepta una biblioteca del ambiente, cache, artefacto descargado ni otra
CPU. La inspección de versión/proyecto ocurre antes del build y el test
`linked_version` confirma `1.0.22` después de enlazar el resultado preparado.

En Windows 11 ARM64 hospedado y Windows 11 x64 aún no disponible, el laboratorio
debe crear mediante SCM el servicio own-process automático
`PasswordManager` bajo `NT SERVICE\PasswordManager`, identidades restringidas
human/agent separadas y un volumen/directorio descartable. Debe comprobar:

1. DACL protegida de ambos pipes, bootstrap DPAPI y datos; ningún ACE de
   Everyone/Users/agent y primera instancia local exclusiva.
2. SID cliente obtenido por impersonación de nivel identificación y revert
   inmediato; PID servidor obtenido de SCM, PID bilateral del pipe y RPK TLS
   fijada. SID/PID/RPK sustituidos o pipe remoto fallan antes del motor.
3. El mismo `pm-vault` persistente y canales humano/delegado: agente no puede
   invocar humano, leer bootstrap/bóveda/config, cambiar DACL/servicio/binario,
   abrir proceso custodio ni heredar handles. No se concede admin/SeDebug al
   proceso agente.
4. DPAPI machine roundtrip solo tras comprobar DACL; blob copiado a agente no
   es legible. Ausencia/corrupción/reparse point/LocalDumps incompatible deja
   custodia no disponible, sin otra clave/backend.
5. Windows Terminal/ConPTY real a 80x24, Unicode/control-sequence/resize y
   secretos sin eco; `OpenClipboard`/`CF_UNICODETEXT`, timeout 30 s y carrera
   sequence-number no borran una selección posterior. Sin OSC52.
6. Persistencia tras restart de proceso. Reboot con FDE, TTY humana completa,
   firma/instalador y ambos CPU siguen en tickets 32/34 y no pueden inferirse
   de un job de un boot.

Éxito requiere logs `PASS` por cada punto sin canarios en stdout/stderr/files no
custodios. Cualquier requisito ausente termina el script con error, no `skip`.
Root deberá integrar primero el workflow autorizado y publicar el entrypoint;
este worktree no ejecuta jobs ni writes externos.

## TDD y resultado local

Se observó RED en el seam público antes de implementar:

```text
./scripts/cargo-local.sh test -p pm-native-channel --test windows_contract --locked --offline
# error E0432: WindowsEndpoint/windows_pipe_sddl no existían

# Comprobación estática enfocada del harness, antes del hardening
# FAIL explicit ephemeral flag; workflow flag; correct CLI binary;
# ownership tracking; visible cleanup; PASS after cleanup (exit 1)
```

La implementación local añade al canal nativo, sin segundo ledger:

- nombres separados agent/human y SDDL protegida solo SYSTEM, service SID y el
  SID de cuenta configurado;
- pipe local first-instance, identificación de SID mediante impersonación y
  PID bilateral, y cliente que obtiene el PID esperado desde SCM;
- DPAPI machine-scope explícito (sin tratarlo como frontera sin DACL);
- `OwnedClipboard` con `CF_UNICODETEXT` y limpieza condicionada al sequence;
- `ConPty` nativo con resize; tests Windows futuros para DPAPI, clipboard race y
  pseudoconsola.

Después del checkpoint inicial se compuso `pm-custody` con SCM como servicio
own-process bajo `NT SERVICE\PasswordManager`, los dos pipes, TLS 1.3/RPK/ALPN,
DPAPI para claves/bootstrap/custodia de auditoría, desbloqueo y cierre humano y
el motor wire delegado. El motor delegado se extrajo a `agent_wire.rs` y lo
usan Linux y Windows; Windows no mantiene una copia divergente ni un segundo
ledger. `scripts/test-windows-custody-lab.ps1` prepara cuentas locales
restringidas sintéticas, DACL, servicio virtual, vault real, sustitución
negativa y restart. Nada de esto cuenta como evidencia hasta ejecutarlo en el
runner Windows 11 ARM64 autorizado.

Comprobaciones locales, que **no sustituyen ejecución Windows**:

```text
./scripts/verify-windows-libsodium-build.sh
# RED antes del script de preparación: required Windows source-build file is absent; exit 1
# PASS tras conectar fetch -> fuente autenticada -> lab offline; exit 0
# RED posterior al exigir rustup-which y cardinalidad segura: contrato ausente; exit 1
# PASS tras fijar la ruta de Cargo y materializar ambos Select-String con @(...); exit 0
# RED tras exigir checkout byte-estable: .gitattributes ausente; exit 1
# PASS con ambos inputs autenticados -text y git check-attr text=unset; exit 0

./scripts/cargo-local.sh run -p pm-build-input-verifier --locked --offline -- \
  third_party/libsodium/LATEST.tar.gz third_party/libsodium/LATEST.tar.gz.minisig
# PASS libsodium-source minisign=verified key=upstream-fixed; exit 0

# La misma firma contra una copia con un byte alterado
# Error: InvalidSignature; exit 1

./scripts/cargo-local.sh test -p pm-native-channel --all-targets --locked --offline
# 1 passed; exit 0 (contrato puro SDDL/nombres)

RUSTFLAGS='--cfg target_os="windows" -Aexplicit_builtin_cfgs_in_flags' \
  ./scripts/cargo-local.sh clippy -p pm-native-channel --all-targets --locked --offline -- -D warnings
# exit 0; chequeo sintáctico cfg únicamente, no target ni runtime Windows

# Comprobación estática enfocada tras el hardening
# PASS: guard CI, workflow flag, target/debug/pm.exe, colisiones previas,
# ownership por recurso, cleanup visible y PASS posterior (exit 0)

git diff --check && ./scripts/check.sh
# exit 0, incluida la nueva herramienta de verificación y el workspace vigente
```

El host Linux no dispone de `pwsh`; solo se comprobó balance de delimitadores
de ambos scripts PowerShell, además de los chequeos estáticos anteriores. La
sintaxis PowerShell real, MSBuild/`ReleaseLIB|ARM64`, Dumpbin y el comportamiento
de cleanup continúan pendientes de la ejecución Windows nativa, sin inferirse
del chequeo Linux.

## Corrección acotada de SCM y método TDD (escrito antes de implementar)

La octava ejecución nativa del producto,
[run 34802741744](https://github.com/SantanaJcp/passwordmanager/actions/runs/34802741744),
compiló `pm-vault`, `pm-custody` y `pm` en ARM64, pasó los cuatro tests del
canal y el test de producto disponible, y después falló al crear el servicio
antes de crear fixtures. `sc.exe` recibió el token `password=` con un valor
vacío junto con la cuenta virtual `NT SERVICE\PasswordManager`, y SCM devolvió
1057. La documentación de
[CreateServiceA](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
exige `lpPassword = NULL` para cuentas virtuales; una cadena vacía no satisface
ese contrato.

El seam público de esta corrección es el argv de la única invocación
`sc.exe create` del laboratorio. Antes de tocarla se añadió al checker
`verify-windows-libsodium-build.sh` una regresión que conserva el nombre de la
cuenta virtual y rechaza cualquier `password=` en esa invocación. La regresión
dio RED contra el candidato congelado porque aún contenía `'password=', ''`.
La implementación mínima elimina solo ese token: la omisión es la forma en que
`sc.exe` entrega `NULL` a `lpPassword`; no cambia la cuenta virtual, el tipo o
inicio del servicio, las guardias de colisión, el registro de propiedad ni el
cleanup. No se introduce cuenta `LocalSystem`, fallback, retry o timeout.

La comprobación local posterior debe repetir el checker, `git diff --check`,
`./scripts/check.sh` y el laboratorio Linux de custodia que ya cubre recursos,
ownership, colisiones y cleanup. El host Linux no tiene `pwsh`, por lo que no se
simula parsing PowerShell. Solo una corrida Windows nativa puede demostrar que
SCM acepta la cuenta virtual y que el resto del laboratorio continúa; el ticket
permanece sin aceptar.

## Corrección acotada del CRT y método TDD (escrito antes de implementar)

La misma corrida `34802741744` terminó el build Rust con el warning del linker
`LNK4098: defaultlib 'LIBCMT' conflicts with use of other libs`. El proyecto
libsodium fuente ya había demostrado `ReleaseLIB|ARM64` con runtime C estático
`/MT`, por lo que el warning es un conflicto de runtimes y no debe ocultarse
con `/NODEFAULTLIB`. El seam de esta corrección es la selección del runtime C
del compilador Rust para los targets Windows MSVC; el checker exige una entrada
target-specific para ARM64 y x64 con `-C target-feature=+crt-static`, y rechaza
flags globales, `-crt-static` y cualquier supresión del linker. La regresión dio
RED antes de implementar porque `.cargo/config.toml` no contenía esas entradas.

La implementación mínima añade únicamente esas dos entradas target-specific.
Así Rust y los C compilados con `/MT` usan el runtime estático sin cambiar
libsodium, otro target, linker flags globales ni la advertencia en sí. La base
documental de Rust explica que `crt-static` selecciona el runtime C y que los
build scripts pueden observarlo mediante `CARGO_CFG_TARGET_FEATURE` en
[Linkage — Static and dynamic C runtimes](https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes).

La validación nativa posterior debe comprobar que ambos ejecutables se enlazan
sin `LNK4098` y revisar sus dependencias PE con `dumpbin /dependents` para que
no aparezca el runtime MSVC dinámico (`ucrtbase`, `vcruntime`/`msvcp` o
`api-ms-win-crt-*`); la salida no debe contener secretos ni convertirse en un
criterio de éxito por ausencia de logs. El host Linux no tiene target Windows,
MSVC ni `dumpbin`, así que no se simula esta comprobación: aquí solo se pueden
ejecutar el checker, `git diff --check`, `./scripts/check.sh` y los labs Linux
establecidos. Una corrida Windows nativa debe confirmar el binario real y el
resto del laboratorio; el ticket permanece sin aceptar.

## Inspección PE automatizada y método TDD (extensión escrita antes de implementar)

El run Windows siguiente al checkpoint CRT debe dejar de depender de una
revisión manual de artefactos. La preparación ya resuelve el `dumpbin.exe`
ARM64-host/ARM64-target junto con Visual Studio v145; esta extensión exporta esa
ruta exacta como `PM_NATIVE_DUMPBIN` en `GITHUB_ENV`. El laboratorio la exige,
comprueba que existe y que el propio ejecutable es ARM64; no busca `dumpbin` en
`PATH`, no selecciona otra instalación y no descarga ni sustituye la herramienta.

El seam observable es el build real seguido por la inspección PE antes de SCM.
Antes de implementar se añadió al checker una regresión que exige dos llamadas
de inspección, una por `pm-custody.exe` y otra por `pm.exe`, después del build y
antes de crear cualquier fixture. Cada llamada debe ejecutar el `dumpbin`
resuelto con `/headers` (machine `AA64`, sin x64/x86) y `/dependents`, y fallar
si aparece una dependencia CRT dinámica (`api-ms-win-crt-*`, `ucrtbase`,
`vcruntime`, `msvcp`, `msvcr`, `msvcrt`, `concrt` o `vcomp`). La regresión da RED
contra `8e22acd` porque todavía no existe la exportación ni las llamadas.

La implementación no cambia el linker, no suprime `LNK4098`, no añade retry,
timeout, fallback ni cambia cuentas/fixtures. El resultado nativo debe mostrar
la salida normal del linker sin `LNK4098`, dos inspecciones PE exitosas y luego
el laboratorio completo; cualquier error de `dumpbin` mantiene el job en RED.
Linux solo puede comprobar el contrato estático y el balance de scripts porque
no tiene `pwsh`, MSVC, `dumpbin` ni target Windows.

## Corrección acotada de ACL del fixture y método TDD (escrito antes de implementar)

La corrida nativa `34804746619` pasó la compilación, `linked_version`, los
checks del canal y la creación/SID del servicio, pero terminó en
`CUSTODY_UNAVAILABLE` y después en `Access denied` al limpiar. El laboratorio
sellaba `service`, `agent` y `human` antes de terminar el provisionado y de
crear la bóveda; además, el runner intentaba escribir y leer archivos de
redirección dentro de árboles que ya solo le permitían acceso a la cuenta de
runtime. La salida de `icacls` también se ejecutaba con `/c`, que podía dejar
errores por archivo sin convertirlos en un fallo del comando.

El seam verificable es la frontera de staging/sellado y el cleanup del único
árbol efímero creado por el laboratorio. Antes del cambio, el checker debe dar
RED si no encuentra este método:

1. Resolver el nombre del instalador desde el token elevado actual. Crear la
   raíz y los cuatro subárboles (`service`, `agent`, `human` y un `harness` de
   redirección sintética) y aplicar inmediatamente DACL explícita `SYSTEM` +
   instalador. No se escribe ningún secreto real ni se concede acceso a las
   cuentas runtime.
2. Generar las claves, provisionar bootstrap/perfiles, crear la bóveda y
   preparar antes del sellado todos los archivos de entrada/salida del
   harness. El harness solo contiene el master y argumentos sintéticos del
   ticket y permanece `SYSTEM` + instalador; no contiene datos de custodia.
3. Sellar después esas operaciones `service` como `SYSTEM` + cuenta virtual,
   `agent` como `SYSTEM` + agent y `human` como `SYSTEM` + human, sin ACE del
   instalador y antes de configurar/arrancar SCM. Las aserciones de salida leen
   únicamente el harness sintético; los procesos runtime conservan solo sus
   derechos de su propio árbol y del canal contractual.
4. Detener/eliminar el servicio y reparar ACL solo sobre el árbol propio
   previamente creado y su registro de rutas planificadas, nodo por nodo con
   `takeown.exe`/`icacls.exe`. Enumerar un nivel cada vez, rechazar cualquier
   `ReparsePoint`, no usar `-Recurse` ni `/R`, borrar solo después de recorrer
   los nodos regulares y propagar cada error. Si aparece un nodo no registrado
   o reparse, el cleanup queda en RED; no se atraviesan enlaces ni se borran
   recursos ajenos.

`icacls /grant:r` solo reemplaza el grant del trustee que se nombra y
`/inheritance:r` solo quita ACE heredadas; ninguno elimina por sí solo un ACE
explícito del instalador. Por eso `Set-ExactTreeAcl` aplica `/reset`, protege y
concede los trustees finales por nodo, de abajo hacia arriba, y no usa `/c`.
La semántica está documentada por
[Microsoft `icacls`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls).

La regresión estática comprueba el orden staging → provisionado/bóveda/harness
→ sellado → SCM, que el sellado sea role-only y que cleanup no use traversal
recursivo opaco. No cambia el motor, el modelo RPK/SID, las cuentas virtuales,
permisos runtime, plazos ni fallback. La comprobación Linux se limita al
checker, balance/sintaxis disponible y `git diff --check`; PowerShell real,
ACL, `takeown`, SCM y los procesos ARM64 siguen requiriendo el runner nativo.
El ticket permanece sin aceptar hasta repetir la corrida completa allí.

La regresión se ejecutó primero contra el estado anterior y dio RED por faltar el
identificador del instalador/staging. Después de implementar, el checker
`./scripts/verify-windows-libsodium-build.sh`, `sh -n
scripts/verify-windows-libsodium-build.sh` y `git diff --check` dieron exit 0.
No se ejecutó `check.sh`, `clean-offline-build.sh` ni los labs Cargo de Linux en
este checkpoint porque otra integración tenía la ventana exclusiva del
workspace; esas verificaciones previas de `6434449`/`8e22acd` no se presentan
como evidencia de la nueva ruta ACL. `pwsh`, ACL, `takeown`, SCM y el lab
Windows continúan sin ejecutarse en este host.

## Pendiente que bloquea aceptación

Falta compilar y ejecutar el producto y el script en Windows 11 ARM64. El
preflight corregido `34763094631` pasó 5/5 y observó Windows 11 Enterprise
10.0.26200, imagen `win11-vs2026-arm64 20260907.151.1`, PowerShell/PE ARM64 y
Rust 1.98.1 host `aarch64-pc-windows-msvc`; `EnableLUA=1` y el token del runner
pasó la comprobación de administrador. Fue solo entorno, no ejecutó producto.
La primera corrida del producto `34796411705` falló antes de MSBuild porque el
checkout convirtió el `.minisig` textual de LF a CRLF: el repositorio no tenía
atributo que preservara sus bytes. El hash del blob LF comprometido sigue
siendo el fijado y su transformación CRLF produce otro hash; no se cambió el
hash ni se normaliza el input al verificar. `.gitattributes` marca el tarball y
su firma como `-text`, y el checker exige `git check-attr text=unset` para ambos
antes de una nueva corrida. Este resultado no acredita el build nativo.
La segunda corrida `34796755222` pasó ambos hashes y la verificación Minisign
nativa, pero se detuvo antes de MSBuild porque la preparación había supuesto el
nombre inexistente `Microsoft.VCToolsVersion.VC.14.50.default.txt`. La corrección
usa únicamente el nombre estándar documentado, registra la metadata observada y
fija explícitamente la versión v145 leída; no prueba nombres alternativos ni
selecciona otro toolset.
Además,
`libsodium-sys-stable 1.24.0` contiene en su `build.rs` un fallback existente:
si falla `install_from_source()` en MSVC, activa
`extract_libsodium_precompiled_msvc()` y sustituye la compilación del tarball
fijado por `libsodium-1.0.22-stable-msvc.zip`. `SODIUM_DIST_DIR` fuerza entrada
local y ese zip no existe. La preparación autorizada evita ese camino mediante
`SODIUM_LIB_DIR` solo después de verificar y compilar el tarball firmado; no
añade el ZIP ni cambia el fallback. Windows 11 x64
estándar no está disponible. Reboot/FDE, Windows Terminal humano real y firma
permanecen en 32/34. Por ello el ticket conserva `Status: claimed` y ningún
criterio de aceptación se marca completo.

La tercera ejecución nativa del producto,
[run 34797085446](https://github.com/SantanaJcp/passwordmanager/actions/runs/34797085446),
volvió a quedar en **failure** antes de crear fixtures o ejecutar el producto.
La compilación fuente autenticada de libsodium y `linked_version` ya habían
pasado; el laboratorio se detuvo en su guardia administrativa porque
`(whoami /groups) -match ...` produjo un `Object[]` que PowerShell no pudo
convertir al parámetro `[bool]` de `Assert-True`. La corrección mantiene la
guardia `EphemeralCI`, `GITHUB_ACTIONS=true`/`CI=true` y la comprobación de
administrador, pero usa `WindowsPrincipal.IsInRole(Administrator)`, el mismo
token administrativo que ya comprueba el preflight. Este fallo no es evidencia
de producto y exige una nueva corrida Windows nativa; no se marca ningún
criterio como completo.

La cuarta ejecución nativa,
[run 34797595176](https://github.com/SantanaJcp/passwordmanager/actions/runs/34797595176),
acreditó los tests DPAPI y ConPTY, pero el test público de carrera clipboard
falló porque la segunda lease tampoco se reconoció como propietaria al limpiar.
Antes de cambiar el comportamiento se extiende el mismo test nativo con un
diagnóstico acotado y sin payload: registra los sequence numbers después de
`EmptyClipboard`, después de `SetClipboardData`, inmediatamente antes y después
de `CloseClipboard`; registra además si existe owner HWND/open HWND, los
resultados booleanos de cada API y `GetLastError` solo al fallar. La aserción
original permanece. Esto discrimina si el sequence cambia al cerrar, si la
apertura con HWND nulo deja owner inválido, o si otro escritor cambia el
clipboard después. No mueve la decisión de ownership fuera del lock, no añade
sleeps/retries/deadlines y no imprime el secreto sintético. La documentación de
Microsoft establece en [OpenClipboard](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openclipboard)
y [clipboard ownership](https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-operations)
que `OpenClipboard(NULL)` seguido por `EmptyClipboard`
deja owner nulo y puede hacer fallar `SetClipboardData`, mientras el sequence se
incrementa al vaciar o cambiar contenido; por eso ninguna corrección se atribuye
hasta observar estos puntos en Windows 11 ARM64.

La quinta ejecución,
[run 34798532966](https://github.com/SantanaJcp/passwordmanager/actions/runs/34798532966),
confirmó el discriminante: primera lease `after_empty=1`, `after_set=2`,
`after_close=5`; segunda `6/7/10`; `current=10`; owner y open HWND fueron
nulos en todos los puntos y ambos `CloseClipboard` tuvieron éxito. Se conservan
el RED original y este RED diagnóstico. La corrección que deberá comprobar el
mismo test crea un HWND message-only propio por lease y lo pasa a
`OpenClipboard`, publica con `EmptyClipboard` + `SetClipboardData`, cierra y
vuelve a adquirir una sola vez el lock. Ya bajo ese lock verifica atómicamente
que `GetClipboardOwner` aún sea ese HWND y captura el sequence final estabilizado;
si perdió ownership, falla y jamás vacía contenido ajeno. `clear_if_owned`
adquiere el lock una vez y solo vacía cuando owner HWND y sequence coinciden.
El HWND se destruye al consumir o descartar la lease. No hay lectura post-close
ciega, retry, sleep, sustitución ni limpieza por sequence solamente. El test
existente conserva la carrera de dos owners y se añade una pérdida de ownership
entre publicar y capturar mediante un hook solo de test que publica el segundo
owner en esa frontera; la lectura real de `CF_UNICODETEXT` se comprobará bajo el
lock si la API nativa disponible permite hacerlo sin duplicar el motor.

La implementación candidata usa la clase de sistema `STATIC` como
[HWND message-only](https://learn.microsoft.com/en-us/windows/win32/winmsg/window-features)
por lease. Los dos tests de clipboard mantienen la carrera original,
leen de vuelta el `CF_UNICODETEXT` real y prueban pérdida de owner exactamente
entre publicación y captura; no contienen un backend alternativo. En Linux solo
se pudo compilar esta ruta con el chequeo sintáctico cfg ya documentado:

```text
RUSTFLAGS='--cfg target_os="windows" -Aexplicit_builtin_cfgs_in_flags' \
  ./scripts/cargo-local.sh clippy -p pm-native-channel --all-targets \
  --locked --offline -- -D warnings
# exit 0

./scripts/check.sh
# exit 0
```

Ambos tests nuevos siguen pendientes de ejecución real Windows ARM64; este
resultado local no convierte el ticket en aceptado.

La sexta ejecución,
[run 34799143030](https://github.com/SantanaJcp/passwordmanager/actions/runs/34799143030),
pasó DPAPI, ConPTY y la carrera clipboard original. El nuevo caso de pérdida de
ownership falló al crear su writer interloper, mientras el otro caso clipboard
seguía ejecutándose en paralelo en el mismo binario de tests. Ambos casos usan
el único clipboard de la misma window station y `OpenClipboard` excluye otros
writers; por tanto no son fixtures independientes. La corrección de método
serializa **solo esos dos casos** con un `Mutex` test-only compartido. La
concurrencia adversaria intencional dentro del segundo caso permanece en la
frontera exacta publish/capture; no se usa `--test-threads=1`, retry, timeout ni
cambio de producto. El siguiente Windows ARM64 debe pasar ambos casos juntos
con el runner paralelo normal para confirmar el diagnóstico; un fallo seguiría
siendo RED y requeriría nuevo análisis.

## Regresión Linux del checkpoint

Después de extraer el motor wire compartido, `./scripts/check.sh` terminó con
exit 0. La corrida integral de labs **no** fue verde: `attempts` devolvió
`RUNNING` donde el lab esperaba `INDETERMINATE`; pasó sin cambios al reintento.
La continuación se detuvo al faltar en el worktree el artefacto CFT ya
preparado; se enlazó el mismo artefacto del repositorio, no otro navegador. Los
17 scripts terminaron verdes individualmente, pero `passkey-login` devolvió
primero `RUNNING` donde esperaba `WAITING_FOR_HUMAN` y `token-exchange` obtuvo
retorno no cero en la negativa de audience; ambos pasaron sin cambios al
reintento. No se estableció causa para esos tres resultados, no se ocultan y no
se afirma estabilidad integral. `./scripts/clean-offline-build.sh` pasó después
de los cambios en 35.50 s. Lo observado cubre regresión funcional Linux, no
aporta evidencia Windows.

## Resultado verificable del checkpoint de filesystem

El checkpoint partió de `6bef3bc6dcba2367bc460c8aa0011b6ac9335ced`, con el
worktree limpio. La prueba TDD RED añadió primero el uso de
`native_fs::file_identity` sin crear el módulo y falló con `E0583` (módulo
ausente). Después se implementaron únicamente los seams de `pm-vault` en
`native_fs.rs`, sus llamadas en `onepux.rs`/`reducer.rs`, la dependencia
Windows fijada y esta nota de verificación. La creación Windows usa
`CreateFileW(CREATE_NEW)` con el descriptor DACL privado desde la propia
creación; no existe una ventana de ACL heredada ni una ruta de copia/rename.

Evidencia Linux posterior, siempre con bytes sintéticos y `--locked --offline`:

```text
./scripts/cargo-local.sh fmt --all -- --check                         # PASS
./scripts/cargo-local.sh clippy -p pm-vault --lib --locked --offline -- -D warnings  # PASS
./scripts/cargo-local.sh test -p pm-vault --lib native_file_identity_is_read_from_the_open_file --locked --offline  # 1 PASS
./scripts/cargo-local.sh test -p pm-vault --test onepux_import --locked --offline      # 4 PASS
./scripts/cargo-local.sh test -p pm-vault --test causal_reducer --locked --offline    # 7 PASS
./scripts/cargo-local.sh test -p pm-vault --test history_lifecycle --locked --offline  # 3 PASS
./scripts/cargo-local.sh test -p pm-vault --test local_vault --locked --offline       # 3 PASS
./scripts/test-linux-1pux-import-lab.sh                                      # PASS
./scripts/test-linux-history-lab.sh                                          # PASS
./scripts/test-linux-sync-lab.sh                                             # PASS (public/production limits unchanged)
git diff --check                                                             # PASS
./scripts/check.sh                                                           # PASS
./scripts/clean-offline-build.sh                                             # PASS
```

Se inspeccionó además la metadata de Cargo filtrada para
`aarch64-pc-windows-msvc`: `windows-sys 0.61.2` queda como dependencia solo
para Windows con las features Foundation, Security, Authorization y
Storage/FileSystem. El intento honesto de `cargo check --target
aarch64-pc-windows-msvc --locked --offline` no puede encontrar `core` porque
este host solo tiene el target Linux. No se usó `RUSTFLAGS`, `cfg` manual,
cross-compilation ni mocks para convertirlo en evidencia. Por tanto el
compilado/ejecución nativos Windows ARM64/x64 siguen siendo prerrequisito del
runner y este checkpoint no marca aceptación del ticket.

## Diagnóstico acotado de persistencia Windows (método antes de editar Rust)

La corrida nativa `34806610284` sobre `6daece1` compiló los binarios y pasó
PE/CRT, SCM, keygen, bootstrap y perfiles, pero `vault create` devolvió
`ERROR_ACCESS_DENIED` antes del sellado final. El cleanup no registró
`cleanupErrors` y su inventario no incluyó `vault.sqlite3` ni un temporal; esto
no distingue todavía entre el `sync_all` de solo lectura del temporal, el
hard-link o el `File::open(parent)` posterior. `VaultError` tampoco conserva la
fase.

Antes de cambiar el motor se añade el entrypoint opt-in
`scripts/test-windows-storage-diagnostics.ps1`. Es destructivo únicamente para
una raíz sintética nueva bajo `ProgramData`, exige `-EphemeralCI`,
`GITHUB_ACTIONS=true`, `CI=true`, Windows 11 y proceso nativo, y no usa Cargo,
servicios, cuentas ni secretos. La raíz y un único archivo de bytes sintéticos
se registran y se eliminan solo por sus rutas propias; todo fallo de cleanup
falla el diagnóstico.

El workflow manual expone `diagnostic_only` como booleano explícito, cuyo valor
por defecto es `false`: `false` conserva únicamente el job de producto y sus
fases Rust/MSVC existentes; `true` selecciona un job separado Windows 11 ARM64
que hace checkout con la acción SHA fijada y ejecuta solo este entrypoint. El
job diagnóstico no instala toolchain, no hace `cargo`, no prepara libsodium, no
ejecuta el laboratorio de producto y no publica artefactos/cache. Aunque el job
termine con categorías observadas, su nombre y documentación dejan claro que
no cuenta como aceptación de Windows ni cierra ningún gate.

Con P/Invoke directo a `CreateFileW`, `FlushFileBuffers` y `CloseHandle`, el
entrypoint ejecuta exactamente estas fases sobre nombres fijos y emite solo
categorías fijas, sin ruta, código, excepción ni payload:

1. sella el archivo de diagnóstico con DACL protegida exacta
   `SYSTEM`+instalador, verifica sus ACE y demuestra primero que un handle
   `GENERIC_READ|GENERIC_WRITE` puede abrirse y hacer flush (`file-flush-write`);
2. abre ese archivo con `GENERIC_READ` como hace `File::open` y llama a
   `FlushFileBuffers` para observar `file-flush-readonly`;
3. abre el directorio con `GENERIC_READ` sin
   `FILE_FLAG_BACKUP_SEMANTICS` para observar `directory-open-no-backup`;
4. abre el directorio con `GENERIC_READ` y el flag de backup, y llama a
   `FlushFileBuffers` para observar `directory-flush-readonly`;
5. repite el directorio con `GENERIC_READ|GENERIC_WRITE` y el flag para
   observar `directory-flush-write`.

Cada handle se cierra y un error no se convierte en éxito. La salida puede
clasificar únicamente `success`, `access-denied`, `invalid-handle`,
`invalid-function`, `not-supported`, `invalid-parameter`, `not-run` u
`other-error`; no hay retry, espera, flush del volumen, privilegio
administrativo adicional, no-op ni fallback. El entrypoint no declara la
durabilidad del producto ni modifica `persist_new`; solo aporta el
discriminante nativo para decidir si existe una API Windows equivalente.

El método se basa en las fuentes primarias de Microsoft: [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
exige `FILE_FLAG_BACKUP_SEMANTICS` para abrir directorios; [Directory
Handles](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-handle-to-a-directory)
enumera las operaciones aceptadas sobre esos handles; y
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
exige `GENERIC_WRITE` y devuelve el error del sistema cuando falla. La
documentación de [File Caching](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching)
confirma que el metadata flush es una garantía explícita, no una razón para
ignorar un resultado fallido. Hasta observar el diagnóstico y una estrategia
Windows documentada, no se cambia el seam Rust ni se afirma persistencia
durable equivalente.

## Corrección acotada del flush nativo (método antes del código)

El diagnóstico nativo opt-in de
[run 34807853352](https://github.com/SantanaJcp/passwordmanager/actions/runs/34807853352),
sobre `b5788c3`, terminó correctamente como **diagnóstico**, no como aceptación:

```text
file-open-write=success
file-flush-write=success
file-open-readonly=success
file-flush-readonly=access-denied
directory-open-no-backup=access-denied
directory-flush-no-backup=not-run
directory-open-backup-readonly=success
directory-flush-readonly=access-denied
directory-open-backup-write=success
directory-flush-write=success
```

La lectura exacta de los sitios de producción encontró solo dos usos de ruta que
requieren este seam: `crates/pm-vault/src/lib.rs` abre en solo lectura el temporal
antes del hard-link (línea 682 en el RED) y abre el directorio padre sin
`FILE_FLAG_BACKUP_SEMANTICS` (línea 690). El `sync_all` de
`crates/pm-vault/src/reducer.rs` ya se ejecuta sobre el handle escribible que
devuelve `native_fs::create_private`; no se reescribe ni se cambia ningún otro
camino de persistencia.

El contrato verificable antes de implementar es:

1. `sync_file` abre el archivo existente con acceso escribible, no sigue un
   reparse point final y propaga el resultado de `sync_all`/`FlushFileBuffers`.
2. `sync_directory` abre el directorio existente con acceso escribible y
   `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, comprueba que el
   handle sea un directorio no reparse y propaga el flush. En Unix conserva
   `O_CLOEXEC | O_NOFOLLOW` y el contrato de `sync_all` existente.
3. `persist_new` conserva el orden `flush temporal -> hard-link -> flush padre`,
   sus errores observables y la atomicidad; no cambia la API pública.
4. `FILE_FLAG_OPEN_REPARSE_POINT` protege el componente final solamente. Los
   padres siguen sujetos al contrato existente de raíz confiable/ACL; no se
   inventa un recorrido alternativo ni se concede privilegio de volumen.

No se permite convertir un error en éxito, ignorar `FlushFileBuffers`, usar un
flush del volumen, añadir privilegios, cambiar a rename/copia, introducir
fallback o ampliar plazos. Las referencias primarias que fijan el método son
[CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
(`FILE_FLAG_BACKUP_SEMANTICS` para directorios),
[Directory Handles](https://learn.microsoft.com/en-us/windows/win32/fileio/obtaining-a-handle-to-a-directory)
y [FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
(`GENERIC_WRITE` necesario).

La regresión de contrato se añade primero en el test de `pm-vault`: un archivo y
un directorio sintéticos se sincronizan mediante ambos seams, sin datos de
custodia. Debe fallar en el estado anterior por funciones inexistentes y pasar
después de la implementación. El checker exige además las llamadas en
`persist_new`, los flags de apertura nativa y la ausencia de los dos `File::open`
problemáticos. La validación Windows posterior debe repetir el job de producto
normal (`diagnostic_only=false`) y observar el vault real; el diagnóstico opt-in
no cuenta como aceptación. En este host no se simula PowerShell, MSVC ni el
target Windows y no se ejecutan los checks/labs pesados mientras la ventana de
Linux pertenece a otra integración.

La RED local observada antes de implementar fue explícita: el comando enfocado
`./scripts/cargo-local.sh test -p pm-vault --lib
native_flush_seams_sync_synthetic_file_and_parent --locked --offline` terminó
con exit 101 y dos `E0425` (`sync_file` y `sync_directory` ausentes). La corrida
duró 16,2 s y no dejó procesos activos; su resultado no se repite hasta que
root libere la ventana compartida de Cargo.

## Verificación local de esta corrección

Con la ventana Linux27 concedida por root y después de implementar, la regresión
en verde fue:

```text
native_flush_seams_sync_synthetic_file_and_parent: 1 passed, 0 failed
```

También pasaron `cargo fmt --all -- --check`, `cargo clippy -p pm-vault --lib
--locked --offline -- -D warnings`, y las suites enfocadas de `pm-vault`:
`causal_reducer` (7), `history_lifecycle` (3), `local_vault` (3) y
`onepux_import` (4), todas sin fallos. Los labs reales Linux
`test-linux-1pux-import-lab.sh`, `test-linux-history-lab.sh` y
`test-linux-sync-lab.sh` terminaron `PASS`; el último mantuvo `tls=1.3`, RPK
mutual, ALPN `pm-sync/1` y proceso real.

El checker `verify-windows-libsodium-build.sh`, `sh -n`, `git diff --check` y
`check.sh` pasaron. `clean-offline-build.sh` eliminó el target y recompiló el
workspace offline sin error en 38,63 s. No se ejecutó PowerShell, MSVC, Dumpbin
ni un target Windows; por tanto no se afirma que el helper compile o funcione
en Windows hasta la corrida nativa normal con `diagnostic_only=false`. No se
modificó el cleanup heredado de `persist_new` ni se introdujo fallback.

## Diagnóstico acotado del estado SCM (método antes del código)

La corrida normal nativa 11,
[run 34809788057](https://github.com/SantanaJcp/passwordmanager/actions/runs/34809788057),
sobre `e2fdc21`, avanzó más que el RED anterior: creó `vault.sqlite3` y
`vault.sqlite3.audit-custody`, selló ACL y compiló el servicio. `sc.exe start`
mostró temporalmente `STATE : 4 RUNNING`, `WIN32_EXIT_CODE : 0` y PID 8528,
pero después del `Start-Sleep -Seconds 2` vigente el `Get-Service` del lab falló
con `custody service did not reach RUNNING`. El log no contiene el código que
dejó el servicio en estado detenido; ampliar ese sleep no distingue una demora
de arranque de un proceso que se registra como RUNNING y luego devuelve
`CUSTODY_UNAVAILABLE`.

Antes de tocar el motor se fija este método mínimo y reversible:

1. Añadir al lab un switch exacto `-ServiceDiagnostics`, apagado por defecto,
   y una entrada manual booleana `service_diagnostics` cuyo default siga siendo
   `false`. El job normal continúa ejecutando exactamente el mismo flujo cuando
   el input es falso.
2. En tres fases fijas (`before-start`, `after-start`, `after-settle`) consultar
   una vez `Win32_Service` por el nombre ya colisionado. Emitir solamente
   categorías constantes para `state` (`running`, `start-pending`,
   `stop-pending`, `stopped-exit-zero`, `stopped-exit-nonzero`, `missing`,
   `other`, `query-error`) y `pid` (`present`, `absent`, `unknown`). El estado
   detenido se clasifica por `ExitCode` y `ServiceSpecificExitCode`, sin imprimir
   valores dinámicos, rutas, excepciones, cuentas ni secretos.
3. Conservar el `Start-Sleep -Seconds 2`, la aserción actual, las cuentas y el
   cleanup. El diagnóstico no reintenta `sc start`, no extiende el plazo, no
   cambia el estado de éxito/fallo y no puede convertir una detención en PASS.
   Si el modo está apagado, no consulta ni imprime nada adicional.

Este discriminante separa un servicio aún pendiente de un servicio propio que
se detuvo con código no cero, sin asumir cuál fase interna falló. Si el modo
opcional observa `stopped-exit-nonzero`, la siguiente corrección deberá añadir
una fase interna categórica solamente con nueva evidencia; no se inventa un
fallback ni se relaja el contrato del servicio. La corrida diagnóstica tampoco
cerrará ningún criterio de aceptación: sigue siendo necesaria la corrida normal
con `service_diagnostics=false` y el resto de gates nativos.

La regresión estática se ejecutó primero contra `e2fdc21` y dio RED porque faltaba
`[switch]$ServiceDiagnostics` (checker exit 1). Después de implementar el
checkpoint, `verify-windows-libsodium-build.sh`, `sh -n`, `git diff --check` y
la inspección estructural YAML pasaron. El host Linux no tiene `pwsh`; todavía
falta ejecutar el mismo lab en Windows con el input manual
`service_diagnostics=true` para observar las categorías reales. Esa corrida no
debe sustituir la posterior corrida normal con el input en `false`.

## Diagnóstico acotado de subfases del servicio (método antes del código)

La corrida nativa 12 (`34810534527`, sobre `762a60c`) confirma que no basta con
muestrear el estado de SCM: `sc start` informó temporalmente `RUNNING`, código de
salida cero y PID 1776; 243 ms después y de nuevo tras los 2 s ya vigentes el
servicio figuraba `stopped-exit-nonzero`, sin PID. La fase `before-start` no se
trata como causal porque el campo de salida de un servicio que todavía no ha
arrancado puede ser histórico. En el código actual, `service_main` publica
`SERVICE_RUNNING` antes de llamar a `serve_vault`; después todos los errores de
argumentos, DPAPI/bootstrap, audit custody, TLS o la primera named pipe se
reducen a `Failure::Unavailable` y un único exit code no cero. `serve_vault`
además espera primero al hilo agente, de modo que el error inicial del rol no
identifica la subfase.

Antes de instrumentar se fija este discriminante mínimo, reversible y solo de
observación:

1. El laboratorio recibe `-ServiceDiagnostics` únicamente cuando el input
   manual booleano `service_diagnostics` es explícitamente `true`; el default
   sigue siendo `false` y la invocación del producto normal permanece idéntica.
   En modo diagnóstico se precrea un archivo vacío y de propiedad registrada
   bajo una carpeta descartable separada. Su DACL protegida contiene solo
   `SYSTEM`, el instalador elevado y `NT SERVICE\PasswordManager`; no se
   concede acceso a `Everyone`, `Users`, agente ni humano. La carpeta, archivo
   y ruta se registran en el ledger de recursos propios y siguen las mismas
   guardias de colisión, no-reparse y cleanup propagador del fixture.
2. El servicio acepta el argumento opt-in `--service-diagnostics <path>` solo
   para esa corrida. Abre el archivo ya existente con lectura y escritura
   explícitas, `FILE_FLAG_OPEN_REPARSE_POINT`, `GetFileInformationByHandle` y
   una identidad de archivo regular/no-reparse válida; no lo crea ni imprime la
   ruta. Un `Arc<Mutex<File>>` serializa las escrituras concurrentes de ambos
   roles; cada escritura busca el final bajo el mutex y hace `sync_all`, y un
   error de la ruta no se ignora ni crea una ruta alternativa.
3. Solo se escriben líneas literales, sin tiempos, rutas, SIDs, códigos Win32,
   excepciones, argumentos, secretos ni datos de bóveda: `phase=args-ok`,
   `phase=bootstrap-ok`, `phase=audit-ok`, `phase=agent-tls-ok`,
   `phase=agent-pipe-ok`, `phase=human-tls-ok`, `phase=human-pipe-ok` y
   `phase=service-failed`. `args-ok` se emite después de validar todos los
   argumentos y nombres de pipe; los siguientes marcadores se emiten solo tras
   completar cada fase. `service-failed` se emite una sola vez cuando la
   inicialización devuelve error. La ausencia del último marcador permite
   ubicar el siguiente substage sin afirmar una causa que la evidencia no
   contiene.
4. El lab lee únicamente esas literales desde el archivo protegido, rechaza
   cualquier otra línea y las muestra como diagnóstico fijo. Conserva la
   aserción actual de `Running`, el `Start-Sleep -Seconds 2`, los roles, el
   restart, los plazos, la salida pública `CUSTODY_UNAVAILABLE` y el cleanup.
   El modo diagnóstico no reintenta `sc start`, no convierte una detención en
   éxito, no cambia el estado de aceptación y no se activa por defecto. Una
   corrida con estos marcadores sigue siendo evidencia diagnóstica, no cierre
   de ningún gate nativo.

La regresión se escribe antes del seam de Rust en el verificador existente:
debe fallar contra `762a60c` si faltan el argumento `--service-diagnostics`, los
ocho literales de fase, el handle `Arc<Mutex<File>>`, el `create(false)` y la
propagación de `service-failed`; también debe fallar si el lab no crea y
registra el archivo protegido, no valida su DACL exacta o pasa el argumento
cuando el switch está apagado. Después de la implementación, el mismo checker
y `git diff --check` deben pasar. El host Linux no tiene `pwsh`, así que no se
simula parsing PowerShell ni se reclama que el servicio Windows compile. La
corrida manual con `service_diagnostics=true` observará las subfases reales; la
posterior corrida normal con `false` sigue siendo obligatoria.

La regresión estática se ejecutó primero contra `762a60c` y falló con exit 1 por
la ausencia de `enum ServiceDiagnosticPhase`. Tras añadir el seam, el mismo
checker volvió a pasar, junto con `git diff --check` y `sh -n` del checker. No
se ejecutaron Cargo, compilación, laboratorios ni PowerShell en este host por la
ventana Linux compartida; la sintaxis y ACL reales de Windows siguen pendientes
de la corrida hospedada autorizada.

## Corrección acotada de banderas del servidor de named pipe (método antes del código)

La corrida nativa 13 (`34837323516`, sobre `deaa746`) llegó a `args-ok`,
`bootstrap-ok`, `audit-ok`, `agent-tls-ok` y `human-tls-ok`, pero no produjo
`agent-pipe-ok` ni `human-pipe-ok` y terminó en `service-failed`. La revisión del
seam que crea el pipe encontró que `CreateNamedPipeW` recibía, dentro de
`dwOpenMode`, `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. La
documentación primaria de
[CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew)
limita ese parámetro a los modos de acceso del pipe y las banderas de servidor
enumeradas; las banderas SQOS no forman parte de esa lista. Esas banderas sí
pertenecen al parámetro de atributos de la llamada cliente
[`CreateFileW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
donde continúan siendo necesarias para solicitar impersonación de nivel
identification. La inferencia causal queda acotada a la incompatibilidad de la
invocación del servidor hasta repetirla en Windows; el log no se usa para
afirmar una causa del motor ni para cerrar el ticket.

Antes de editar el seam se fijó este método TDD, limitado a las banderas de la
API y a una regresión nativa real:

1. Añadir primero una prueba `#[cfg(target_os = "windows")]` que abra el token
   del proceso actual y obtenga su SID mediante la API del sistema. La prueba
   crea un identificador de bóveda hexadecimal único y una primera instancia
   del helper nativo compartido por `WindowsServerPipe`, con un descriptor
   propietario del SID actual, ese SID como cliente y un SID de servicio
   sintético en las ACE. Mientras el primer handle sigue vivo, intenta crear la
   segunda instancia con el mismo nombre, el mismo servicio y un SID de cliente
   distinto; la primera creación debe pasar y la segunda debe devolver error.
   El recurso es propio de la prueba y se libera por RAII al terminar. No hay
   mocks, skips, nombres compartidos ni reintentos.
2. Cambiar únicamente `dwOpenMode` de `CreateNamedPipeW` para conservar
   `PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE`; también se conservan
   `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS`,
   la DACL explícita y las comprobaciones bilaterales SID/PID. Se eliminan de
   ese parámetro solo las banderas SQOS que pertenecen al cliente. La llamada
   `CreateFileW` mantiene
   `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`; no se sustituye el pipe,
   no se relaja autenticación local y no se introduce fallback.
3. Si la creación del servidor devuelve `INVALID_HANDLE_VALUE`, leer
   `GetLastError` inmediatamente, antes de `LocalFree(descriptor)`, y conservar
   únicamente la indicación de que la creación falló para la decisión local.
   El código numérico se descarta después de esa comprobación: no se persiste ni
   se expone como diagnóstico. La API pública conserva
   `ChannelAuthenticationError` opaco y no imprime código Win32, ruta, SID ni
   otro dato dinámico; liberar el descriptor no participa en la decisión.

La regresión textual del checker se ejecutó antes de la corrección y dio RED
con `CreateNamedPipeW server mode must not contain client SQOS flags`. Después
de la prueba y del cambio acotado, pasaron
`./scripts/verify-windows-libsodium-build.sh`, `sh -n
scripts/verify-windows-libsodium-build.sh` y `git diff --check`. No se ejecutó
Cargo, `check.sh`, PowerShell ni el test Windows en este host: no hay target
Windows/MSVC y la ventana de Cargo compartida estaba reservada. El siguiente
job Windows debe ejecutar la regresión contra el API real y el laboratorio
normal; cualquier ejecución con diagnósticos sigue siendo observación y no
aceptación. El ticket permanece sin aceptar hasta que la corrida normal con
`service_diagnostics=false` y los demás gates nativos pasen.

La validación estática adicional usó directamente el `rustfmt` de Rust 1.98.1
(`rustfmt --edition 2024 --check`) y pasó. La inspección del binding local
`windows-sys 0.61.2` confirmó `OpenProcessToken` bajo
`Win32::System::Threading` y `TOKEN_QUERY` bajo `Win32::Security`; los imports
del test siguen esas ubicaciones. No se ejecutaron Cargo ni una prueba Windows.

## Corrección del fixture de regresión named pipe (método antes del código)

La corrida nativa 14 (`34838861714`, sobre `23bc5e6`) falló en el `unwrap` de
la primera creación de la regresión del pipe; las otras cuatro pruebas del
canal pasaron y el servicio ni siquiera llegó a iniciarse. Ese `unwrap` no
conservaba `GetLastError`, por lo que esta corrida no demuestra que la
corrección de banderas del servidor haya fallado. La hipótesis acotada es que
el fixture pedía como propietario y grupo `S-1-5-80-27027`, un SID de servicio
sintético que no está en el token del runner (`S-1-5-21-...`). La fuente
primaria de
[CreatePrivateObjectSecurityWithMultipleInheritance](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createprivateobjectsecuritywithmultipleinheritance)
indica que la validación de propietario acepta el `TokenUser` o un grupo
autorizado del token y puede devolver `ERROR_INVALID_OWNER`; la documentación
de [seguridad de named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
confirma que el descriptor entregado a `CreateNamedPipe` gobierna ambos
extremos. Esta es una hipótesis comprobable, no una causa ya observada en
Windows.

Antes de cambiar la prueba se fijó este método mínimo:

1. Mantener sin cambios `windows_pipe_sddl`, su validación de SID y el
   descriptor de producción: el proceso real del servicio seguirá usando su
   SID de servicio como propietario/grupo y conservará las ACE de SYSTEM,
   servicio y cliente. No se sustituye la cuenta por `LocalSystem` ni se
   relaja la identidad.
2. Construir únicamente para la regresión un descriptor derivado del SDDL
   canónico, reemplazando propietario/grupo por el SID del token actual del
   runner. Las ACE de SYSTEM, servicio y cliente permanecen idénticas. La
   primera instancia usa un nombre hexadecimal único, un handle propio y el
   SID cliente actual; la segunda usa el mismo nombre y un SID cliente válido
   distinto. Así el descriptor es válido para el creador sin falsear el
   contrato de producción.
3. Compartir con producción el helper que llama a `CreateNamedPipeW` y hace
   `GetLastError` inmediatamente cuando devuelve `INVALID_HANDLE_VALUE`, antes
   de que el caller libere el descriptor. La prueba debe mostrar el código
   Win32 solo en el mensaje de fallo del test y debe exigir que la primera
   creación pase y la segunda devuelva exactamente `ERROR_ACCESS_DENIED` por
   `FILE_FLAG_FIRST_PIPE_INSTANCE`; el camino público continúa descartando el
   código y devolviendo `ChannelAuthenticationError` opaco. Un wrapper RAII
   cierra el primer handle incluso durante unwinding.
4. No se añade retry, timeout, pipe alternativo ni salida de secretos. La
   siguiente ejecución Windows es la que debe aportar el código real de un
   eventual fallo de fixture o de API; hasta entonces no se atribuye el RED a
   la corrección del servidor ni se marca aceptación.

La regresión estática se ejecuta primero contra el test anterior y debe
comprobar que el nuevo fixture exige el SID propietario actual, que conserva
las ACE canónicas, que informa `GetLastError` y que mantiene el error exacto de
segunda instancia. En este host solo se ejecutan el checker, `rustfmt` directo,
`sh -n` y `git diff --check`; no se ejecuta Cargo ni se simula Windows. El
laboratorio nativo normal sigue siendo obligatorio después de este diagnóstico.

### Cierre del handle del fixture (método antes del código)

El wrapper `OwnedTestPipe` no puede ignorar el resultado de `CloseHandle`: la
regresión debe acreditar también que no deja una instancia con nombre viva.
Antes del ajuste se fija este ciclo:

1. El wrapper guarda el handle en `Option<HANDLE>`. El camino normal llama una
   sola vez a `close`, extrae el handle y exige que `CloseHandle` devuelva éxito;
   el error devuelve el código fijo de Win32 al test y no se reintenta.
2. `Drop` intenta ese mismo cierre solo si el handle todavía está presente. Si
   falla sin que el hilo esté desenrollando, hace fallar el test con el código;
   si ya hay unwinding, aborta en vez de provocar un segundo panic. De esta
   forma el resultado no queda ignorado y el cierre se intenta una sola vez.
3. El `Drop` heredado de `WindowsServerPipe` no se modifica: esta corrección
   está limitada al fixture `#[cfg(test)]`. No cambia producción, permisos,
   fallback ni la semántica del canal.

## Diagnóstico acotado de la operación humana (método antes del código)

La corrida diagnóstica nativa 15 sobre `776bf26`, conservada en el log de
ejecución entregado para este diagnóstico, pasó los cinco tests nativos del
canal y el contrato de nombres de pipe. El servicio
llegó a `RUNNING` y registró las siete fases de inicialización hasta
`human-pipe-ok` y `agent-pipe-ok`. Esas dos fases prueban únicamente la creación
de la primera instancia de cada pipe, no `accept`, handshake ni una petición.
El `human-lock` devolvió el error público opaco `CUSTODY_UNAVAILABLE`; las fases
actuales no permiten ubicarlo. La contraseña sintética coincide con la usada
para crear la bóveda, pero eso no prueba canal, KDF, almacenamiento ni auditoría.

El `probe` agente vigente sí acredita el handshake: antes de consumir el primer
write, rustls 0.23.44 ejecuta `complete_prior_io` y propaga el error de
`complete_io` mientras la conexión está en handshake. El I/O posterior a
consumir esos bytes puede diferir su error hasta la operación siguiente; como
el probe termina sin lectura ni `flush`, su PASS no acredita que el servidor
aceptó el MAGIC aplicativo ni que produjo la respuesta del rol. Tampoco prueba
la identidad, canal o operación humana, que usan otro pipe y RPK.

Con el `-ServiceDiagnostics` ya autorizado se añade un único discriminante,
sin otra autenticación ni operación de bóveda:

1. El servicio registra literales fijas después de completar cada frontera de
   la misma operación: `human-accepted`, `human-magic-alpn`,
   `human-unlock-request`, `human-unlock-ok`, `human-unlock-ack`,
   `human-lock-request`, `human-audit-open`, `human-audit-append` y
   `human-lock-ack`.
2. Si la única llamada a `HumanVault::unlock` con custodia explícita falla,
   registra exactamente
   una categoría terminal derivada de la variante ya disponible, nunca de su
   texto: `human-unlock-wrong-channel`, `human-unlock-storage-io`,
   `human-unlock-vault-crypto`, `human-unlock-vault-format` o
   `human-unlock-other`. El error público continúa siendo
   `CUSTODY_UNAVAILABLE`; no se escriben tiempos, códigos, rutas, SIDs, datos de
   bóveda, contraseña ni mensajes dinámicos.
3. El parser del fixture conserva la gramática cerrada, exige cardinalidad
   máxima uno para cada fase humana y acepta únicamente un prefijo ordenado de
   la traza de éxito o una traza que termina en una sola categoría de fallo.
   Lee el archivo inmediatamente después de `human-lock`, antes de afirmar su
   salida pública, de modo que el RED también preserva el discriminante.
4. No cambia ningún timeout, ACL, RPK, pipe, KDF, retry ni resultado. Si no se
   observa siquiera `human-accepted`, hará falta proponer por separado un seam
   cliente; este cambio no lo anticipa.

La regresión estática debe escribirse antes de Rust y dar RED por las fases
ausentes. Después verifica que todas las literales están en el enum cerrado,
que el lab valida orden/cardinalidad y que el resultado de una sola llamada de
unlock selecciona la categoría sin imprimir el error. Solo una nueva corrida
Windows con `-ServiceDiagnostics` puede localizar el fallo.

La regresión dio RED contra `776bf26` por ausencia de
`human_unlock_failure_phase`. Tras implementar el seam, el checker completo,
su sintaxis `sh -n` y `git diff --check` pasaron. La inspección `rustfmt --check`
alcanzó tres diferencias de formato ya presentes fuera de los bloques
instrumentados; no se reescribió el archivo completo ni se presenta ese
resultado como verde. No se ejecutaron Cargo, PowerShell, build ni
laboratorio. La clasificación humana permanece sin observar hasta la próxima
corrida diagnóstica Windows.

Antes del dispatch se aplicaron las tres diferencias mínimas de formato
heredadas en el mismo archivo ya afectado; `rustfmt --check` quedó verde sin
refactor semántico. También se corrigió la ubicación de
`human-magic-alpn`: ahora se registra únicamente dentro del branch que ya
comprobó simultáneamente rol humano, ALPN y el MAGIC humano exacto, por lo que
el marcador no puede afirmar un MAGIC inválido. El checker y
`git diff --check` permanecieron verdes; no se ejecutó Cargo ni Windows.

### Bóveda vacía y primer paquete de auditoría (método antes del arreglo)

La corrida diagnóstica Windows 16
[`34841947088`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34841947088)
sobre `9878bc6` observó, en orden, `human-accepted`, `human-magic-alpn`,
`human-unlock-request`, `human-unlock-ok`, `human-unlock-ack` y
`human-lock-request`, pero no `human-audit-open`. Por tanto el canal, MAGIC y
ALPN humanos, la contraseña/KDF y el root ya habían sido aceptados; el fallo
está después de recibir lock y antes de abrir la auditoría autónoma. Esto no es
evidencia de un fallo de I/O o KDF.

La causa común está en el motor, no en Named Pipe. Una bóveda recién persistida
no contiene fila en `audit_keys`. La apertura humana anterior
verifica el canal, abre SQLite y KH, pero no provisiona KAUD ni registra
`human_unlock`. Al soltar esa sesión, tanto Windows como Linux llaman
`AutonomousAuditVault::open`; esta exige una fila coincidente mediante
`load_matching_package` y devuelve `AuditKeyUnavailable` si falta. La primera
operación humana que usa `append_event` sí crearía el paquete porque conserva
KH, pero fabricar contenido antes de lock sólo ocultaría el defecto y no es
parte del laboratorio.

La regresión pública y portable parte de una bóveda realmente vacía. Con la
misma `AuditDeviceCustody` estable debe comprobar:

1. contraseña incorrecta: unlock falla y `audit_keys`, `audit_state`,
   `audit_segments` y `encrypted_audit_records` siguen vacías;
2. contraseña correcta: antes de devolver la sesión se publica atómicamente un
   único paquete y un registro `human_unlock/succeeded` para el dispositivo;
3. tras soltar KH, `AutonomousAuditVault::open` puede registrar
   `human_lock/succeeded`; un desbloqueo posterior permite consultar la
   secuencia `human_unlock`, `human_lock`, `human_unlock`;
4. un fallo sintético de inserción del primer registro hace fallar unlock y
   revierte también paquete, estado y segmento. No se permite una sesión
   desbloqueada sin su evento ni una fila KAUD parcial;
5. después de crear la generación inicial, la apertura autónoma con otra
   custodia falla cerrada y no crea una generación; una custodia de reemplazo
   proporcionada explícitamente a una apertura humana autenticada por KH sí
   conserva la rotación histórica y abre una generación enlazada.

El seam compartido por Linux, macOS y Windows es la única API pública
`HumanVault::unlock(path, password, device, channel, audit_custody)`. Después de abrir KH y revalidar
el canal humano, inicia una transacción SQLite `IMMEDIATE`, obtiene la frontera
de autoridad y llama una sola vez a `append_event` con el root humano,
`HumanUnlock/Succeeded` y la custodia estable entregada por el servicio. Para
el servicio instalado, la transacción debe distinguir ausencia inicial real de
la custodia suministrada. `ensure_package` continúa la generación si coincide;
si la apertura humana autenticada entrega deliberadamente una custodia de
reemplazo, crea la siguiente generación enlazada conforme a
`security-operations.md` §4. Esto no autoriza a la apertura autónoma a rotar:
sin KH, una custodia que no coincide devuelve `AuditKeyUnavailable`. La misma
transacción confirma paquete, evento, estado, segmento y manifiesto antes de
construir la sesión. Cualquier error revierte y mantiene el fallo cerrado. La
contraseña incorrecta no llega a esa transacción y no produce un evento.

El usuario autorizó hacer explícita la custodia estable en la API pública. Se
elimina la variante que generaba custodia aleatoria por llamada y no queda un
alias, cache global, valor sustituto ni ruta sin auditoría. Cada consumidor
mantiene la custodia de su dispositivo y la pasa en todas las reaperturas. La
regresión histórica
`replacing_device_custody_opens_a_linked_audit_generation` permanece positiva:
es reemplazo humano explícito respaldado por KH, no rotación autónoma o
accidental.

Primero se añade el test de estas observaciones a la superficie pública de
`pm-vault`; queda preparado para observar su RED contra el comportamiento
previo cuando se conceda la ventana de ejecución. Sólo
después se implementará el cambio común y se actualizarán las expectativas de
secuencia existentes que ahora empiezan con la primera apertura humana. Los
gates enfocados deberán incluir auditoría, transacciones humanas y el lock
compartido Linux; los gates completos y otra corrida Windows normal siguen
siendo obligatorios. En este checkpoint de método/test estático no se ejecuta
Cargo ni se presenta un GREEN de producto. Los casos nuevos usan una raíz de
fixture propia cuya eliminación se comprueba; no reutilizan ni cambian el
`TestDir::drop` heredado que suprime errores de cleanup.

Con la ventana Linux exclusiva concedida, ambos casos nuevos observaron RED
contra el comportamiento previo. El caso vacío llegó a `query_audit` y recibió
`Storage(QueryReturnedNoRows)` porque no existía paquete; el trigger del primer
registro dejó que unlock devolviera una sesión, incumpliendo el fallo cerrado.
Ambos procesos terminaron 101 y sus salidas se conservaron en
`/tmp/pm27-audit-first-unlock-red-{empty,rollback}.log`.

La primera implementación del plan hizo GREEN esos dos casos. Una corrida
transitoria de `audit_lifecycle` quedó 8/8 sólo después de convertir la
expectativa heredada de rotación implícita en una negativa; ese cambio no
estaba autorizado y se revirtió, por lo que no constituye un GREEN aceptable.
Al ampliar a todo `pm-vault` apareció además un RED distinto y verificable: los
helpers antiguos llaman
la antigua `HumanVault::unlock`, que generaba una custodia nueva en cada llamada. Una segunda
apertura del mismo dispositivo ya no puede coincidir con el paquete estable y
`backup_lifecycle` falla con `AuditKeyUnavailable`. El producto Linux/Windows
ya conservaba custodia estable. La autorización posterior reemplaza ambas
variantes por una sola firma explícita y migra fixtures/consumidores; no se
añade cache, custodia sustituta ni ruta sin auditoría. Hasta ejecutar los gates
enfocados y completos de este candidato, el gate completo sigue sin ser GREEN.

La verificación posterior a la migración se ejecutará en ventana Linux
exclusiva y conservará cada intento por separado. Primero:

1. `cargo test -p pm-vault --test audit_lifecycle` debe cubrir creación inicial,
   reapertura estable, rechazo autónomo de custodia incorrecta, rollback del
   primer evento y la rotación humana enlazada original;
2. `cargo test -p pm-vault --test human_transactions` y
   `cargo test -p pm-vault --test backup_lifecycle` deben probar reaperturas con
   la custodia del fixture sin cambiar la atomicidad de commits/restore;
3. todos los tests de `pm-vault` y `e2ee_replication` deben verificar que la
   firma pública única fue migrada y que no queda un consumidor que genere una
   custodia nueva al reabrir el mismo dispositivo;
4. `scripts/check.sh`, `scripts/clean-offline-build.sh` y los laboratorios TUI
   de contenido/acceso/operaciones deben permanecer verdes para acreditar los
   consumidores CLI/TUI y el canal humano compartido. La corrida Windows STOP
   se repite sólo después de integrar el seam, porque el GREEN Linux no acredita
   SCM, Named Pipe ni DPAPI.

Antes de esa ventana sólo se ejecutan `rustfmt` directo, `git diff --check`, el
checker estático Windows y una comprobación sintáctica de que cada llamada a
`HumanVault::unlock` tiene los cinco argumentos explícitos. Ninguno de esos
checks se presenta como evidencia conductual.

La ejecución enfocada posterior confirmó `audit_lifecycle` 8/8 (incluida la
rotación humana enlazada original), `human_transactions` 4/4 y
`backup_lifecycle` 5/5 en el primer intento. La primera barrida de todos los
tests de `pm-vault` conservada en
`/tmp/pm27-audit-api-pm-vault-tests-attempt1.log` encontró un único RED
conductual: `csv_import` todavía esperaba un solo registro tras el commit y
ahora existen el `HumanUnlock` obligatorio más `Import`. Se corrigió sólo ese
contador 1→2; el test enfocado pasó 3/3 y la segunda barrida completa pasó. El
`e2ee_replication` migrado a custodias estables por dispositivo pasó 5/5. Las
salidas enfocadas están en `/tmp/pm27-audit-api-{audit-lifecycle-attempt1,human-transactions-attempt1,backup-lifecycle-attempt1,csv-import-attempt2,e2ee-replication-attempt1}.log` y la barrida completa verde en
`/tmp/pm27-audit-api-pm-vault-tests-attempt2.log`. Estos resultados son Linux;
no acreditan todavía el servicio Windows nativo.

`scripts/check.sh` conservó dos intentos RED de integración antes del GREEN:
el primero encontró `too_many_lines`/orden de items en fixtures y una closure
redundante; el segundo encontró únicamente dos declaraciones locales colocadas
después de la nueva custodia. Se corrigieron mecánicamente sin cambiar las
aserciones y el tercer intento terminó 0. Los logs son
`/tmp/pm27-audit-api-check-attempt{1,2,3}.log`.
`scripts/clean-offline-build.sh` terminó 0 y está conservado en
`/tmp/pm27-audit-api-clean-offline-attempt1.log`.

Los tres laboratorios TUI enumerados por el método no existen en la base
histórica de esta rama Windows (`266b088`): `crates/pm-custody/tests` aún no
contiene `tui_content_lab.py`, `tui_access_lab.py` ni `tui_operations_lab.py`.
No se sustituyeron por otros labs ni se copiaron desde otro worktree. Deben
ejecutarse después de componer este cambio común sobre la rama unificada que sí
contiene TUI 23–25; hasta entonces esa regresión observable queda pendiente.

## Déficit contractual de parada SCM (plan, no implementación)

La misma corrida mostró `NOT_STOPPABLE` y el cleanup no pudo ejecutar
`Stop-Service`. La causa es directa: `service_main` publica
`dwControlsAccepted=0` y `service_control` devuelve siempre 120. Aceptar STOP
con un booleano y llamar `CancelSynchronousIo` una sola vez no es suficiente:
existe una carrera entre comprobar el booleano y comenzar un nuevo I/O; la
cancelación puede devolver `ERROR_NOT_FOUND` y el hilo bloquearse después.

La realización futura debe usar I/O overlapped y un evento STOP propiedad del
servicio en el mismo wait que cada connect/read/write. Al observar STOP no
inicia otra operación; si una ya está pendiente, usa `CancelIoEx` sobre ese
`OVERLAPPED`, espera y drena su finalización antes de liberar handles. Solo
entonces une ambos hilos, informa `STOPPED` y permite cleanup. El handler acepta
únicamente `SERVICE_CONTROL_STOP`, señala el evento y el servicio anuncia
`SERVICE_ACCEPT_STOP` solo al estar listo; otros controles siguen devolviendo
no implementado. La prueba nativa deberá parar con `Stop-Service` sin `-Force`,
incluido mientras ambos roles esperan conexión, verificar el mismo PID
terminado y luego reiniciar ambos roles. No se autoriza force-kill, polling
arbitrario, conexión sustituta, segundo motor ni ampliación de plazos.

### Método RED y diseño cerrado de la parada

La regresión nativa se coloca antes del primer `human-lock`, para que la
ausencia inicial del paquete KAUD observada por separado no pueda explicar el
resultado de STOP. Después de que SCM publique `RUNNING` y el agente complete
el canal Named Pipe/TLS-RPK normal, el fixture exige `CanStop`, captura el PID,
ejecuta `Stop-Service` sin `-Force`, comprueba `Stopped` y que una consulta CIM
exacta ya no encuentra ese PID. Luego inicia el mismo servicio, exige un PID
nuevo y repite los probes agente y humano con los mismos SIDs, DACL, perfiles y
RPK. El probe humano sólo completa su canal; no desbloquea ni reautentica una
operación externa. Tras el recorrido humano posterior se repite la misma
parada/reinicio, para cubrir tanto threads esperando conexión como una conexión
ya atendida. Sólo después de que ambas paradas SCM hayan pasado se conserva el
caso independiente de crash: mata intencionalmente ese PID, exige que termine,
reinicia y repite ambos probes. Todo error de SCM, consulta, proceso o canal
aborta el lab.

El RED previo es cerrado: sobre `9878bc6`, `dwControlsAccepted=0` y el handler
devuelve `ERROR_CALL_NOT_IMPLEMENTED`, por lo que el primer `Stop-Service` debe
fallar antes de unlock. El `Stop-Process -Force` heredado no era un fallback:
es la inyección deliberada de crash/restart y se conserva como escenario
separado, nunca como alternativa después de STOP fallido. Cleanup usa
`Stop-Service` normal sin `-Force`; el switch de PowerShell ampliaría la
operación a servicios dependientes y no significa terminar a la fuerza el
proceso. Ninguna ruta convierte una parada SCM fallida en éxito. Los
procesos/servicio pertenecen a la raíz única del lab y la limpieza conserva su
agregación de errores.

La corrida nativa RED `34845264907` sobre el método congelado `3dd9d4f`
confirmó ese discriminante: pasaron los cinco tests nativos y el contrato de
pipe, pero SCM informó `NOT_STOPPABLE`; el primer error del cuerpo fue
`RUNNING service did not advertise SERVICE_ACCEPT_STOP` y el fallo posterior
de `Stop-Service` durante cleanup también quedó visible. El log preservado es
`/tmp/pm-windows-stop-native-red.log`. Este resultado acredita la ausencia del
contrato STOP anterior, no la implementación overlapped ni el ticket 27.

La implementación propuesta usa un evento manual-reset de STOP, creado y
cerrado por el runtime del servicio. El contexto estable registrado con
`RegisterServiceCtrlHandlerExW` contiene únicamente ese evento y el status
handle válido. Sólo después de que ambos workers hayan creado su primer pipe y
el contexto esté listo se publica `SERVICE_RUNNING | SERVICE_ACCEPT_STOP`.
`SERVICE_CONTROL_STOP` publica `SERVICE_STOP_PENDING`, deja de aceptar otros
controles y señala el evento; el handler retorna inmediatamente. INTERROGATE
devuelve éxito sin mutar estado y los demás controles devuelven
`ERROR_CALL_NOT_IMPLEMENTED`. Al terminar ambos workers, el hilo de servicio
publica `SERVICE_STOPPED`; un fallo de status, wait, cancel, drain, join o close
queda visible como salida no cero, nunca como STOP correcto.

Cada `WindowsServerPipe` del servicio se crea con `FILE_FLAG_OVERLAPPED`. Un
objeto owned conserva el handle del pipe, un evento manual-reset por operación,
el `OVERLAPPED` y el buffer hasta que esa operación termina. Connect, read y
write inician una sola operación y esperan simultáneamente su evento I/O y el
evento STOP mediante `WaitForMultipleObjects(INFINITE)`: no se introduce un
deadline. Si gana STOP, `CancelIoEx(handle, &overlapped)` solicita cancelar
exactamente esa operación y, incluso si devuelve `ERROR_NOT_FOUND`, el worker
debe obtener/drain su resultado terminal mediante `GetOverlappedResult` antes
de liberar o reutilizar `OVERLAPPED`, evento, buffer o handle. Ese
`ERROR_NOT_FOUND` sólo significa que no encontró una petición cancelable; no
autoriza asumir cancelación ni empezar otro I/O. Si gana I/O, se obtiene y
valida su resultado antes de comprobar STOP y antes de iniciar la operación
siguiente. Por ello no existe ventana `stop flag -> nuevo bloqueo síncrono`.

El mismo wrapper implementa `Read`/`Write` para rustls sin cambiar framing,
ALPN, RPK, DACL o verificación bilateral. En STOP, una conexión parcial termina
con el error opaco existente y no produce audit, intento ni respuesta de éxito;
no se reintenta el request. El dueño desconecta/cierra cada instancia sólo
después del drain y cada handle/evento se cierra exactamente una vez. Los
clientes instalados pueden conservar I/O síncrono: STOP cancela únicamente las
operaciones overlapped de los handles server owned por este proceso.

El diagnóstico opt-in conserva `startup.phases` como historia append-only
durante stop, restart y crash; no trunca ni limpia un log vivo. El parser separa
generaciones por el único `args-ok` de cada proceso, exige una sola copia de
cada fase de inicialización por generación y comprueba que el TLS de cada rol
preceda a su pipe. Dentro de cada generación separa conexiones humanas por
`human-accepted` y valida orden/cardinalidad dentro de cada conexión, permitiendo
el prefijo corto del probe y la secuencia completa de unlock/lock. Así dos
probes no parecen una fase repetida ni ocultan una repetición real. La fase
`human-magic-alpn` acredita aceptación del MAGIC aplicativo después de TLS y
ALPN; no se denomina ni se usa como evidencia adicional de handshake.

Este orden sigue las APIs primarias: Microsoft exige conservar `OVERLAPPED` y
buffer hasta completar la operación y usar un evento para sincronizar
([I/O síncrono y asíncrono](https://learn.microsoft.com/en-us/windows/win32/fileio/synchronous-and-asynchronous-i-o));
`CancelIoEx` no espera la cancelación y requiere consultar el resultado, con
`ERROR_NOT_FOUND` posible
([CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex));
el patrón Named Pipe overlapped obtiene el resultado de toda operación pendiente
([servidor Named Pipe overlapped](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-server-using-overlapped-i-o));
y el servicio debe anunciar STOP, transitar por `STOP_PENDING` y devolver pronto
desde su handler
([transiciones SCM](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions),
[control handler](https://learn.microsoft.com/en-us/windows/win32/services/service-control-handler-function)).

Antes de GREEN, el checker estático exige en el fixture las dos paradas sin
`-Force`, el crash separado, PID terminado/nuevo, probes bilaterales y parsing
por generación/conexión; en producto exige las APIs, flags y estados anteriores
y rechaza `CancelSynchronousIo`, polling, sleeps y timeouts añadidos. Esta
inspección no acredita la carrera: el mismo lab Windows
11 ARM64 debe observar el RED previo y, después del código, STOP antes de
unlock, STOP después de tráfico, reinicio con nuevo PID y ambos canales. Luego
siguen los cinco tests nativos, pipe contract, DPAPI, ConPTY, clipboard, cleanup
estricto y gates completos. Un RED posterior de auditoría vacía permanece un
fallo independiente y no invalida el STOP ya observado, pero impide aceptar el
ticket completo.

El primer checkpoint GREEN estático `d9acde4` hizo pasar el checker de STOP,
pero el primer `scripts/check.sh` posterior terminó antes de Cargo: el guard de
orden del fixture escogía la última lectura diagnóstica de toda la historia,
que ahora pertenece al reinicio posterior, en vez de la primera lectura entre
`human-lock` y su aserción pública. Durante esa inspección también se detectó
que el checkpoint todavía podía ocultar fallos de cierre/drain y dejar un
worker separado en salidas tempranas; por tanto no se considera candidato
nativo.

La corrección mantiene un único evento STOP compartido por ownership `Arc` y
lo cierra explícitamente sólo después de unir ambos workers y publicar siempre
`STOPPED`. Cada evento de operación se cierra en todas las salidas y combina el
error primario con un fallo de cierre; una falla del wait cancela y drena antes
de devolver ambos errores. Los dos roles se preparan por completo antes de
crear threads. Cualquier fallo posterior señala el evento y el padre intenta
ambos `join`; ningún fallo del primer spawn puede dejar un worker y ningún
fallo del segundo evita unir el primero. El guard del fixture ahora selecciona
la primera lectura diagnóstica posterior a `human-lock`, conservando las
lecturas append-only posteriores. `rustfmt`, ambos checkers estáticos, `sh -n`
y `git diff --check` pasan; Cargo y Windows siguen pendientes de una nueva
ventana/ejecución.

La composición mueve cada `WindowsServerPipe` preparado desde el hilo de
arranque hacia un único worker. Como `HANDLE` es un puntero opaco y no obtiene
`Send` automáticamente, el backend declara únicamente `Send`, no `Sync`: el
objeto conserva ownership exclusivo, no ha iniciado I/O antes del movimiento y
sus duplicados posteriores permanecen dentro del mismo worker para rustls y la
lease humana. Una regresión de trait en el módulo Windows exige esta propiedad
sin construir un handle sintético. La ejecución nativa sigue siendo necesaria
para validar el contrato operativo.

Sobre `5d64bc2`, `scripts/check.sh` y `scripts/clean-offline-build.sh` pasaron
con salida cero; sus logs son `/tmp/pm27-windows-stop-check-5d64bc2.log` y
`/tmp/pm27-windows-stop-clean-5d64bc2.log`. Esos gates compilaron únicamente el
`cfg` Linux y no acreditan el backend Windows. La corrida nativa
`34848390243`, publicada sobre ese checkpoint, fue cancelada al detectarse por
inspección el trait `Send` ausente, antes de obtener un log que demostrara un
RED de compilación o comportamiento; no se registra como tal. La siguiente
corrida debe identificar exactamente `0a0ec3d`, que añade el contrato de
movimiento único, y volver a ejecutar todo el método nativo.

La corrida nativa `34848533955` sobre producto exacto `0a0ec3d` compiló el
backend Windows ARM64 y pasó los seis tests nativos —incluida la regresión
`Send`— y el contrato de pipe (6+1). En el cuerpo, las aserciones alcanzadas
demuestran: servicio inicial `RUNNING` y `CanStop`; probe agente inicial;
`Stop-Service` antes de unlock; registro SCM `Stopped`, PID cero y ausencia del
PID anterior; arranque con un PID distinto; probes agente y humano posteriores;
y unlock humano hasta `human-unlock-ack`. El intento llegó después a
`human-lock-request` y falló `CUSTODY_UNAVAILABLE` sin `human-audit-open`, el
límite `AuditKeyUnavailable` ya aislado en una bóveda inicialmente vacía.

No se ejecutaron las aserciones posteriores al `human-lock`: sustitución
cross-role, invariancia del PID tras tráfico, segundo STOP/restart, probes tras
ese segundo restart ni el crash/restart deliberado. El diagnóstico append-only
contiene exactamente las dos generaciones esperadas, inicial y restart. Las
tres apariciones de `phase=args-ok` en el log de consola no son tres procesos:
la lectura de las 13:23:01 imprimió la primera generación, y la lectura de las
13:23:19 volvió a imprimir esa historia completa seguida de la segunda. El run
no alcanzó la aserción posterior que habría comparado explícitamente el PID en
uso con el PID devuelto por el restart; se conserva esa comprobación posterior
como no ejecutada, sin inventar un restart adicional.

El `finally` sí se ejecutó: el log muestra `DeleteService SUCCESS`, seguido por
la reparación ACL completa hasta cada hoja; `Remove-LocalUser` y cada
`Remove-Item -ErrorAction Stop` retornaron sin alimentar `cleanupErrors`, y no
apareció el fallo STOP que afectó corridas anteriores. Sin embargo, el harness
no consulta de nuevo SCM, usuarios ni `Test-Path $root` después de borrarlos:
por eso el run acredita que las operaciones de cleanup se alcanzaron y
retornaron éxito, pero no una comprobación independiente de ausencia final.
El resultado global permanece FAIL por auditoría; no se declara ticket 27 ni
STOP completo.

### Composición STOP + apertura auditada (checkpoint estático)

El merge `c71cee1` tiene exactamente los padres STOP/evidencia
`f47affea8f4da50d7ddbac8f944cb54454d92c0b` y API/custodia auditada
`360f5b33abee46130db363fe56385b3f2b8ed313`. Conserva Named Pipe overlapped,
evento STOP, `CancelIoEx` con drain, estados SCM y los escenarios STOP/crash
del primer padre; del segundo conserva una sola API pública
`HumanVault::unlock` con custodia estable explícita y la rotación humana
autenticada que abre una generación enlazada. La apertura autónoma con custodia
incorrecta continúa fallando y no rota.

Sin ejecutar Cargo, el checker Windows, `rustfmt --check` directo y
`git diff --check` pasaron. Esta composición es sólo candidato para la próxima
corrida nativa: siguen pendientes el lock auditado sobre bóveda vacía, STOP
posterior a tráfico, sustitución cross-role, reinicio/crash, comprobación final
de ausencia de recursos y la composición TUI 23–25. No se declara completo el
ticket 27.

Antes de esa corrida se extiende el harness, sin cambiar cómo elimina recursos:
después de intentar todo el cleanup propio, una consulta SCM con errores
terminantes debe confirmar que no queda el nombre exacto del servicio; una
enumeración exitosa de usuarios locales debe confirmar la ausencia de los dos
usuarios exactos; y `Test-Path -ErrorAction Stop` debe confirmar que no queda la
raíz propia. Cada error de consulta o presencia residual se agrega a
`cleanupErrors`, junto con el error primario si existe. No se reintenta, no se
fuerza otro borrado y no se inspecciona ni modifica un recurso ajeno. El checker
estático exige la función y su llamada posterior al cleanup, pero sólo Windows
nativo acredita las tres ausencias.

### Resultado nativo de la composición base

La corrida Windows 11 ARM64
[`34853430364`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34853430364)
sobre el producto exacto `50dd1bf` terminó verde. La fuente libsodium
autenticada compiló con MSVC; pasaron seis tests nativos y el contrato de pipe.
El servicio completó `human-unlock-ok/ack`, `human-lock-request`,
`human-audit-open/append` y `human-lock-ack`; después alcanzó ambos STOP/restart,
el crash deliberado y los probes bilaterales. El harness imprimió su PASS sólo
después de que las consultas terminantes confirmaron ausencia del servicio, los
dos usuarios y la raíz propia. El log completo está preservado en
`/tmp/pm-windows-composed-run18-full.log`.

Esto cierra el RED de bóveda vacía y la carrera STOP para esta composición, no
el ticket 27 completo. La corrida no lanzó la TUI, no adjuntó un proceso a
ConPTY, no ejercitó clipboard desde una sesión humana, no cubrió x64/reboot/FDE
ni acredita Windows Terminal visible.

### Propuesta de seam único para TUI Windows 23–25

La superficie actual aún no puede satisfacer el método. `windows::run` sólo
ofrece `service`, `probe` y `human-lock`; su servidor humano acepta únicamente
unlock seguido de opcode 14. La TUI completa y los opcodes 46/51–79 viven en
`linux/tui.rs` y `linux.rs`, con tipos concretos `UnixStream`, `/dev/tty`,
`wl-copy` y `SCM_RIGHTS`. `ConPty` sólo crea/redimensiona una pseudoconsola; no
lanza el binario mediante `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`. Por tanto los
tests actuales de `ConPty` y `OwnedClipboard` prueban primitivas, no composición
humana.

La extracción propuesta mantiene un solo motor, protocolo, modelo y keymap:

1. `human_wire` contiene el dispatch humano 1–79, `FrameReader`/`FrameWriter` y
   el estado común necesario (bóveda, auditoría, autoridad y trabajos sync).
   Se parametriza sobre un stream `Read+Write` y una interfaz estrecha de
   transferencia nativa; Linux y Windows sólo autentican su canal y entregan
   el stream TLS al mismo dispatch. No se copia el match de opcodes en
   `windows.rs`.
2. `tui` contiene `App`, modos, render, keymap, confirmaciones, timers y loop de
   eventos actuales. Un adaptador de plataforma suministra: conexión humana
   TLS (`UnixStream` o `WindowsClientPipe`), terminal propio, lease de clipboard
   y operaciones de fichero. Crossterm/Ratatui siguen siendo la única UI.
   Linux conserva `/dev/tty`; el proceso Windows usa los handles estándar que
   le entrega ConPTY. Ambos conservan la misma taxonomía pública
   `INVALID_ARGUMENT`/`CUSTODY_UNAVAILABLE` y los errores de operación visibles.
3. El clipboard común expone sólo `copy_owned(bytes)` y
   `clear_if_owned(lease)`. Linux conserva el proceso `wl-copy`; Windows usa
   `OwnedClipboard` y su HWND/sequence bajo el lock existente. La pérdida de
   owner devuelve “limpieza no confirmada” y nunca borra contenido posterior.
   No se emite OSC52 ni se sustituye clipboard por stdout.
4. Descargas/exportaciones/restores ya viajan en frames acotados; el adaptador
   Windows debe crear destino nuevo con DACL humana, escribir incrementalmente,
   `FlushFileBuffers` y publicar atómicamente con el seam durable nativo. Un
   destino existente o fallo de flush/publicación falla sin truncar ni usar
   otro path. CSV conserva su límite confirmado y restore/attachments no se
   materializan en un frame grande.
5. El único caso `SCM_RIGHTS`, el 1PUX ya abierto, requiere transferencia nativa
   del mismo objeto File. La propuesta Windows envía el valor del handle por el
   TLS humano y el servidor, ligado al PID/SID ya autenticado del Named Pipe,
   impersona sólo para abrir ese proceso con `PROCESS_DUP_HANDLE` y ejecuta
   `DuplicateHandle` hacia sí mismo. Después valida tipo, reparse, identidad,
   links, DACL y tamaño en el handle duplicado y `pm-vault` vuelve a comprobar
   identidad/digest al consumirlo. Si cualquier permiso o identidad no
   coincide, falla; no copia a un temporal, no reabre por path y no cambia a
   streaming como fallback.
6. `pm-sync` es actualmente `cfg(target_os="linux")` y usa Unix sockets. La TUI
   Windows no puede marcar pairing/sync verde hasta que el mismo protocolo
   opaco TLS-RPK tenga un transporte Windows primario (Named Pipe local con
   identidad bilateral y ACL cerrada, o un transporte remoto ya confirmado).
   Ese transporte implementa la interfaz existente de `SyncTransport`; no crea
   otro ledger, no cambia backoff y no convierte offline en éxito.

El método nativo TDD debe fallar primero porque el binario normal todavía no
expone `tui`, no por una herramienta ausente. Un launcher test-only crea pipes
propios, `ConPty(80x24)` y un proceso `pm-custody.exe tui` real mediante
`STARTUPINFOEXW`; espera texto visible antes de cada tecla, redimensiona a
42x12 y 100x30 y une/cierra proceso, HPCON y handles con errores visibles. La
misma sesión recorre los siete tipos/campos y selección sin secreto, autoridad
y pendientes, import/export/backup/restore/rotaciones, pair/sync/offline/retire,
auditoría/purga y attachment mayor de 16 MiB, comprobando resultado durable en
el motor. Contraseña, canarios y controles no aparecen en la captura VT; no hay
OSC52.

Para copy se selecciona un campo exacto, se lee `CF_UNICODETEXT` desde la sesión
humana, se comprueba expiración y luego se publica una selección sintética con
otro owner: timeout/lock deben conservarla. Un proceso agente intenta leer en
paralelo y no obtiene el secreto. Como el clipboard de Windows pertenece a la
window station/session y no al SID, el fixture debe crear una estación/sesión
humana de vida acotada con DACL explícita y lanzar allí TUI, lector e interloper;
el agente queda fuera. Si el runner no puede crear o validar ese aislamiento,
el lab falla: Named Pipe DACL no se presenta como aislamiento de clipboard y
no se toca la sesión interactiva del usuario. El runner hosted headless puede
acreditar ConPTY real, pero no Windows Terminal visible; esa diferencia queda
explícita.

Éxito requiere además cleanup estricto y ausencia comprobada de proceso TUI,
HPCON, handles, window station, servicio, cuentas y raíz. Luego se repiten los
tests nativos, checker, build/check completo y el lab Windows. No se declara
TUI ni ticket 27 por tests unitarios de las primitivas.

### Primer RED nativo de la composición TUI

Antes de extraer código de producto se añade un único tracer del seam público:
el binario normal `pm-custody.exe tui`. El fixture se compila como `example` de
test de `pm-native-channel`, se copia a la raíz humana propia y se ejecuta con
la cuenta humana sintética; no es un segundo binario de producto. El launcher:

1. crea dos pipes anónimos propios y una `ConPTY(80x24)` real;
2. crea con `CWF_CREATE_ONLY` una window station privada para ese logon y un
   desktop propio, ambos con DACL protegida que sólo concede `SYSTEM` y el SID
   humano, y falla ante colisión o si no puede recuperar/validar su nombre;
3. lanza el `pm-custody.exe` normal mediante `CreateProcessW`,
   `STARTUPINFOEXW`, `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` y el desktop propio;
4. cierra inmediatamente los extremos host cedidos a ConPTY tras crear el
   proceso y drena el output en un hilo dedicado hasta EOF. Este primer RED no
   interpreta ni guarda VT: sólo cuenta hasta 1 MiB, continúa drenando si se
   excede y convierte exceso o salida vacía en fallo explícito;
5. exige sólo liveness del proceso durante los 15 segundos del plazo humano ya
   existente. El binario actual debe salir por el subcomando `tui` ausente; un
   proceso vivo con output presente vuelve verde este tracer, pero todavía no
   se denomina pantalla lista ni input visible;
6. ante cualquier resultado, cierra el input propio y llama una sola vez a
   `ClosePseudoConsole` mientras el hilo sigue drenando. Conserva el handle del
   proceso hasta comprobar su terminación, une el drainer y sólo entonces
   cierra process/thread/pipes/desktop/window station. `ClosePseudoConsole` es
   el teardown primario documentado, no se añade `TerminateProcess`, relaunch ni
   sustitución de ConPTY por redirección.

Microsoft documenta que los atributos extendidos de proceso requieren
`STARTUPINFOEX` y `EXTENDED_STARTUPINFO_PRESENT`, y que una pseudoconsola debe
publicarse pasando el valor `HPCON` directamente como `lpValue` de
`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, no la dirección de una variable que lo
contiene. La guía exige cerrar los extremos cedidos tras `CreateProcess` y
mantener el output drenado concurrentemente durante `ClosePseudoConsole` para
no bloquear el teardown. También documenta
que una window station creada sin descriptor concede acceso amplio; por eso el
fixture no admite descriptor nulo ni reutiliza `winsta0`:
<https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session>,
<https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-createwindowstationw>.

La corrida RED autorizada usa el mismo Windows 11 ARM64 efímero y prerequisitos
del lab base, con un switch explícito `-TuiConPtyRed`. Debe cruzar primero los
seis tests nativos, pipe contract, servicio y probes existentes. Después el
launcher debe llegar al `CreateProcessW` del binario normal y el lab debe fallar
porque `pm-custody.exe tui` sale antes del intervalo de liveness, con
output ConPTY presente pero no expuesto, no por herramienta, ACL, estación,
ConPTY o proceso ausentes. El log no puede contener la contraseña sintética ni
captura VT. La limpieza y comprobación de ausencia existentes se ejecutan
incluso en RED.

Este primer tracer no acredita pantalla, teclado, resize, flujos 23–25,
clipboard ni aislamiento negativo del agente. Tras observar el RED correcto,
el siguiente tracer añade un observer test-only verificable; sólo entonces
espera `keyboard-ready`, envía `q` y exige salida, y un tracer posterior exige
redraw real de `42x12`/`100x30`. La misma estación se ampliará con
lector/interloper humanos y un proceso agente que debe fallar al abrirla; nunca
usa la estación interactiva real. No se escribe código de producto hasta
preservar este RED nativo.

La corrida Windows 11 ARM64
[`34857970004`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34857970004)
sobre `7998ebab731233bf2ba362065c60b03c8f5bf330` preservó ese RED. Los seis
tests nativos y el contrato de pipe pasaron; el launcher creó la estación
privada, la ConPTY y el proceso normal, y observó output de producto. El primer
fallo fue exactamente `INVALID_ARGUMENT TUI_CONPTY_RED pm-custody.exe tui
exited 2 before 15-second liveness interval; conpty-product-output=present`.
Por tanto el fallo no fue compilación, ACL, creación de estación/ConPTY ni
ausencia de output: el binario normal aún no aceptaba `tui`. El cleanup eliminó
el servicio y los recursos propios sin error agregado; las comprobaciones
terminantes de ausencia se ejecutaron silenciosamente antes de volver a
propagar el error corporal. El log completo está preservado en
`/tmp/pm-windows-tui-red-run19-full.log`.

### Método del primer GREEN observable de TUI compartida

La base TUI 23–25 se compone primero mediante merge normal del commit unificado
`d57a707b2bab3d4e1f0e3109835e8bf7947939b5`; la resolución conserva tanto la
durabilidad nativa Windows como el estado publicado explícito de los errores de
cleanup. La extracción posterior debe mover el modelo, render, keymap y
dispatch humano existentes a módulos comunes. Los módulos de plataforma sólo
pueden aportar transporte autenticado, terminal, clipboard y transferencia de
ficheros; no pueden copiar el `match` de opcodes ni sustituir una operación no
disponible.

Antes del primer GREEN nativo el fixture deja de usar liveness como oráculo de
UI. Un observer test-only consume todos los bytes UTF-8 de ConPTY y mantiene una
pantalla 80x24: aplica texto Unicode, CR/LF/backspace y únicamente las
secuencias CSI/DEC que emite el backend verificado. Bytes UTF-8 inválidos,
parámetros vacíos ambiguos, secuencias no soportadas, coordenadas fuera de
pantalla o captura superior al límite son errores categóricos; no se eliminan
escapes ni se reemplazan glifos. El drainer continúa hasta EOF aunque el
observer falle para no bloquear `ClosePseudoConsole`.

El test espera en esa pantalla reconstruida el título y el estado inicial
`Password required`; envía el primer byte sintético y sólo continúa cuando la
pantalla cambia a `Password required (input hidden)`, acreditando que el input
no se dibuja. Después completa la contraseña, espera `Unlocked: selection never
reveals secrets` y el catálogo de metadatos antes de enviar `q`; exige salida
natural con código cero antes de iniciar `ClosePseudoConsole`, además del lock
auditado y teardown completo. La
captura conservada por el observer nunca se imprime y se comprueba que no
contenga contraseña, secreto ni canario sintético. Sólo este recorrido acredita
teclado y pantalla reales; el tracer previo de 15 segundos queda como evidencia
RED, no como aceptación. Resize, clipboard, transferencia Windows y todos los
flujos 23–25 permanecen tracers posteriores y no se declaran por este primer
GREEN.

La primera corrida del observer,
[`34860222525`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34860222525)
sobre `33fcff71a684cc4fb4ea7cc01aaab9fd84decf6a`, no llegó al launcher ni al
producto. En `cargo test -p pm-native-channel --all-targets`, el caso Unicode
pasó y los dos negativos fallaron porque el propio test hizo `unwrap` del
`Err` inmediato y correcto de `feed` para OSC no soportado y UTF-8 inválido.
El harness intentó todo su cleanup propio sin error agregado y terminó con el
error primario `cargo failed (101)`. Esto es un RED de la aserción del fixture,
no evidencia de pantalla/teclado ni una regresión de producto. El log completo
está en `/tmp/pm-windows-tui-observer-red-run20-full.log`; la corrección exige
directamente esos dos `Err` sin cambiar parser, producto ni plazos.

La segunda corrida del observer,
[`34861192989`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34861192989)
sobre `6e9f354f228bf9f17cdb93d5610f05f4dd51d74a`, tampoco llegó al launcher:
pasaron los seis tests nativos, el contrato de pipe y los tres tests del parser,
pero la composición de `pm-custody` encontró ocho errores de compilación en
`pm-sync`. El crate importaba `OpenOptionsExt` Unix sin `cfg`, usaba
`O_CLOEXEC|O_NOFOLLOW` y aplicaba `.mode(0o600)` en cinco temporales. Es un
fallo de precondición de portabilidad introducido al componer la base TUI, no un
RED de pantalla ni teclado. El cleanup propio terminó sin error agregado. El
log está preservado en `/tmp/pm-windows-tui-observer-red-run21-full.log`.

El arreglo mínimo no elimina ni condiciona fuera `pm-sync`. Se añade al seam
nativo una creación exclusiva de fichero privado (DACL protegida, sólo SYSTEM
y owner; sin handle heredable) y una apertura de fichero regular que no sigue
el componente reparse final. `pm-sync` usa esas dos operaciones en todos sus
temporales/outputs y conserva en Unix los modos 0600 y `O_CLOEXEC|O_NOFOLLOW`.
Los tests nativos deben comprobar create-new/colisión, DACL protegida, rechazo de
reparse y que un output sólo se publica después de flush+rename; cualquier
imposibilidad de consultar la seguridad o identidad es error, no una apertura
menos protegida. Después se repiten los tests nativos y el lab completo; sólo
entonces el observer puede producir el RED de producto esperado.

La corrida
[`34862625148`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34862625148)
sobre `7f5aeece266368d98c7343b03871cd56cbf48d8e` cerró esa precondición:
compilaron `pm-sync` y `pm-custody` en Windows, y pasaron 8 tests nativos más
los grupos 1/1 y 3/3 de ejemplos. El observer alcanzó el proceso normal pero
rechazó una secuencia CSI privada que su gramática cerrada aún no reconoce.
Por tanto tampoco es un RED de pantalla del producto. El cleanup del fixture y
el cleanup/chequeo de ausencia del lab se ejecutaron; el error agregado del
fixture repite el fallo del observer, no identifica un recurso residual. El log
completo está en `/tmp/pm-windows-portfs-observer-run22-failed.log`.

Para obtener el discriminante sin exponer pantalla, input ni bytes crudos, el
rechazo de CSI privada informará solamente la lista numérica de modos, su
cardinalidad y el byte final ASCII. El parser seguirá rechazando el opcode: el
diagnóstico no lo ignora ni lo incorpora a la pantalla. Una regresión fija debe
comprobar esa gramática pública cerrada. La siguiente corrida clasificará el
modo concreto antes de decidir si su semántica debe implementarse.

La corrida
[`34863382975`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34863382975)
sobre `10558e2a75c8a25fdaa83b056aa98f7f90b2c7e5` pasó 8/8 tests nativos,
1/1 del contrato pipe, 4/4 del observer y 1/1 de `pm-sync`. El discriminante
nativo fue exactamente `modes=[9001] count=1 final=0x68`, es decir,
`CSI ? 9001 h`; no se alcanzó todavía un oráculo de pantalla del producto.
El cleanup y el chequeo de ausencia no agregaron otro error. El log está en
`/tmp/pm-windows-conpty-private-csi-run23-failed.log`.

La especificación primaria de Microsoft Terminal define
[`CSI ? 9001 h/l` y el wire de `KEY_EVENT_RECORD`](https://github.com/microsoft/terminal/blob/main/doc/specs/%234999%20-%20Improved%20keyboard%20handling%20in%20Conpty.md):
virtual key, scan code, unidad Unicode UTF-16, down/up, estado de control y
repeat count. Su parser clasifica la reinyección requerida por ConPTY como
[`W32IM`](https://github.com/microsoft/terminal/blob/main/src/terminal/parser/stateMachine.hpp).
El observer modela `9001 h/l` como estado de input sin alterar las celdas y el
writer test-only consulta ese estado antes de cada input. En modo activo emite
pares down/up completos; en modo inactivo emite el UTF-8 normal. No hay
fallthrough tras un error de codificación o mapeo. Los tests verifican
activación/desactivación, pantalla inalterada, campos de tecla y que otros modos
privados continúen rechazados.

La corrida
[`34864402493`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34864402493)
sobre `a6ddb893235204d05518525c958ca2aa8274f995` pasó 8/8, 1/1, 6/6 y
1/1 en esos mismos grupos. El writer W32IM ya no fue el bloqueo: el siguiente
rechazo cerrado identificó `modes=[1004] count=1 final=0x68`. El producto no
se alcanzó aún. El cleanup/ausencia terminó sin un error independiente; log
completo en `/tmp/pm-windows-conpty-w32im-run24-failed.log`.

Microsoft Terminal clasifica en el mismo parser primario `CSI ? 1004 h` como
`DECSET_FOCUS`. El observer modela de forma separada `1004 h/l` como el estado
que habilita reportes Focus In/Out; no altera la pantalla ni inventa eventos de
foco para esta sesión estable. Cualquier otro modo privado sigue fallando.

La corrida
[`34866591723`](https://github.com/SantanaJcp/passwordmanager/actions/runs/34866591723)
sobre `9e50f5184c390ae1a6b649d4bb4965a967705257` no llegó al producto: seis
tests del observer pasaron y `observer_classifies_private_csi_without_screen_content`
falló porque su dato negativo aún combinaba 9001 y 1004, ambos ya soportados.
Es un fallo de fixture, no un RED del TUI. La regresión usa ahora el modo
cerrado 7777 para conservar el rechazo de un privado realmente desconocido.
Log preservado en `/tmp/pm-windows-conpty-focus-run25-failed.log`.

El primer checkpoint de producto separó la transferencia 1PUX del tracer de
catálogo. Una propuesta intermedia intentó abrir el proceso de servicio desde
el cliente/impersonación de nivel `SecurityIdentification`; se retiró antes de
la siguiente publicación porque ese nivel sólo permite consultar identidad y
porque una revalidación temprana podía abandonar el handle de proceso. No se
considera primitive operativa ni evidencia. El contrato pendiente conserva
`PROCESS_DUP_HANDLE` mínimo, PID observado por la pipe y cierre comprobado en
todas las ramas; no se ampliará el token humano a administrador ni se usará una
copia temporal sustitutiva.

La sincronización del directorio Windows reutiliza el contrato ya integrado en
`pm-vault::native_fs`: abre el directorio exacto con `GENERIC_READ |
GENERIC_WRITE`, `BACKUP_SEMANTICS | OPEN_REPARSE_POINT`, verifica tipo e
identidad y sólo entonces hace `sync_all`. Un handle de sólo lectura no acredita
`FlushFileBuffers` y queda excluido.

### Método de transferencia 1PUX por handle en Windows

La transferencia Windows no reabre un path ni concede derechos sobre el
servicio. Sólo después de autenticar Named Pipe + TLS-RPK y recibir el `ready`
del opcode 31, la TUI instala durante una única transferencia un ACE no
heredable para el SID fijo `NT SERVICE\\PasswordManager` sobre el DACL de su
propio proceso. El ACE concede exactamente `PROCESS_DUP_HANDLE |
PROCESS_QUERY_LIMITED_INFORMATION`; este derecho sigue siendo potente y el SID
del custodio forma parte del TCB porque `DuplicateHandle` puede duplicar otros
handles del proceso. Nunca se concede al agente ni al humano sobre el servicio.

El servidor usa el PID observado por `GetNamedPipeClientProcessId`, revalida el
SID/PID y abre exclusivamente ese proceso. El cliente envía por el TLS ya
autenticado el valor de su handle abierto; el servidor lo duplica hacia sí,
revalida el peer y comprueba sobre el mismo handle tipo regular, ausencia de
reparse, identidad, número de links y tamaño antes de entregarlo al procesador
1PUX común. Todos los handles tienen ownership único y cierre comprobado en
todas las ramas.

El lease conserva el descriptor original y el DACL instalado. Al terminar la
transferencia consulta el DACL actual: sólo restaura el original si sigue siendo
exactamente el que instaló. Si otra parte lo cambió, falla y termina la TUI sin
sobrescribir el cambio ajeno, sin retry. Error de query, instalación,
duplicación, validación, cierre o restauración es fallo explícito; no se copia a
un temporal, no se reabre por nombre y no se transmite el fichero como ruta o
como alternativa degradada.

Las regresiones nativas deben cubrir DACL antes/durante/después, SID agente sin
ACE, peer impostor, PID cambiado, pseudohandle/source inválido, reparse/link y
cambio concurrente del DACL. El caso positivo procesa un 1PUX sintético mayor
que un frame desde el mismo handle. Ningún test modifica el DACL de un proceso o
sesión ajenos; el fixture usa exclusivamente el proceso TUI propio efímero.
