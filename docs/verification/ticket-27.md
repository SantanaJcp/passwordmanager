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
