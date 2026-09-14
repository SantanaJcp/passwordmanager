# Ticket 27 — composición Windows pendiente de ejecución nativa

Fecha: 2026-09-13. Estado: **implementación sin acreditar, no candidato
aceptado**. Este documento no acredita Windows ni resuelve el ticket. No se
ejecutó Windows, no se instaló servicio y no se modificó el host Linux.

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
