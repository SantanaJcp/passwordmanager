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
`cargo fetch --locked` y solo entonces entra al lab con builds `--offline`.
No se ha publicado ni despachado desde este worktree.

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
./scripts/cargo-local.sh test -p pm-native-channel --all-targets --locked --offline
# 1 passed; exit 0 (contrato puro SDDL/nombres)

RUSTFLAGS='--cfg target_os="windows" -Aexplicit_builtin_cfgs_in_flags' \
  ./scripts/cargo-local.sh clippy -p pm-native-channel --all-targets --locked --offline -- -D warnings
# exit 0; chequeo sintáctico cfg únicamente, no target ni runtime Windows

# Comprobación estática enfocada tras el hardening
# PASS: guard CI, workflow flag, target/debug/pm.exe, colisiones previas,
# ownership por recurso, cleanup visible y PASS posterior (exit 0)

git diff --check && ./scripts/check.sh
# exit 0
```

El host Linux no dispone de `pwsh`; solo se comprobó balance de delimitadores
del script, además del chequeo estático anterior. La sintaxis PowerShell real y
el comportamiento de cleanup continúan pendientes de la ejecución Windows
nativa, sin inferirse del chequeo Linux.

## Pendiente que bloquea aceptación

Falta compilar y ejecutar el producto y el script en Windows 11 ARM64. El
preflight corregido `34763094631` pasó 5/5 y observó Windows 11 Enterprise
10.0.26200, imagen `win11-vs2026-arm64 20260907.151.1`, PowerShell/PE ARM64 y
Rust 1.98.1 host `aarch64-pc-windows-msvc`; `EnableLUA=1` y el token del runner
pasó la comprobación de administrador. Fue solo entorno, no ejecutó producto.
Además,
`libsodium-sys-stable 1.24.0` contiene en su `build.rs` un fallback existente:
si falla `install_from_source()` en MSVC, activa
`extract_libsodium_precompiled_msvc()` y sustituye la compilación del tarball
fijado por `libsodium-1.0.22-stable-msvc.zip`. `SODIUM_DIST_DIR` fuerza entrada
local y ese zip no existe, así que hoy el build falla explícitamente; no se
añadió el zip ni se cambió el fallback sin autorización. Windows 11 x64
estándar no está disponible. Reboot/FDE, Windows Terminal humano real y firma
permanecen en 32/34. Por ello el ticket conserva `Status: claimed` y ningún
criterio de aceptación se marca completo.

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
