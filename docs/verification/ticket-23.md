# Ticket 23 — método y evidencia de verificación TUI de contenido

## Método escrito

Entorno probado: Linux x86_64 del host autorizado, Rust 1.98.1 local del
repositorio, `tmux` con PTY real, terminal Crossterm/Ratatui por `/dev/tty` y
Wayland humano real con `wl-clipboard 2.3.0`. El laboratorio se ejecuta en un
user+mount namespace desechable con identidades kernel distintas para humano,
custodio y agente. La copia exacta del helper fijado se monta sobre
`/usr/bin/wl-copy` **solo dentro de ese mount namespace**, para conservar la
comprobación de propietario root sin modificar el host ni relajar el producto.

Prerrequisitos:

- toolchain raíz ya aprovisionado mediante `scripts/cargo-local.sh`;
- `/usr/bin/tmux`, `/usr/bin/wl-copy` y `/usr/bin/wl-paste` ejecutables;
- sesión Wayland humana accesible al UID humano del laboratorio;
- rangos `/etc/subuid` y `/etc/subgid` para el usuario del host;
- ningún secreto real: todas las claves, contraseñas y canarios son sintéticos.

Criterio de éxito: el cliente TUI real debe abrir el motor real mediante el
canal humano TLS 1.3/RPK, rechazar una maestra incorrecta sin revisión ni audit
de éxito, operar por teclado los siete tipos y todos sus descriptores de campo,
búsqueda/organización/generador/historia/papelera/restauración/purgas, y probar
lock/idle/reveal/copy con los plazos G7. Seleccionar un elemento o un descriptor
no puede transferir su valor. Reveal/copy requieren elegir el campo exacto. El
PTY debe seguir usable a 80x24, 42x12 y 100x30; Unicode se conserva y controles
inyectados no se ejecutan como OSC52. La carrera clipboard debe conservar la
selección posterior de otra aplicación y el UID agente no puede leerla.

Compatibilidad de regresión: deben pasar `scripts/check.sh`, el build limpio
locked/offline y todos los laboratorios Linux integrados. Éxito significa exit
0 sin skips, stubs de motor ni sustitución por mocks. Esta evidencia acredita
solo Linux x86_64; los otros cinco targets y empaquetado pertenecen a tickets
posteriores.

## TDD red → green observado

Los rojos fueron fallos del comportamiento público, no ausencia de una
dependencia:

1. El primer laboratorio no podía provisionar el bootstrap porque los
   directorios de claves públicas no eran atravesables por el custodio. Se
   conservaron privadas 0400 y se expuso solo la travesía necesaria a las
   públicas, como en los laboratorios integrados.
2. La primera ejecución del generador cerró la TUI con
   `CUSTODY_UNAVAILABLE`: el cliente interpretó incorrectamente el framing
   histórico de opcode 13. El flujo final de TUI usa su operación reservada 50,
   que recibe configuración, genera primero, registra reveal solo tras éxito y
   devuelve un campo length-prefixed validado; no deja audit de éxito si falla
   RNG o la configuración.
3. Tras organizar o mover a papelera, `refresh` cambiaba silenciosamente la
   selección al primer ítem; la prueba esperaba historia de la nota y recibió
   historia de otro elemento. El catálogo conserva el ID seleccionado si
   sigue presente.
4. La validación real de `/usr/bin/wl-copy` rechazó correctamente al root del
   host visto como UID no mapeado dentro del user namespace. El laboratorio no
   debilitó esa validación: añadió un mount namespace privado y bind-mount de
   los mismos bytes fijados, propiedad del root mapeado.
5. El corte inicial `r/c` elegía implícitamente un único valor y no podía
   seleccionar campos `source`, custom, múltiples auth ni attachments. La
   superficie 51–53 ahora lista únicamente label/tamaño, exige selección
   explícita y solo entonces entrega el valor elegido con audit reveal/copy.
6. Al componer la base unificada, `AuthRecord::TokenExchange` produjo RED
   `E0004` tanto en el catálogo de campos como en el fallback heredado
   `primary_human_secret`. El catálogo ahora enumera subject token, cliente,
   secreto requester, proveedor, perfil, destinos y expiración. La superficie
   pública comprueba que 47/48 se rechazan; se retiraron esos opcodes y el
   helper completo, y reveal/copy existen solo como 51–53 con índice explícito.
   Las notas siguen siendo un campo elegible y el lab las revela por su índice,
   no como sustituto de un secreto ausente.
7. La primera corrida integral de 18 labs dejó la TUI con `Input: keyboard-0`
   todavía visible y agotó la espera de `Organization committed`: dos clientes
   `tmux send-keys` consecutivos no acreditaban que Crossterm ya hubiera
   consumido y renderizado el texto antes de enviar Enter. El harness ahora
   espera el eco visible exacto del input en el PTY antes de Enter. No reintenta
   la operación, no aumenta deadlines y no aplica esta observación a la maestra
   oculta. El lab enfocado y la siguiente corrida integral pasaron.

Comando enfocado actual:

```text
./scripts/test-linux-tui-content-lab.sh
PASS tui-content types=7 fields=explicit-complete token-exchange-fields=subject+requester notes=explicit legacy-exposure=rejected type-mutations=7 wrong-password=unchanged tls-rpk=1 keyboard=1 pty=1 terminal=linux resize=80x24+42x12+100x30 unicode=1 controls=sanitized osc52=absent selection-secret=absent reveal-expiry=1 idle-lock=1 clipboard=wl-copy-2.3.0 clipboard-race=preserved hostile-agent=denied history=1 trash=1 restore=1 purge=1
```

Checks de candidato requeridos:

```text
./scripts/check.sh
./scripts/clean-offline-build.sh
set -euo pipefail
for lab in $(find scripts -maxdepth 1 -name 'test-linux-*-lab.sh' | sort); do
  "$lab"
done
git diff --check
```

El historial de ejecución conserva los fallos y no los presenta como una suite
verde: el checkpoint previo tuvo un timeout de web-auth con OTP vacío, sin causa
establecida, seguido por un retry exacto verde. Tras componer la base, la primera
corrida de 18 labs encontró expectativas obsoletas de backup/recovery (la base
ya contenía ocho records de siete tipos) y de la salida content; cuatro labs
web/passkey no arrancaron porque el clean había borrado symlinks ignorados a los
artefactos fijados. Se restauraron exactamente esos symlinks repo-locales. Las
expectativas de backup/recovery ahora distinguen `types=7 records=8`, con 18
items/20 partes durables y nueve items restaurados (ocho records más el stream),
sin reducir tipos ni datos. La siguiente corrida integral observó el RED de
framing de teclado descrito arriba.

Gate final del candidato, sin skips ni reintentos de operaciones:

```text
./scripts/check.sh
PASS (fmt, check, tests y clippy; exit 0)

./scripts/clean-offline-build.sh
Finished `dev` profile [unoptimized + debuginfo] target(s) in 49.24s

set -euo pipefail
for lab in $(find scripts -maxdepth 1 -name 'test-linux-*-lab.sh' | sort); do
  "$lab"
done
PASS all-linux-labs count=18
```

Los 18 laboratorios pasaron secuencialmente, incluidos TUI real, Keycloak
26.7.3, CFT/MV3/Native Messaging, SSH y sync con artefactos fijados.

## Límites

- No se ejecutaron macOS/Windows ni Linux ARM64; ticket 33 conserva validación
  y distribución de los seis targets.
- No se amplió la TUI a autoridad, pendientes, backup/import/export o sync de
  los tickets 24/25.
- Los attachments streaming mayores que el frame humano conservan su seam de
  descarga/exportación streaming; esta pantalla enumera el descriptor exacto
  y no inventa una copia parcial.
- La revisión formal Astra y la integración/resolución pertenecen a las
  puertas finales/separate merger, no a este implementador.
- Tras autorización explícita, los opcodes heredados 47/48 y
  `primary_human_secret` fueron retirados. No queda una ruta implícita o
  alternativa a la selección exacta 51–53.
