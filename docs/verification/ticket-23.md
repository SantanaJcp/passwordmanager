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

Comando enfocado actual:

```text
./scripts/test-linux-tui-content-lab.sh
PASS tui-content types=7 fields=explicit-complete type-mutations=7 wrong-password=unchanged tls-rpk=1 keyboard=1 pty=1 terminal=linux resize=80x24+42x12+100x30 unicode=1 controls=sanitized osc52=absent selection-secret=absent reveal-expiry=1 idle-lock=1 clipboard=wl-copy-2.3.0 clipboard-race=preserved hostile-agent=denied history=1 trash=1 restore=1 purge=1
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

La ejecución secuencial inicial de laboratorios llegó a web-auth y falló allí:
Keycloak informó actualización de imagen/configuración y el preflight terminó
por timeout con OTP de longitud cero. Esto no se atribuye como causa demostrada
ni se ocultó como verde. Un segundo `test-linux-web-auth-lab.sh` exacto, con los
mismos artefactos fijados, pasó P1/isolation/adversarial/challenge. Los otros 13
laboratorios pasaron; passkey/SSH/sync/TUI se ejecutaron con los artefactos
repo-locales fijados. La integración debe repetir el gate compuesto.

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
- El checkpoint conserva todavía opcodes heredados 47/48 y su selección
  `primary_human_secret`; no forman parte del flujo 51–53. Su reemplazo o
  retirada espera autorización explícita por la regla de no modificar
  fallbacks existentes.
