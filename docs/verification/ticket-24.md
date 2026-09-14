# Ticket 24 — método de verificación TUI de autoridad y pendientes

## Método escrito antes de ejecutar

Entorno objetivo: Linux x86_64 autorizado, Rust 1.98.1 repo-local, motor SQLite
real y procesos separados en un user+mount namespace efímero. La superficie es
la TUI Ratatui/Crossterm integrada del ticket 23, conducida por teclado dentro
de un PTY `tmux`; no se acepta una ruta CLI-only, un segundo motor ni una
respuesta simulada. Identidades, RPK, intentos, claves y canarios son
sintéticos. El laboratorio no modifica el host fuera del namespace.

El laboratorio de autoridad debe:

1. abrir la TUI por el canal humano TLS 1.3/RPK y mostrar una vista sin secretos
   del estado global, agentes/generaciones y conjunto común;
2. dar de alta por teclado una solicitud cerrada con subject/request/RPK/labels,
   comprobar el mismo conjunto habilitado desde dos procesos agente reales,
   deshabilitar/habilitar una credencial, suspender/reanudar y revocar;
3. demostrar que lock humano no suspende agentes, mientras suspensión,
   deshabilitación y revocación sí se aplican en el próximo uso sensible y
   persisten según los contratos integrados;
4. listar intentos abiertos con solo ID, título habilitado, integración, estado,
   razón, expiración e identidad/generación; cancelar por teclado y mostrar el
   estado terminal sin repetir autenticación;
5. conservar pantalla/errores/argv/env/temporales sin secretos ni contexto libre
   del agente.

La confirmación passkey se prueba además en el laboratorio de proveedor real ya
existente: la TUI consulta el `PasskeyPrompt` persistido, muestra RP/cuenta/
origen/documento, exige `APPROVE <request_id>` por teclado y una reautenticación
maestra fresca en un segundo canal humano antes de enviar la evidencia cerrada
al proveedor. UV requerida siempre usa esa reautenticación; no existe tecla o
campo que permita al agente declarar UP/UV. Cancelar, vencer o revocar antes de
confirmar debe impedir la firma y no resucitar el intento.

Prerrequisitos: los de tickets 07/08/13/23 (`tmux`, user namespaces,
`wl-clipboard 2.3.0`, CFT fijado para el recorrido passkey y toolchain
repo-local). Éxito enfocado exige ambos laboratorios con exit 0 y sin skips. El
gate de candidato exige `scripts/check.sh`, clean locked/offline, `git diff
--check` y todos los `scripts/test-linux-*-lab.sh` ordenados con propagación
fiable de cualquier fallo. No acredita macOS/Windows/ARM64, sesiones externas,
TUI de migración/sync/audit del ticket 25 ni revisión formal Astra.
