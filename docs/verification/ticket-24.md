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

## Evidencia del candidato

TDD comenzó con RED enfocado: `delegated_authorization` no compiló porque aún
no existían `access_overview`, `human_pending`, `human_cancel` ni
`prepare_disable`. Después de implementar esos seams sobre los motores humano y
de intentos existentes, el test enfocado pasó `1/1`. El driver TUI también tuvo
dos RED relevantes que se conservaron como diagnóstico: un PTY directo no
ofrecía a Crossterm una terminal completa, y la primera ejecución por `tmux`
encontró una carrera de ciclo de vida del servidor. El harness final usa un
servidor `tmux` con nombre propio y la ejecución verde no cuenta esos intentos
fallidos como éxito.

Resultados observados sobre `a78992a`:

```text
scripts/check.sh
# exit 0; fmt, clippy -D warnings y toda la suite Rust pasan

scripts/clean-offline-build.sh
# hashes fijados OK; 17,561 archivos / 5.1 GiB eliminados;
# build locked/offline limpio en 40.18 s; exit 0

scripts/test-linux-tui-access-lab.sh
PASS tui-access keyboard=enroll+enable+disable+suspend+resume+revoke agents=2 common-set=same human-lock=independent
PASS tui-pending safe-context=1 provider=separate-uid cancel=terminal secrets=absent

PM_KEYCLOAK_DIST=.../keycloak-26.7.3 \
PM_CFT_DIR=.../chrome-linux64 \
scripts/test-linux-passkey-login-lab.sh
PASS passkey-login-human outer=WAITING_FOR_HUMAN UP=TUI-keyboard UV=fresh-second-human-channel presence-only=denied extension=MV3-native real

for lab in $(find scripts -maxdepth 1 -type f -name 'test-linux-*-lab.sh' | sort); do "$lab"; done
PASS complete-linux-labs count=19
# exit 0 con `set -euo pipefail`
```

La barrida final fue una sola ejecución ordenada 19/19 después del clean build.
Los límites emitidos por los labs siguen vigentes: no se ejecutaron navegador
de producto, reinicio/FDE de host ni los targets nativos pendientes.

## RED de integración pendiente

El merger separado integró `36934b3` como `77a5198`. `git diff --check`,
`scripts/check.sh` y clean locked/offline (44.43 s) pasaron; una sola barrida
ejecutó los 19 labs y todos sus cuerpos funcionales retornaron 0. El gate no se
acepta todavía: `tui_access_lab.py` suprime cualquier excepción del cleanup con
`shutil.rmtree(root, ignore_errors=True)`, y la corrida dejó observable
`/tmp/pm-tui-access-linux-lab-c4d1o_6i` con archivos y directorios sintéticos de
UIDs mapeados 100002–100005 pese al exit 0. La supresión convierte un fallo real
de laboratorio en éxito aparente, contrario al método de propagación exigido.
No se ejecutó retry. Se requiere corregir el lab y repetir la verificación antes
de resolver 24; esta evidencia no cambia los límites nativos ya declarados.

### Método de remediación del cleanup

Antes de modificar el lab se fija este criterio: el proceso principal conserva
la ruta única que creó, valida que sea un directorio real hijo directo de
`/tmp` con el prefijo `pm-tui-access-linux-lab-`, y enumera de forma cerrada
cada recurso superior y su UID esperado. Tras detener sus procesos, hijos
efímeros con los UID ya mapeados eliminan únicamente el contenido de sus
directorios; el proceso dueño del root elimina después esos directorios, sus
archivos superiores y el root. Cada `unlink`, `rmdir`, salida de hijo y ausencia
final se comprueba; no se usa `sudo`, `ignore_errors`, una ruta alternativa ni
se toca el residuo de la corrida roja. Los dos mensajes `PASS tui-*` solo se
emiten después de comprobar que la raíz de esa corrida ya no existe.

La regresión enfocada compara el conjunto de raíces con ese prefijo antes y
después de una ejecución completa. RED es el residuo nuevo conservado arriba;
GREEN exige exit 0, mensajes PASS posteriores al cleanup y conjunto final
idéntico al inicial. Después se repiten `check.sh`, clean locked/offline y los
19 labs con propagación explícita, sin disminuir ninguna prueba.


### Remediación y GREEN observados

La remediación elimina `ignore_errors`, fija la creación bajo `/tmp`, valida el
prefijo/ruta, tipo y owner de cada entrada superior, borra el contenido con el
UID mapeado propietario y propaga cada salida/error mediante `ExceptionGroup`.
Los PASS se movieron después de comprobar que la raíz desapareció.

La primera ejecución de la implementación estricta produjo otro RED útil: el
inventario cerrado detectó `terminal.raw`, que el método aún no había declarado,
y abortó sin emitir PASS. Tras añadir ese archivo regular root-owned al
inventario, se eliminó de forma segura únicamente la raíz de esa ejecución
fallida. La raíz del RED original `pm-tui-access-linux-lab-c4d1o_6i` se conservó
como evidencia y no se tocó.

La regresión enfocada final comparó raíces antes/después y pasó:

```text
PASS tui-access ... cleanup=verified
PASS tui-pending ... cleanup=verified
focused-exit=0 cleanup-set=UNCHANGED
```

El gate final se ejecutó dentro de una ventana Linux coordinada y exclusiva:
los worktrees comparten toolchain, artefactos y CPU, por lo que ningún otro
`check`, clean build o lab pesado local puede correr simultáneamente. No se
cambió producto ni se ampliaron plazos para acomodar contención. Resultado:

```text
git diff --check
# exit 0

scripts/check.sh
# exit 0; fmt, suite Rust y clippy -D warnings

scripts/clean-offline-build.sh
# Removed 11,644 files / 4.0 GiB; build locked/offline 1m 01s; exit 0

# una ejecución por lab; acumulación de rc y comprobación del conjunto de raíces
LAB-SUMMARY count=19 failures=0 ticket24-cleanup-set-changed=0
```

Al finalizar no quedaron procesos ni raíces de laboratorio creadas por esta
ventana; solo permanece el residuo del RED original, identificado arriba. Los
límites de plataforma/product browser y la revisión formal final continúan sin
cambio.
