# Daemon ordinario: implementación local 1A/2A

Resultado: **ISSUES**. Medido: integración ordinaria Linux con procesos/UID/RPK
reales y datos sintéticos. Pendientes: integración Windows, ejecución macOS,
proveedor externo real, fairness por identidad, revisión independiente y
composición global. No se certifica soporte ni se cierran tickets.
Principios: `design`, `prove`, `root-cause`, `no-fallbacks`, `truthful-state`,
`small-owned`, `isolate`, `handoff`.

Base exacta `ecc2e9d390b780223dfdf1322288762f87af891c`; código base
`d4b1be662a1b8766eff54c2b8269ef4c94770c54`. Worktree exclusivo
`/home/santana/.t3/worktrees/passwordmanager/t3-9959e6f2`, rama
`t3/daemon-readiness-registry-adapter`. [Decisiones 1A/2A](../../decisions.md)
autorizan estas dos composiciones locales, sin cambiar eventos/grants/wire
sincronizados ni supervisar procesos de adaptador.

## Forma y flujo del registro Unix

`<vault>.agent-registry`: binario local `PMAR1`, vault16, device16,
server-RPK44, count-u16 big-endian; cada entrada RPK44 + UID-u32 big-endian.
Cabecera83 y entrada48: máximo339 entradas por el límite de **16 KiB reales
serializados**, sin imponer un segundo límite de agentes. Rechaza duplicados
por RPK, roles humanos/custodios y pérdida del par bootstrap conocido. Las
etiquetas `environment_binding` no se interpretan como UID.

El archivo exige owner custodio, modo0400, regular sin symlink/hardlink y
ancestros root/custodio sin escritura ajena; solo un ancestro root-owned
sticky admite escritura ajena. **No se aprende ningún owner desde `/`.**
Se pinnean bytes y dev/inode/ctime/modo/longitud, se revalida por handle y nombre
antes de admitir el snapshot. Sustitución incluso con bytes iguales, retirada,
owner/modo inseguro o corrupción invalidan el archivo. Cambios requieren
reinicio. No hay TOFU ni otro camino delegado cuando falta el registro; el
canal humano puede preparar la primera autoridad antes de migrar.

El listener obtiene UID del socket real, elige solo pins registrados para ese
UID y extrae la RPK probada por TLS. El handler vuelve a cruzar ambos valores;
el motor conserva concesión/revocación humana por operación. El hook W3 de
custodia permanece; el snapshot local se verifica en cada request y antes del
uso del proveedor, incluidos intentos previamente aceptados.

Migración explícita, dentro de la instalación sintética del custodio:

```text
pm-custody migrate-agent-registry --bootstrap /installed/bootstrap \
  --vault /installed/vault.sqlite3 --device <device-hex> \
  --agent-public /installed/B.pub --agent-uid <B-uid>
```

Solo este comando incorpora explícitamente el par bootstrap ya confiable.
Verifica las concesiones humanas actuales de todos los RPK, bóveda/dispositivo
y custodia; rechaza revocados/ambiguos. Publica create-only mediante hardlink
atómico de temporal sincronizado, unlink y fsync de padre; cleanup propagado.
No sobrescribe bootstrap, registro, identidad propia ni datos de autoridad.
Un error posterior a publicar se informa sin borrar confianza ya visible.

## Adaptadores instalados, lifecycle externo

`<vault>.adapters` usa la misma protección de archivo/snapshot y límite16KiB.
Formato `PMAC1`, cabecera idéntica; por entrada: integración length-u32+UTF8,
versión-u32, perfil length-u32+UTF8, método length-u32+UTF8, endpoint absoluto
length-u32+UTF8 y UID-u32. Solo integraciones reales implementadas/version1,
combinaciones de método cerradas y clave integración/perfil/método única.
`controlled.external` nunca se puede instalar como proveedor ordinario.

```text
pm-custody provision-adapters --bootstrap /installed/bootstrap \
  --vault /installed/vault.sqlite3 --device <device-hex> \
  --integration github-rest-bearer --profile github-assigned-issues/1 \
  --method bearer --endpoint /adapter-runtime/github.sock --adapter-uid <uid>
```

La provisión verifica separación de roles frente al registro y es create-only.
La configuración no necesita abrir el perfil privado del adaptador: vincula
su profile_id/destino exacto, integración, método, endpoint y principal; el
adaptador valida su propio perfil y los datos tipados de la integración.
No acepta endpoints del agente. Antes de enviar: snapshot actual, directorio
final del adaptador sin escritura ajena, socket del UID esperado y peer UID
real. Reutiliza el transporte nativo que usan los adaptadores existentes;
no crea procesos, perfiles de laboratorio ni selección alternativa.

`serve-vault` compone el worker y `recover_inflight` existentes. Configuración
ausente/retirada/insegura o endpoint indisponible produce fallo público seguro;
selección ausente devuelve UNSUPPORTED_INTEGRATION. Get/cancel conservan el
motor y ownership. Reconcilia sin repetir login; recuperar una reconciliación
que quedó running puede terminar INDETERMINATE, sin relabel de terminal por
cancel. No cambia esa política ni los plazos/límites existentes.

## RED, corrección del límite G1 y GREEN final

Medido antes del fix: build propio locked/offline rc0. Registro rc1 en
`/tmp/chef-runtime-registry-red.log`: A+B enrolados, TUI abierta, A descubre y B
recibe CUSTODY_UNAVAILABLE. Proveedor rc1 en
`/tmp/chef-runtime-adapter-red.log`: binarios de base preservados, adaptador
pm-web-auth real y destino TLS sintético; intento no llega a terminal en20s.

**Corrección retirada:** el primer commit local `6728bbd` aprendía el owner
de `/` para evitar el owner sin mapear del namespace. El coordinador señaló
que ampliaba confianza; ese commit **no debe integrarse solo**. Los primeros
GREEN con ese guard no acreditan G1. El caso discriminante
`/tmp/chef-runtime-root-policy-red2.log` demuestra el defecto: raíz propiedad
del UID agente, config leaf custodio0400 y B admitido realmente. La versión
final restaura solo root/custodio y rechaza el mismo caso.

Preflight medido: tmpfs propio disponible; mknod para dispositivos privados
falla EPERM. El intento de ejecutar todo dentro de chroot deja TUI NOT_RUN,
registrado en `/tmp/chef-runtime-owned-final.log`, sin fingir dispositivos.
La fixture final separa los dominios reales: **custodia/provisión dentro de un
chroot UID0 propio; clientes y TUI en su PTY nativo fuera**, mismas credenciales
kernel y sockets. Copia únicamente binarios propios y bibliotecas públicas
necesarias, sin mounts del host ni modificación de permisos/identidades reales.

GREEN final: `/tmp/chef-runtime-local-final.log`, comandos propios
[registry](../../crates/pm-custody/tests/chef_runtime_registry.py),
[adapter](../../crates/pm-custody/tests/chef_runtime_adapter.py) y
[runner](../../crates/pm-custody/tests/chef_runtime_chroot.py).

- A+B mismo PID/conjunto con TUI abierta; pares cruzados, RPK desconocida bajo
  UID conocido y rol humano desde agente rechazados. Par nativo registrado sin
  concesión humana rechazado. Raíz de filesystem propiedad del agente rechazada.
- Migración explícita, bootstrap conservado, rechazo de ambigüedad/sobrescritura
  y agente revocado; otra bóveda, corrupción, owner/modos inseguros, inode nuevo
  con mismos bytes y retirada rechazados. Sin registro no hay bootstrap alterno.
- [Cliente TLS persistente](../../crates/pm-custody/examples/chef_runtime_open_channel.rs)
  obtiene NOT_FOUND antes de revocación y AGENT_REVOKED después en el mismo canal.
- pm-web-auth real: éxito, WAITING individual/cancelación, reinicio/idempotencia
  y recuperación INDETERMINATE sin otro login; una llamada inicial por intento.
  Config retirada/ausente, perfil/binding/endpoint incorrectos: cero llamadas;
  método/destino libres y proveedor de test rechazados. Redirect/reflexión,
  401/403, SSO, cuota/retry inválido/5xx no exponen secretos en salida/storage.
- Cleanup estricto de procesos/fixtures/chroot comprobado antes del PASS final.

Reproducción desde este worktree: toolchain inmutable de la raíz histórica,
RUSTUP_AUTO_INSTALL=0 y CARGO_TARGET_DIR=$PWD/target-chef-daemon-implementation.
Todo Cargo/build/lab bajo flock /tmp/pm-cargo-window.lock. Construir con
scripts/cargo-local.sh build -p pm-custody -p pm-cli -p pm-web-auth
--example chef_runtime_open_channel --bins --locked --offline. Después, bajo
el namespace real de [03](ticket-03.md) con mapas de /etc/subuid y /etc/subgid:

```text
python3 crates/pm-custody/tests/chef_runtime_chroot.py registry "$PWD/target-chef-daemon-implementation/debug/pm-custody" "$PWD/target-chef-daemon-implementation/debug/pm" "$PWD/target-chef-daemon-implementation/debug/pm-web-auth"
python3 crates/pm-custody/tests/chef_runtime_chroot.py adapter "$PWD/target-chef-daemon-implementation/debug/pm-custody" "$PWD/target-chef-daemon-implementation/debug/pm" "$PWD/target-chef-daemon-implementation/debug/pm-web-auth"
```

scripts/check.sh se ejecutó **una vez**: verificadores/fmt/workspace check/test
pasaron; clippy terminó rc101 con cinco errores de estilo del candidato.
Log `/tmp/chef-runtime-final-check3.log`. Corregidos explícitamente; clippy
-p pm-custody --all-targets --locked --offline final rc0 en
`/tmp/chef-runtime-owned-final.log`. Tests de custody sobre fuente final en
`/tmp/chef-runtime-local-final.log`. No se presenta el check completo como rc0
ni se repite full52/clean/integración reservada al coordinador.

## Pendientes, fallbacks y siguiente paso

Medido: cuatro handlers **globales** ocupados por A rechazan B; recuperación
al liberar. Es una limitación heredada, no cuatro conexiones por agente ni
fairness conforme al [contrato G4](../design/agent-identity.md). No se ampliaron
límites ni crearon workers por agente sin cota. El coordinador debe resolver
la forma de admisión acotada para ese contrato, fuera de este correctivo mínimo.

Windows: API SID comprometida en sibling
`f56c993b2ba3d770f6aae7f5c3401bf0263d98e1`, leída pero no incorporada aquí.
Necesita integración exacta de create_agent_instance_for_sids y
accepted_client_sid, más primitive nativo de archivo instalado seguro
(owner/service+SYSTEM-write DACL, no reparse/hardlink, handle/fileID estable,
16KiB, revalidación y publicación no-replace). Este último sigue asignado al
dueño de native-channel. Windows custody aún carece de worker ordinario;
no se inventó código cfg o un uso inseguro de read_bounded para simular soporte.
Windows y macOS ejecución nativa: NOT_RUN. Darwin comparte el módulo Unix;
no equivale a evidencia de dos CPU macOS. Otros perfiles reales distintos del
adaptador medido y proveedor GitHub real permanecen pendientes.

Fallbacks heredados conservados: accept/config/handler descartados por
linux::accept_one; serve_loop omite recuperación si falla open y descarta error
del worker; settle AUTHORITY_REVOKED descartado; Windows descarta handler.
Pueden ocultar fallos al loop y no acreditan readiness. Se mantiene el inventario
[W4](w4-agents-provider.md); no se autorizó cambiar esas políticas.

Siguiente paso: coordinador revisa el diff combinado final con Claude
configurado, integra siblings exactos/API Windows y callers de fixtures/instalación
fuera de esta allowlist, y comprueba composición. Los fixtures heredados que
inician serve-vault necesitan la provisión/migración explícita nueva; no reciben
un fallback para permanecer verdes. Sin push/PR, instalación real, dispatch,
release ni cambios de tickets/spec/ejecución. G7 y revisión35 siguen su cauce.
