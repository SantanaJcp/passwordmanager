# Migración local de callers legacy — 2026-10-14

**ISSUES. Medido: siete RED originales reproducidos localmente; cinco pasan tras
la provisión explícita. Passkey y token exchange alcanzan fallos adicionales del
worker ordinario. No se modificó producción ni se aceptaron esos dos casos.**

## Autoridad y procedencia

Trabajo sintético local autorizado sobre 1A/2A de [decisions.md](../../decisions.md).
Las decisiones 3/4 siguen pendientes. No es la revisión formal 35 ni aceptación
nativa/G7. Se leyeron chef-mode, PRINCIPLES, feature-xray, find-the-cause,
AGENTS, CONTEXT, contratos de identidad, spec §11/§15 y el método exacto
`0a11733ffc784e80cb75c8df01d2cdcf34862d7e` del integrador, sin editarlo.

Base exacta: `8cd45529b062506a2cbe0c567538d3999ac8a2b6`.
Merge propio: `b12784295b31415de577889b63883f9169278dfd`, padres
`e8c750fef38d4e88d57ec6e68621c787ae514d14` y el compuesto exacto.
Medido: `git diff 8cd45529 HEAD -- crates scripts Cargo.toml Cargo.lock`
estaba vacío después del merge; las diferencias heredadas eran ocho archivos
históricos bajo `.scratch/passwordmanager`, no cambios de producción.
No fetch externo, reset, push, PR, master, release, CI, instalaciones,
dependencias nuevas ni credenciales reales.

Archivos propios después del merge:

- `crates/pm-custody/tests/{authorization_lab.py,linux_lab.py,passkey_lab.py,concurrency_lab.py,tui_access_lab.py,chef_installed_fixture.py}`
- `crates/pm-web-auth/tests/{passkey_login_lab.py,token_exchange_lab.py}`
- `docs/verification/chef-caller-migrations-20261014.md`

Se conservan manifests, lockfile, schemas, retención, permisos de producto, wire,
KDF, replay, receipts y límites4/16/128. La evidencia privada bajo `.scratch`
no se incluye en el commit ni modifica ledgers/reportes del coordinador.

## Método y API de fixture

Build propio: Rust1.98.1 del toolchain fijo
`/home/santana/Documents/ChatGPT/passwordmanager/.toolchain`,
`RUSTUP_AUTO_INSTALL=0`, `--locked --offline`, target/debug de este worktree,
sin symlinks a targets ajenos. Build de custody/CLI/web-auth, sync y ejemplo
`chef_runtime_open_channel`: rc0. Cada build y lab bajo
`flock /tmp/pm-cargo-window.lock`, sin locks anidados.
[Logs y hashes](../../.scratch/chef-caller-migrations-20261014/binary-origins.json).

`initialize(custody)` exige UID0 de un namespace subordinado, copia el binario
propio y sus bibliotecas públicas a una raíz UID0 única en `/var/tmp` y conserva
`fixture.json`. `prepare(uid, command, identity)` transforma exclusivamente
serve-vault/migrate-agent-registry/provision-adapters y flags de paths conocidos
que pertenecen a esa raíz; entra en chroot **antes** de bajar a UID1. Un comando
instalado sin inicialización falla explícitamente. No hooks globales de Popen,
reescritura de fuentes, mounts del host dentro del chroot, aprendizaje del owner
de `/`, UID65534, excepción root ni TTY falso. Clientes, browser y PTY humanos
permanecen fuera y usan el mismo socket real.

`migrate(...)` ejecuta el CLI público como UID1, exige destino ausente, conserva
bootstrap y verifica owner/mode del registro. El producto valida grant vigente,
RPK/UID, bóveda/dispositivo/root-public. `stop_and_unlink(...)` exige salida
SIGTERM/output verificados y elimina solo sockets de custodia propiedad UID1
bajo la raíz propia. Plazos originales de clientes8/15/20/30 conservados;
el cierre passkey conserva8s y los cierres Linux5s.

Autorización registra A/B tras setup y reinicia el snapshot. Tras reenrolar A2,
retira explícitamente el archivo instalado anterior a un nombre propio no
existente, conservando inode/owner; crea un registro nuevo con A2/B mediante
migración validada, sin sobrescritura. Las pruebas de A viejo/rogue usan un
bootstrap instalado vigente y conservan sus denegaciones originales.

Linux ejecuta primero CRUD/audit/content y sus conteos originales; después
setup humano, registro A/UID3+B/UID4 y restart antes del probe delegado.
Se añaden negativas cruzadas de UID/RPK. La inspección completa de canarios
pausa/reanuda el daemon propio mediante fronteras SIGSTOP/SIGCONT observadas:
una repetición midió desaparición del WAL entre glob y read, no un secreto
en claro; no se omiten archivos ni se ignora FileNotFoundError. Concurrencia registra A/B antes de la
TUI, manteniendo el daemon ordinario, cuotas y todos sus controles.
Bridge/login instalan sus RPK/UID3 y segundo agente/UID4. Nombres temporales
cortos evitan el límite real de Unix sockets de Chromium; no se cambian plazos.

Token exchange conserva explícitos sus primeros modos de laboratorio. Su
fase ordinaria instala 1A y una ruta2A cerrada:
`keycloak-token-exchange / keycloak-exchange-lab / token_exchange / UID5`, con
endpoint real del binario propio pm-web-auth y destino TLS sintético. El destino
retiene la respuesta hasta release explícito, con límite20s, para observar el
worker antes de cancelar. No controlled.external, proveedor alternativo ni
retry de autenticación desconocida en esa fase.

## RED original y resultado observable

[RED originales](../../.scratch/chef-caller-migrations-20261014/red-direct-results.json)
ejecutan copias byte-idénticas de los tests del compuesto, con binarios propios,
namespace subordinado, mount privado y prerequisitos de los wrappers. Son
mediciones de este writer; las42/52 del integrador son evidencia distinta.
Los scripts completos de reproducción permanecen en la evidencia local.

[Vector de entrega: comando, rc y hashes de fuentes por caso](../../.scratch/chef-caller-migrations-20261014/completed-results.json).
Los nombres siguientes mapean directamente a `scripts/test-linux-<nombre>-lab.sh`;
se ejecutó su fixture subyacente con los mismos argumentos/binarios/prerequisitos.

| Caso | Primer RED propio | Resultado tras migración |
|---|---|---|
| authorization | A discovery rc4/CUSTODY_UNAVAILABLE | rc0; A/B, rotación, revocación, restart y atomicidad intactos |
| content | probe delegado rc4 | rc0; CRUD, contenido, streaming/crash y audit intactos |
| human-transaction | probe delegado rc4 | rc0; conteos, replay, receipts y fallos atómicos intactos |
| passkey | Native Messaging NOT_ALLOWED, esperaba waiting | rc1; registro/create/confirm/enable avanzan, get interno falla |
| passkey-login | request llamado, pendiente no aparece; timeout en dataset | rc0; registro, login real, UP/UV, revocación y restart intactos |
| token-exchange | cancel-start ordinario no devuelve0 | rc1; start ordinario/proveedor POST observados; cancel falla |
| concurrency | A discovery rc4 y cleanup missing-socket | rc0; TUI abierta, paralelismo y límite4; cleanup verificado |

[Comparación AST de aserciones](../../.scratch/chef-caller-migrations-20261014/assertion-comparison.json):
todas las aserciones originales de aceptación permanecen. Única sustitución: la vieja aserción textual de cleanup tmux en
`tui_access_lab.py`, reemplazada por registro de creación, owner/socket/inode/PID,
cierre observado y unlink del socket exacto. No modifica oráculos de producto.
[Witness independiente](../../.scratch/chef-caller-migrations-20261014/cleanup-results.json):
cleanup antes de crear tmux da rc1 en la fuente original y rc0 con el nuevo caller,
sin contactar el servidor no creado. La TUI creada también cierra y vuelve a
abrirse, con pruebas completas de ownership. No ignore_errors añadido.

## Dos seams de producción fuera del ownership

### Passkey interna consumida por el worker genérico

**Medido:** el browser obtiene registration, confirmación humana, enable y
metadatos; al pedir get `4141…4141`, Native Messaging devuelve NOT_ALLOWED.
La consulta pública del intento devuelve
`state=FAILED reason=ADAPTER_UNAVAILABLE`; el daemon registra la misma categoría.
La captura `passkey-get-failure.json` se conserva en la raíz identificada por el
log [passkey](../../.scratch/chef-caller-migrations-20261014/completed-passkey.log).
Los fallos de cleanup se agrupan junto al fallo primario; no se oculta ninguno.
Los controles posteriores a get no se consideran ejecutados.

**Inferido del código:** [agent_wire.rs](../../crates/pm-custody/src/agent_wire.rs)
(opcode40, líneas289–299) crea `vault-webauthn-provider`. El worker de
[linux.rs](../../crates/pm-custody/src/linux.rs) (líneas3624–3661) reclama cualquier
created/waiting; [attempts.rs](../../crates/pm-vault/src/attempts.rs) (líneas1132–1150)
no separa los intentos intrínsecos. La configuración instalada no admite esa
integración, según [installed_unix.rs](../../crates/pm-custody/src/installed_unix.rs)
(líneas289–297). Un caller no puede proveerle una ruta pública válida.

Seam mínimo para el padre: propiedad/selección del intento intrínseco entre
`run_provider_once`/`AttemptVault::claim_next` y `PasskeyProvider`; conservar el
proveedor interno y sus estados, sin sustituir integración o impedir el worker.

### Cancelación durante I/O del adaptador ordinario

**Medido:** start ordinario rc0 y POST real del pm-web-auth propio al destino
TLS sintético; mientras la respuesta está retenida, `BEGIN IMMEDIATE` con
timeout0 observa `database is locked`. El cancel público devuelve
`INTERNAL_ERROR` y `error: CUSTODY_UNAVAILABLE`, antes de alcanzar la aserción
original CANCELLED. `cancel-boundary.json` y `synthetic-cancel.request` quedan
retenidos en la raíz del [log token](../../.scratch/chef-caller-migrations-20261014/completed-token-exchange.log).
No se ejecutó el control final de suspensión de ese caller después de su fallo.

**Inferido del código:** [attempts.rs](../../crates/pm-vault/src/attempts.rs):1255
abre una transacción Immediate y llama al proveedor en:1280 antes de commit:1281.
Cancel necesita otra Immediate en:899. [linux.rs](../../crates/pm-custody/src/linux.rs)
aplica ese guard a token exchange. El seam mínimo está en esa frontera de
transacción/lease y cancelación. No basta cambiar la fixture, ampliar deadlines,
quitar el worker o relajar la validación de grants. No se propone resolverlo con
un cambio de schema/retención ni se presupone aprobación de la decisión4.

## Flujos afectados y límites

Medido: rc0 en custody, backup, history, recovery, tui-content, tui-operations,
attempts y registry del [run afectado](../../.scratch/chef-caller-migrations-20261014/affected-results.json).
Tui-access y concurrencia rc0 en la [repetición tras corregir el ciclo de creación/cierre](../../.scratch/chef-caller-migrations-20261014/affected-final-results.json).
Registry incluye pares cruzados, unknown-RPK, root filesystem realmente UID3,
file replacement/removal/modes y hot revoke en canal abierto. Autorización añade
otro root negativo real, con custodia chroot y UID3 en `/`, rc4 antes de sockets.
No se contó un root virtual ni solo una lectura de fuente como PASS.

Se inspeccionaron los callers del helper Linux, incluidos scripts copiados a
procesos proveedor: la importación de `chef_installed_fixture` es explícita y
perezosa; no rompe esos helpers privados que copian solo linux_lab.py.
Los nueve flujos medidos no son una barrida52 ni una aceptación externa.

Intentos iniciales conservados: falta de traversal por `/home/santana`0700,
rutas Unix demasiado largas y selección inicial incorrecta del path Java.
Se corrigió exclusivamente el entorno/paths propios; no se contaron como RED de
producto. El error Chromium `Socket path too long` fue capturado antes de
acortar los nombres. No se limpiaron artefactos de otros escritores. Diez procesos de custodia
abandonados por excepciones de los runs propios se terminaron tras verificar
UID/cmdline y procedencia local; sus snapshots de cleanup se retienen.

Raíces externas `/var/tmp/pc-*`, ledgers, logs y target propio conservados. Las
subcarpetas internas de datos siguen el cleanup de cada fixture; los diagnósticos
relevantes se copian a la raíz retenida antes de ese cleanup. El wrapper auxiliar
baseline solo configura raíz propia/LAB_PARENT; no es el método del integrador
editado ni la implementación del helper entregado.

NOT_RUN: G7 completo, Windows/macOS nativos, otras CPU, proveedores no sintéticos,
reboot/FDE, instalaciones reales, release, CI y aceptación humana formal.
No se hereda como PASS la evidencia histórica ni se cierra3/4.
Principios aplicados: `prove`, `root-cause`, `no-fallbacks`, `truthful-state`,
`small-owned`, `isolate`, `evidence`, `owner-attention`.

## Integridad de fuentes

Medido: producción permanece byte-idéntica al compuesto; el
[manifest](../../.scratch/chef-caller-migrations-20261014/production-manifest.json)
se comprobó al final. Árboles Git fuente sin cambios:

- pm-custody/src: `056eb30237998870e2e70b533cdd627dfca7209f`
- pm-vault/src: `e9c2c297cbeb6441f5ee75071f5d242b4a43648c`
- pm-web-auth/src: `c29f003003893418417f9faf61c95dc0b8906c9b`

[Resumen final](../../.scratch/chef-caller-migrations-20261014/summary.json)
y prerequisitos: [Keycloak/Java/CFT y hash](../../.scratch/chef-caller-migrations-20261014/prerequisites.log).
