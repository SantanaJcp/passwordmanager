# Adaptadores: owners propios SSH — 2026-10-14

Estado: **ISSUES**; seams corregidos con RED/GREEN local, inventario integral pendiente.
No cierra 28/G7 ni acredita producto terminado.

Base exacta: `ea57a7173424a7c607376ff5e0b49d2a19bc334f` (baseline de código
`d4b1be662a1b8766eff54c2b8269ef4c94770c54`). Rama `t3/adapter-plaintext-leaks`;
worktree `/home/santana/.t3/worktrees/passwordmanager/t3-4b41f2eb`.
Medido: pwd, raíz Git, HEAD y binding T3 coinciden; relación `subagent` con el
coordinador. No se cambia de rama ni se incorporan commits posteriores.

## Corte y causa

Inferido del mapa de fuente: `CustodySigner::auth_sign` y `consume` construían
frames propios en Vec; `authenticate` construía JSON en String y luego Vec;
`parse_consumer_reference` duplicaba texto de un frame ya protegido mediante
`to_owned`, incluso antes de comprobar trailing bytes. Web conserva los owners
HTTP/JSON/CDP/proveedor ya integrados y no tiene cambios en este candidato.

Cambio mínimo: encoder exacto compartido sobre `ProtectedWriter`, con fragmentos
prestados; resultado autenticado protegido sin JSON temporal; decoder consumer
presta el texto del frame original y comprueba su final. No añade fallback ni
cambia bytes wire, categorías, hostkey, autoridad, perfiles, métodos o plazos.
El owner se limpia por Drop también si falla I/O. Principios: `small-owned`,
`root-cause`, `design`, `prove`, `truthful-state`.

## Evidencia local

Toolchain inmutable de la raíz histórica; `RUSTUP_AUTO_INSTALL=0`;
`CARGO_TARGET_DIR=/home/santana/.t3/worktrees/passwordmanager/t3-4b41f2eb/target-chef-adapter-memory`.
Todo Cargo/build/lab se ejecuta con `flock /tmp/pm-cargo-window.lock`.

```sh
./scripts/cargo-local.sh test -p pm-ssh-client --lib wire_memory_tests --locked --offline -- --nocapture
```

Medido RED: `/tmp/pm-chef-adapter-memory-red2.log`, rc101, 0/2 pasan.
Tras controles completos independientes del wire, subprocesses con memlock=0
aceptan petición y respuesta ordinarias (`mode=request/response success=false`);
el decoder retorna una copia con dirección distinta de la fuente.
La extracción previa de los encoders conservó el comportamiento original;
compiló correctamente. El primer RED está en `...-red.log`; el segundo separa
las denegaciones para que un fallo de petición no oculte el de respuesta.

Medido GREEN: `/tmp/pm-chef-adapter-memory-green.log`, mismo filtro rc0, 2/2;
petición y respuesta rechazan memlock=0 con Memory(ResourceUnavailable), decode
presta la fuente y rechaza trailing. Control byte a byte del JSON/wire conservado.

Medido paquetes: `test -p pm-ssh-client -p pm-web-auth --all-targets --locked --offline`,
rc0, 31 tests pasan; un hijo memlock ignored se ejecuta por su padre.
Log `...-packages2.log`. `...-packages.log` rc101 fue un error mío de cfg en
un helper aún usado por el desafío público; se restauró ese helper sin migrar
esa constante. No se cuenta el error de compilación como RED conductual.
Build de custody/CLI/web/SSH rc0, log `...-build.log`.

Medido labs, por los seams Python documentados en sus wrappers, con estos
binarios exactos bajo el target propio: `debug/{pm-custody,pm,pm-web-auth,pm-ssh-client}`.
No se ejecuta el `target/debug` hardcoded de los wrappers con un target distinto.
SSH: namespace user+mount con los rangos subuid/subgid del host; OpenSSH 10.5p1,
russh 0.63.3, password/Ed25519 y canal posterior; hostkey/username/firma/consumer/
ownership/revocación/challenge. `...-ssh-lab2.log` rc0. Adapter: denegación de
perfil/frame antes de payload y wire SSH indeterminado conservado;
`...-adapter-lab2.log` rc0. Raíz corta propia `/tmp/pm-ca-MLpJWC`, verificada
vacía tras cada lab; comprobación posterior independiente del cleanup SSH.

Los primeros labs rc1 y check rc101 quedan en `...-ssh-lab.log`,
`...-adapter-lab.log`, `...-check.log`: configuré TMPDIR bajo el worktree, que
el mount /home oculta y cuyos sockets exceden SUN_LEN. No son RED de producto.
Sus dos raíces propias quedan preservadas bajo
`target-chef-adapter-memory/chef-adapter-lab-tmp/` (bins y perfil/CA sintéticos);
no se silencian esos residuos ni se borran artefactos ajenos. Web fixture anterior
sin proceso vivo observado. Repetición justificada sólo por corregir esas
precondiciones, no un retry de autenticación dentro de un intento.

Medido: `scripts/check.sh` corregido rc0 en `...-check2.log`: validadores,
fmt, check, tests y Clippy completos. No clean build ni barrida de 52 labs.
La raíz corta temporal final se retiró vacía; los dos residuos anteriores se conservan.
Los paths abreviados `...` significan `/tmp/pm-chef-adapter-memory`.
Comandos de lab: `python3 crates/pm-ssh-client/tests/ssh_lab.py "$CARGO_TARGET_DIR/debug/pm-custody" "$CARGO_TARGET_DIR/debug/pm" "$CARGO_TARGET_DIR/debug/pm-ssh-client"`
y `python3 crates/pm-custody/tests/adapter_protected_frame_lab.py "$CARGO_TARGET_DIR/debug/pm-web-auth" "$CARGO_TARGET_DIR/debug/pm-ssh-client"`;
check: `./scripts/check.sh`, todos bajo el mismo flock.

## Límites y fallbacks conservados

Inferido, inventario aún abierto: `Profile` SSH mantiene campos/fuente ordinarios
y Debug; `random_reference` y el índice retained mantienen String; los Vec de
firma y el String requerido por russh siguen en su frontera de tercero.
No hay prueba nueva de extracción, swap, heaps de terceros ni seis targets.
La fuente tipada `Error::source` conserva upstream como exige W3; el main y los
logs observados usan códigos/clasificación segura, no serializan esa fuente.

Fallbacks heredados sin modificación (`no-fallbacks`):

- Web `provider::serve`: error de read continúa y error de write se descarta;
  puede ocultar truncamiento/respuesta perdida. Sus closures de parseo agrupan
  fallos de copia en status4. `Browser::stop` descarta kill/wait/cleanup; timeout
  de vista sustituye campos diagnósticos ausentes.
- SSH `Profile::value` devuelve vacío ante ausencia; `read_installed` agrupa I/O
  en INVALID_PROFILE. Consumer canal fallido devuelve `[1]`, igual que referencia
  desconocida; `consume` convierte toda respuesta distinta de `[0]` en rechazo.
  CLI usa `to_string_lossy` para argumentos no UTF-8.
- `ssh_lab.py` usa `rmtree(ignore_errors=True)` en finally: puede ocultar residuos.
  Su ejecución se evaluó con TMPDIR propio y comprobación posterior de vacío,
  sin modificar ese fallback ni borrar residuos cuya limpieza falle.

No ejecutado: GitHub real, browser/Keycloak completo, macOS/Windows, seis targets,
dispatch, revisión cruzada/formal e integración. No se modifica la autoridad
custodial asignada al nuevo carril del coordinador. No hay puerta irreversible
necesaria para este corte. Siguiente paso: revisar/componer el candidato en SHA
exacto; los fallbacks y el inventario restante no se convierten en PASS.
