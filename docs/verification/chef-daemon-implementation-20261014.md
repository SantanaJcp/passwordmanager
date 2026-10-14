# Implementación local del daemon — 2026-10-14

Estado: **ISSUES**: registro Unix verificado localmente; proveedor y dependencias
Windows pendientes. Principios: `design`, `prove`,
`root-cause`, `no-fallbacks`, `truthful-state`, `small-owned`, `isolate`.

Base exacta `ecc2e9d390b780223dfdf1322288762f87af891c`; base de código
`d4b1be662a1b8766eff54c2b8269ef4c94770c54`. Worktree exclusivo
`/home/santana/.t3/worktrees/passwordmanager/t3-9959e6f2`, rama
`t3/daemon-readiness-registry-adapter`. [1A/2A](../../decisions.md) son la
aprobación; no se modifican eventos, grants, formatos sincronizados ni tickets.

## Registro Unix instalado

`<vault>.agent-registry` es un snapshot local del custodio, no autoridad humana.
Formato binario `PMAR1`: vault16, device16, server-RPK44, count-u16 big-endian;
por entrada RPK44 + UID-u32 big-endian. Todas las entradas deben ser completas,
únicas por RPK, distintas de identidades humanas/custodias; se exige continuidad
del par bootstrap original. El límite es **16 KiB serializados reales**, no un
límite independiente de agentes (cabecera83, entrada48: máximo339 en Unix).
No se interpreta `environment_binding` como identidad.

El archivo exige owner custodio, modo0400, archivo regular sin symlink/hardlink,
ancestros confiables y sin escritura ajena. La raíz del filesystem es el ancla
de recorrido: su owner puede aparecer sin mapear en el namespace subordinado
del laboratorio. UID0 administrativo y UID custodio pueden poseer los demás
padres; únicamente un padre sticky del owner de la raíz admite escritura ajena.
Se pinnean dev/inode/ctime/modo/longitud y bytes. Cambiar, reemplazar incluso con
bytes iguales, quitar o hacer inseguro el archivo invalida el snapshot. Cambios
administrativos requieren reinicio; no hay reload ni TOFU.

La admisión cruza UID del socket real con la RPK realmente autenticada por TLS;
la concesión/revocación vigente sigue en el motor. El hook de custodia W3 sigue
antes de admisión y nuevos usos. El snapshot local se comprueba en cada request.
Sin registro solo puede funcionar el canal humano de administración inicial;
ningún agente, incluido el bootstrap, obtiene un camino delegado alternativo.

Migración explícita, ejecutada por el custodio en una instalación aislada:

```text
pm-custody migrate-agent-registry --bootstrap /installed/bootstrap \
  --vault /installed/vault.sqlite3 --device <device-hex> \
  --agent-public /installed/B.pub --agent-uid <B-uid>
```

El par bootstrap se incorpora automáticamente **solo dentro de ese comando
explícito**. Comprueba concesiones humanas actuales de todos los RPK, verifica
vault/device/custodia y rechaza revocados/ambiguos. No sobrescribe bootstrap,
registro existente, identidad propia ni autoridad de la bóveda. Publicación
create-only por hardlink atómico de temporal sincronizado, limpieza propagada
y fsync del padre. Un fallo antes de publicar conserva el estado original; un
fallo de durabilidad posterior a publicar se informa y no elimina confianza
ya visible. No se instala ni reprovisiona ninguna identidad del host real.

## Evidencia y reproducción

Todo build/lab/check usa `flock /tmp/pm-cargo-window.lock`, toolchain inmutable
de `/home/santana/Documents/ChatGPT/passwordmanager/.toolchain`,
`RUSTUP_AUTO_INSTALL=0`, locked/offline y target privado
`target-chef-daemon-implementation`. Los labs Python reciben explícitamente
`$PWD/target-chef-daemon-implementation/debug/{pm-custody,pm,pm-web-auth}`;
no se usan wrappers que ejecuten otro `target/debug`.

RED medido del registro: [probe propio](../../crates/pm-custody/tests/chef_runtime_registry.py),
rc1 contra binarios de base construidos aquí: A+B enrolados, A descubre, TUI
real abierta, B recibe rc4/CUSTODY_UNAVAILABLE con mismo PID/bootstrap.
Log `/tmp/chef-runtime-registry-red.log`. Los binarios de base se conservan en
el subdirectorio `baseline/` del target privado.

Primera corrida posterior FAIL antes de admisión: el control de padres rechazó
el owner sin mapear de `/`/`/tmp` dentro del namespace documentado. También
expuso precondiciones de cleanup de la fixture importada cuando nunca arrancó
TUI; el probe propio ahora registra recursos realmente creados y propaga
errores. Log `/tmp/chef-runtime-registry-green.log`. No es GREEN.

GREEN medido del mismo caso: `/tmp/chef-runtime-registry-green2.log`, rc0.
A/B mismo PID/conjunto con TUI abierta, pares cruzados rechazados; migración
explícita sin sobrescritura, bootstrap conservado; corrupción, otra bóveda,
owner/modo incorrectos rechazados en startup; reemplazo de inode con bytes
iguales, retirada y cambio de permisos invalidan el snapshot en ejecución.
Revocación humana no queda anulada por registro viejo; migrar revocado falla.

Verificación ampliada `/tmp/chef-runtime-registry-green3.log`, rc0: mismo caso
más [cliente real persistente](../../crates/pm-custody/examples/chef_runtime_open_channel.rs),
que obtiene NOT_FOUND antes de la revocación y AGENT_REVOKED después **sobre
el mismo socket/TLS**, sin reconectar. Cleanup estricto comprobado. Comando
interior del lock (entorno y namespace subordinado de [03](ticket-03.md)):

```text
scripts/cargo-local.sh fmt -p pm-custody
scripts/cargo-local.sh build -p pm-custody -p pm-cli --example chef_runtime_open_channel --bins --locked --offline
# bajo unshare --user --mount con mapas reales de /etc/subuid y /etc/subgid:
python3 crates/pm-custody/tests/chef_runtime_registry.py "$PWD/target-chef-daemon-implementation/debug/pm-custody" "$PWD/target-chef-daemon-implementation/debug/pm"
```

## Fronteras pendientes

Windows carece de worker ordinario y de primitives suficientes para el registro
nuevo. Se coordinó con el dueño exclusivo de native-channel: lista de SID en
DACL agente, SID observado inmutable tras impersonación real, y archivo
instalado con owner/DACL, no reparse/hardlink, handle/fileID estable,16KiB,
revalidación y publicación no-replace. No se usa `read_bounded` de custody como
sustituto de seguridad ni se cruzan archivos reservados. Sin SHA integrado y
prueba nativa, Windows permanece **NOT_RUN / dependencia pendiente**. Darwin
comparte código Unix; compilar/ejecutar Linux no acredita macOS.

El dispatcher heredado limita **cuatro handlers globales**. No equivale a las
cuatro conexiones por agente del [contrato](../design/agent-identity.md).
No se amplían límites ni se crean workers sin cota. La prueba finita de A lleno
contra B separa esta limitación de la nueva admisión de identidades.

Fallbacks heredados conservados: accept/config/handler descartados por
`linux::accept_one`; `serve_loop` omite recuperación si falla DelegatedVault::open,
el worker descarta errores; settle de AUTHORITY_REVOKED descartado; Windows
descarta handler. Esas rutas pueden ocultar fallos al loop y no acreditan
readiness. No se autoriza aquí cambiar su política. El inventario de
[W4](w4-agents-provider.md) conserva los demás casos.

Revisión independiente configurada Claude y composición exacta corresponden
al coordinador. Sin push/PR/merge, instalación real, dispatch, release ni cierre
de tickets. G7 y las puertas humanas/nativas siguen sus estados originales.
