# Integración común de auditoría en desbloqueo humano

## Procedencia y alcance

Esta integración trasplanta únicamente el cambio común y portable preparado
por Sol23 para el primer registro de auditoría durante el desbloqueo humano.
La fuente exacta es el rango `9878bc6..360f5b3` del worktree 27. Se aplicó con
un merge de tres vías sobre root `d6c2ce8`, limitado a:

- `crates/pm-vault/src/human.rs`;
- los archivos modificados bajo `crates/pm-vault/tests/`;
- los archivos modificados bajo `crates/pm-sync/tests/`;
- `crates/pm-custody/src/linux.rs`.

El diff fuente modifica 14 archivos dentro de esa lista y los 14 se aplicaron
limpiamente. Se excluyeron de forma deliberada el port Windows
`crates/pm-custody/src/windows.rs`, `docs/verification/ticket-27.md` y
`scripts/verify-windows-libsodium-build.sh`; por tanto este commit no acredita
ni completa Windows. Tampoco modifica TUI, los cleanups ya compuestos ni código
fuera de esos paths.

## Contrato compuesto

`HumanVault::unlock` recibe siempre la `AuditDeviceCustody` estable y explícita
del dispositivo. Tras autenticar contraseña/root y revalidar el canal humano,
la misma transacción SQLite `IMMEDIATE` obtiene la frontera, asegura la
generación correspondiente y confirma el primer evento
`HumanUnlock/Succeeded` antes de devolver la sesión. Un fallo de paquete,
evento, estado, segmento o commit revierte el conjunto y no entrega una sesión.
Una contraseña errónea no crea auditoría. Una custodia de reemplazo explícita
durante apertura humana autenticada abre la generación enlazada; la apertura
autónoma no puede usar ese camino.

La antigua entrada que fabricaba una custodia aleatoria por llamada desaparece:
no queda alias, cache global, fallback ni apertura humana sin auditoría. Los
fixtures comunes conservan una custodia por dispositivo y actualizan sus
secuencias para incluir el evento inicial. El servidor Linux pasa su custodia
ya estable al único entrypoint.

## Verificación de integración

Antes de Cargo se exige `git diff --check`, ausencia de conflictos/markers,
diff limitado a los paths enumerados y comprobación estática de que los
consumidores comunes llaman la firma única con cinco argumentos. El port
Windows excluido puede conservar temporalmente el nombre anterior y no se usa
como prueba de esta composición Linux.

Con ventana Linux local exclusiva se ejecutará, sin retries ocultos:

1. `scripts/check.sh`;
2. `scripts/clean-offline-build.sh`;
3. una sola barrida secuencial, ordenada y con exit propagado, de los 20
   `scripts/test-linux-*-lab.sh`, usando los artefactos Keycloak/CFT fijados.

Se conservará un log por gate/lab y un contador final. Éxito requiere rc0 de
check y clean, `count=20 failures=0`, cero procesos/residuos propios y root
limpio después del commit de evidencia. Este resultado será únicamente Linux
x86_64 de integración: no será revisión formal, ejecución Windows, publicación
ni resolución del ticket nativo.

## Evidencia de composición en curso

El primer `scripts/check.sh` de root se conserva en
`/tmp/pm-audit-unlock-root-check.log` y terminó rc101. No fue un RED del motor:
la composición detectó que el test de retiro causal añadido en root después del
baseline fuente aún llamaba dos veces al helper migrado sin entregar custodia.
El compilador señaló exactamente las líneas 442–443 de
`e2ee_replication.rs`; no hubo otro fallo. La corrección de integración crea una
custodia sintética estable por cada uno de esos dos dispositivos y la pasa al
helper, igual que los demás fixtures migrados. No cambia producto, aserciones,
retiro causal ni la fuente importada. Los siguientes gates se registrarán como
intentos separados, no se sobrescribe este log.

La primera barrida completa de labs se conserva en
`/tmp/pm-audit-unlock-root-labs-summary.log`: ejecutó los 20 scripts una vez y
terminó `count=20 failures=4`. Los fallos 1PUX/backup comparaban todos los
conteos con el snapshot anterior aunque cada comando humano autenticado ahora
confirma legítimamente un `HumanUnlock`; se mantienen iguales todas las tablas
no audit y se exige un delta audit exacto de uno por unlock. Los fallos content
y human-transaction vienen del mismo `linux_lab.py`: su trigger incondicional
abortaba el nuevo `HumanUnlock` antes de alcanzar el commit CRUD que pretendía
probar. Se condiciona el trigger para aceptar sólo ese primer registro y
rechazar el siguiente; siguen exigidos staging/challenge de la operación,
rollback completo de sus tablas y conteos separados de un unlock más tres
mutaciones exitosas. No se cambió producto ni se rebajó una aserción a cero.
