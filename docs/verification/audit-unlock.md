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
