# Windows SQLite observer — diagnóstico local, 2026-10-14

Resultado: **PASS del diagnóstico local**; RETIRE nativo **NOT_RUN**, causa histórica
desconocida. No retiro aceptado, cierre27, revisión35 ni soporte Windows anunciado.

Medido: binding T3/worktree `/home/santana/.t3/worktrees/passwordmanager/t3-424546e4`,
rama `t3/reconcile-windows-retire-observer`; base exacta
`872a880e2549a65f93f33c58da961f4dfdea1a94`. HEAD: commit que añade este informe.
La ampliación explícita del follow-up autoriza sólo ejemplo/helper/probe/informe;
el plan local leído aún contiene la allowlist anterior. No se modifica ese registro.

## Seam y comportamiento

Inferido del diff: `windows_human_tui_seed.rs` llama al helper local
`windows_human_tui_seed/observer.rs` para ambos observers. Ese mismo helper
se ejecuta en tests del ejemplo Linux mediante cfg(test), sin API nueva del producto.
El caller Windows imprime el diagnóstico en stderr y conserva
`Failure::Unavailable`, `WINDOWS_HUMAN_FIXTURE_FAILED` y exit1.

Se mantienen READ_ONLY, los dos SELECT de sync, SELECT exacto de retiro,
sujeto0x28×16, count==1, ambos conteos sync>0 y close comprobado antes de PASS.
Las dos salidas exitosas son idénticas. No cambian producto/roster, selección,
schema, replay, KDF, parser VT ni15s; cleanup W1 y W7 no se vuelven a editar.
El informe anterior permanece intacto.

Forma de diagnóstico: prefijo `WINDOWS_SQLITE_OBSERVER`, operación sync/retire,
fase open/blocks-query/roots-query/retire-query/blocks-count/roots-count/retire-count/close.
Categorías sqlite/read-type/sqlite-api/count-mismatch; primario y extendido
numéricos tomados del error SQLite real. Errores de API sin esos códigos emiten
not-available, nunca0 inventado. Sólo mismatch imprime conteo realmente leído;
fallo de consulta no imprime conteo. Sin Display/Debug del error, SQL, paths,
row values, IDs o payload. Una falla produce una línea; primaria+cierre producen
dos, primaria primero. Un cierre fallido impide salida PASS aunque la consulta pase.

## RED → GREEN medido

Entorno exacto para todas las ejecuciones Cargo/build/lab:
`flock /tmp/pm-cargo-window.lock bash -c '<exports>; <command>'`, con
RUSTUP_HOME=`/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/rustup`,
CARGO_HOME=`/home/santana/Documents/ChatGPT/passwordmanager/.toolchain/cargo`,
CARGO_TARGET_DIR=`/home/santana/.t3/worktrees/passwordmanager/t3-424546e4/target-chef-windows-acceptance`,
RUSTUP_AUTO_INSTALL=0 y PATH=`$CARGO_HOME/bin:$PATH`.

Comando exacto enfocado:
`./scripts/cargo-local.sh test -p pm-custody --example windows_human_tui_seed --locked --offline`.

- RED inicial: extracción que preserva el colapso anterior; compiló y falló3/3
  por error genérico en tabla ausente, conteo0 y roots ausente. Log retire-red.log.
- RED completo: mismo comando, siete casos; compiló y falló7/7. Cierre SQLite
  BUSY real y primaria+cierre también devolvían sólo error genérico.
  Log retire-close-red.log. No se considera compilación fallida como RED.
- GREEN: mismo comando7/7 rc0; log retire-green.log. Refuerzo posterior combina
  error primario y cierre BUSY de la misma conexión:7/7 rc0,
  log retire-final-green.log. No simulación de un error Win32 ni causa nativa probada.

Los controles independientes cubren positivo1, negativo0, duplicados2,
wrongsubject y wrongkind; sync exitoso1/1 conserva salida exacta.
Tabla ausente da códigos1/1; abrir archivo inexistente READ_ONLY da14/14 y no
crea archivo; valor TEXT donde se pide i64 da read-type sin valor ni códigos falsos.
Una sentencia raw pendiente provoca close BUSY5/5 real; el test finaliza esa
sentencia y cierra la conexión recuperada antes de terminar. Las fixtures SQLite
propias se eliminan con errores de cleanup visibles. No writer sustituye el
observer READ_ONLY; SQL de tipo incorrecto/cierre BUSY son controles sintéticos
en sus funciones internas compartidas.

Probe adaptado al nuevo archivo/constante:
`python3 crates/pm-native-channel/tests/chef_retire_observer_probe.py`, bajo flock:
5/5 rc0, retire-sql-probe.log. Primera adaptación falló5/5 porque rustfmt partió
la constante; regex ajustada sólo para whitespace, sin valores sustitutos.
`scripts/check.sh` ejecutado una sola vez en el target existente: **rc0**, config,
fmt y Cargo check/test/clippy del workspace locked/offline. Log retire-check.log.
`git diff --check` rc0 y alcance de archivos comprobado; no manifests/deps nuevos.
Logs bajo target-chef-windows-acceptance, generado preservado sin commit.

## Evidencia que falta y siguiente acción

Windows real **NOT_RUN**: no dispatch/push ni presupuesto nativo autorizado.
Linux ejecuta el helper exacto, pero no compila/ejecuta el caller cfg(windows),
DACL, SCM, WAL/SHM o SQLite Windows. Ningún GREEN anterior resuelve RETIRE durable.
Captura necesaria: mismo run nativo autorizado de SYNC/RETIRE, stderr del observer
con sus líneas categóricas y exitcode, junto con resultado TUI, SCM detenido y
cleanup estricto. No repetir RETIRE ni abrir writer/immutable/copia/checkpoint
como alternativa. Clasificar sólo después de esa captura la fase y causa.

Inferido, heredado sin modificar: los otros errores del ejemplo siguen
colapsando a Failure::Unavailable; activan al fallar esas operaciones y ocultan
su causa. `rusqlite::InnerConnection::drop` ignora el resultado de close cuando
se abandona una conexión; incluido el objeto devuelto por close Err. Se conserva
ese mecanismo y ahora se comunica el fallo del close explícito. Las omisiones
Drop/LocalFree/DestroyWindow y cleanup de pm-sync ya registradas permanecen intactas.
No puerta de una vía ejecutada ni cambio contractual requerido.
Principios: root-cause, prove, truthful-state, no-fallbacks, small-owned, isolate.
