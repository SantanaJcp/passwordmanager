# vault-g7 — 2026-10-14

Estado: **BLOCKED para corrección productiva**, probes locales verificados.
No resuelve 28/G7 ni sustituye integración o revisión final Astra35.

Base exacta `ea57a7173424a7c607376ff5e0b49d2a19bc334f`; baseline de código
`d4b1be662a1b8766eff54c2b8269ef4c94770c54`. T3 y Git confirmaron rama
`t3/g7-stream-staging`, worktree
`/home/santana/.t3/worktrees/passwordmanager/t3-aff64197` antes de escribir.
Solo se añaden este informe, el [probe G4](../../crates/pm-vault/tests/g7_prepared_stream.rs)
y el [witness de pérdida](../../crates/pm-vault/examples/g7_loss_witness.py);
fuentes productivas intactas.

## Evidencia medida

Todos los builds/Cargo/labs usan bloqueo exclusivo
`flock /tmp/pm-cargo-window.lock`, toolchain inmutable de la raíz histórica y
`CARGO_TARGET_DIR=$WORKTREE/target-chef-vault-g7`. Build propio:
`./scripts/cargo-local.sh build -p pm-custody -p pm-cli --locked --offline`,
rc0, log `/tmp/chef-vault-g7-build.log`.

Se invocaron los fixtures Python directamente en el namespace UID del wrapper,
con **binarios propios explícitos**
`$WORKTREE/target-chef-vault-g7/debug/{pm-custody,pm}`. No se ejecutó el wrapper:
`scripts/verify-ticket28-custody-loss.sh` construye en CARGO_TARGET_DIR pero
selecciona `$WORKTREE/target/debug`, seam fuera de este allowlist.

Namespace reproducible (anteponer flock a cada invocación):

```bash
worker=$(id -un)
subuid=$(awk -F: -v user="$worker" '$1 == user {print $2; exit}' /etc/subuid)
subgid=$(awk -F: -v user="$worker" '$1 == user {print $2; exit}' /etc/subgid)
ns=(unshare --user --pid --fork --mount-proc
    --map-users "0:$(id -u):1" --map-users "1:$subuid:65535"
    --map-groups "0:$(id -g):1" --map-groups "1:$subgid:65535")
bin="$PWD/target-chef-vault-g7/debug"
fixtures="$PWD/crates/pm-custody/tests"
export PYTHONDONTWRITEBYTECODE=1
flock /tmp/pm-cargo-window.lock "${ns[@]}" python3 "$fixtures/sqlite_sync_fault_lab.py" \
    "$bin/pm-custody" "$bin/pm" "$fixtures/sqlite_sync_interposer.c" matrix
flock /tmp/pm-cargo-window.lock "${ns[@]}" python3 "$fixtures/custody_loss_lab.py" \
    "$bin/pm-custody" "$bin/pm" vault
```

Originales intactos, logs `/tmp/chef-vault-g7-red-{matrix,bootstrap,vault}.log`:

- Matrix rc1: exactamente commit/outbox/audit EIO+ENOSPC, syscall fsync índice8;
  rc4, `authority-atomic=1`, staging1/streams1/chunks17 tras fallo/reinicio.
  Las demás fronteras WAL/staging/audit pasan; todos los cleanup errors=0.
- Vault rc1: `unchanged=(1,0,1,1,1)`, replacement=0, closed=1, cleanup=0;
  solo difiere conteo de auditoría. Proveedor antes/después de pérdida calls=1.
- Bootstrap rc0 en esta muestra: conteos iguales, replacement=0, closed=1,
  provider-calls=1 y cleanup=0. No atribuir corrección a este PASS intermitente.

Las hipótesis contrastadas son preparado durable G4 retenido, reconciliación
auditada del intento ambiguo, o mutación indebida de autoridad/receipt. El probe
Python compara filas completas en snapshot read-only, prefijo histórico de
auditoría y calls=1; conserva las aserciones/cleanup/rc del fixture original.
El probe Rust rechaza el commit final mediante trigger audit real, exige
rollback de todas las filas, reapertura con HumanUnlock auditado, mismo
preparado/firma, contenido exacto, limpieza al éxito y receipt/replay sin efecto
duplicado. Es cobertura del comportamiento existente, **no RED→GREEN de fix**.

Witness ejecutado con el mismo namespace/binarios, sustituyendo el fixture por
`crates/pm-vault/examples/g7_loss_witness.py` y argumentos bootstrap/vault,
con/sin `completed`. Logs `/tmp/chef-vault-g7-witness-*.log`:

- Bootstrap ambiguo rc1 y vault ambiguo rc1: auditoría10→12, dos filas nuevas,
  prefijo cifrado íntegro, todas las filas completas de las11 tablas de
  autoridad idénticas, mismo estado INDETERMINATE y provider-calls=1.
- Ambos controles `completed` rc0: auditoría10→10, filas/prefijo exactos,
  mismo SUCCEEDED, calls=1. Los cuatro cleanup errors=0.

La hipótesis de mutación final de autoridad/receipt queda refutada en estas
muestras; la de reconciliación auditada concuerda con el control completado y
el código. No se descifra aquí el log ni se acredita cada instante intermedio.

Gate focalizado rc0, **34 tests**, log `/tmp/chef-vault-g7-focused.log`:

```sh
flock /tmp/pm-cargo-window.lock ./scripts/cargo-local.sh test -p pm-vault \
  --test g7_prepared_stream --test human_transactions --test content_records \
  --test backup_lifecycle --test history_lifecycle --locked --offline
```

Incluye probe1, transacciones4, contenido5, backup/W7/restored streams21 e
historia/restore3. Compilación sin errores previos; no RED artificial. El probe
G4 preservó chunks exactos tras fallo/reapertura y produjo contenido exacto,
un único commit/receipt, cero staging al éxito y un HumanUnlock adicional.
Su directorio propio se retiró comprobando ausencia antes de éxito.

## Causa y frontera de decisión

Inferido de `human.rs:1687–1930`: prepare persiste el ciphertext ligado al body
firmado; rollback del commit final restaura ese preparado. Borrar sus chunks
haría imposible retry G4. `human_transactions.rs` exige expresamente retry del
mismo preparado y receipt tras respuesta perdida. G7 exige reconciliar la
limpieza sin perder intención durable; no se seleccionó representación y
transición de retención/reconciliación en este encargo.

Inferido de `attempts.rs:1135–1237,1285–1364`: reclamación de reconciliación y
settle escriben auditoría; el provider lab opcode2 consulta sin incrementar
calls. `custody_loss_lab.py:136` compara también conteo del log activo.
No se suprime HumanUnlock ni reconciliación para satisfacer ese conteo.

Opciones estructurales, ambas puertas de propietario (`doors`):

1. **Recomendada:** intención cifrada durable con ciclo explícito de recuperación,
   retención/expiración y transición terminal, separada de temporales; preservar
   replay firmado y receipt. Requiere decisión sobre representación/schema y
   ajuste autorizado del oráculo para distinguir ambas formas; renombrar tablas
   no constituye solución.
2. Aborto durable al fallar, retirando únicamente payload propio y exigiendo
   prepare/firma nuevos. Reduce el retry actual; requiere autorización expresa
   y nuevo contrato/test G4. No implementado.

## Fallbacks heredados y límites

Inferidos, preservados: `pm-custody/src/linux.rs:939` ignora error del worker;
`run_provider_once` convierte error de proveedor en Indeterminate. Activan ante
fallo de ejecución/settlement y ocultan la causa al loop, manteniendo el estado
ambiguo. `backup.rs:526` convierte fallo SQL a false/Integrity y `:1029` fallo
de conversión a i64::MAX. No se modifican ni se introduce fallback.

Medido: `flock /tmp/pm-cargo-window.lock ./scripts/check.sh` rc0, una ejecución,
log `/tmp/chef-vault-g7-check.log`; config/fmt/check/tests/clippy workspace/all-targets
locked/offline. AST Python, diff-check y enlaces locales del informe pasan.
Este check no ejecuta los RED de los labs ni los convierte en GREEN. No barrida52, clean
global, W4, integración, publicación, dispatch ni aceptación Windows/macOS;
no cambios de auth/schema/wire/KDF/plazos/replay. Los artefactos privados propios
se conservan; no se borran targets ni fixtures ajenos.

Siguiente paso: decisión del propietario sobre composición G4/G7 y encargo al
dueño del verificador para separar autoridad/receipts del log de reconciliación,
manteniendo prefix íntegro, ausencia de login repetido y cleanup estricto.
