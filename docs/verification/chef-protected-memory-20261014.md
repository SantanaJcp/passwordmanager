# Protected-memory — candidato local 2026-10-14

Estado: **ISSUES**; tres casos de memoria RED→GREEN y check Linux rc0;
seam Windows autorizado implementado pero sin ejecución nativa.
No resuelve ticket28/G7 ni acredita aceptación nativa o revisión formal35.

Medido antes de escribir: pwd/top-level/T3 binding
`/home/santana/.t3/worktrees/passwordmanager/t3-a69e62ca`, rama
`t3/protected-memory-exposures`, checkout limpio, base exacta
`ea57a7173424a7c607376ff5e0b49d2a19bc334f` (baseline de producto
`d4b1be662a1b8766eff54c2b8269ef4c94770c54`). HEAD final en el handoff.
Solo root.rs, dos tests nuevos pm-crypto, windows.rs (seam añadido por el
coordinador durante el encargo) y este informe; ningún caller ajeno.

## Causa y cambio

Inferido de [root.rs](../../crates/pm-crypto/src/root.rs): siete destinos
Ed25519 expandidos eran arrays64 en stack; ambos verificadores de grant abrían
el contexto con clave secreta en Vec ordinario. La firma y los dos grants
aceptaban nuevos secretos después de denegar nuevos locks.

Ahora esos destinos son `ProtectedBytes`, bloqueados antes de la llamada FFI,
con error `ResourceUnavailable` y drop/wipe en éxito y error. El parser valida
la longitud32 del campo key por una vista prestada, sin copiar la clave que
no utiliza. Para memoria, APIs, wire, autoridad, KDF, deadlines y presupuesto permanecen.
Costo inferido: un owner64 transitorio por derivación/firma y un owner exacto
por verificación de grant, sujetos a los presupuestos existentes (también
cargo de páginas Windows); puede rechazar una operación antes admitida sin
protección. Ningún cambio al allocator ni a W5/W7.

## Evidencia medida

Toolchain inmutable de raíz `.toolchain`, homes explícitos, PATH cargo/bin;
`CARGO_TARGET_DIR=/home/santana/.t3/worktrees/passwordmanager/t3-a69e62ca/target-chef-protected-memory`.
Todos los comandos Cargo/rustfmt/check bajo `flock /tmp/pm-cargo-window.lock`.
Los padres ejecutan `current_exe()` del test de ese target privado y los hijos
sólo alteran su propio RLIMIT_MEMLOCK. No wrapper ni target/debug alternativo.

- RED firma: `scripts/cargo-local.sh test -p pm-crypto --test protected_signing --locked --offline`, rc101,
  `/tmp/chef-protected-memory-red.log`. Control RFC8032 §7.1 TEST1 válido;
  después memlock0 devuelve Ok(signature) frente a ResourceUnavailable.
- RED grants: `scripts/cargo-local.sh test -p pm-crypto --test protected_grant_context --locked --offline`, rc101,
  `/tmp/chef-protected-memory-grant-red.log`. Ambos controles válidos;
  ambos retornan Ok frente a ResourceUnavailable. Ejecutado después del cambio
  de firma, antes de modificar los destinos de grant; no se atribuye todo al
  mismo árbol base.
- GREEN: `scripts/cargo-local.sh test -p pm-crypto --test protected_signing --test protected_grant_context --locked --offline`, rc0,
  `/tmp/chef-protected-memory-green.log`: firma1/1 y grants2/2. Helpers
  ignored ejecutados por sus padres; controles RFC/grants y memlock0 reales.
- `scripts/check.sh` una vez: rc0, `/tmp/chef-protected-memory-check.log`;
  config/fmt/check/test/clippy workspace locked/offline. Sin warnings/errors
  observados. Incluye las regresiones no-prefetch/protected-writer/exact-size/
  wipe vigentes; cfgWindows no compilado ni ejecutado. No clean ni barrida52.

Las entradas ignored son helpers ejecutados por sus tests padres, no aceptación
omitida. Estas pruebas discriminan reserva/lock real y conservan resultado
criptográfico; no acreditan ausencia universal de secretos en memoria/dumps.

## Gaps finitos y seams (inferidos, sin nueva aceptación runtime)

| Lugar | Pendiente y siguiente acción concreta |
| --- | --- |
| `SyncPairing::to_protected_bytes/open`, `AuditDeviceKeyPair::to_protected_bytes` | APIs devuelven Vec con material secreto; migrar retornos exige callers de otros carriles. Reportar seam, no cambiarlo unilateralmente. |
| `PasskeyKeyPair::from_seed/seed`, `LockedKey::new`, parsers de claves | Arrays de semillas/claves por valor; transición a vistas/owners exige callers. |
| `RecoveryCode::Display/FromStr`, `recovery_checksum`, `hex` | String/Vec/intermedios de recuperación; salida protegida explícita requiere coordinación humana/wire. |
| `encode_wrapped_key/encode_sealed_key`, `open_audit_key/open_attempt_key` | Encoders de claves y dos destinos sealed-box siguen ordinarios. Próximo RED: instrumentar destino FFI con canario propio/lock, no confundir fallo posterior de Secret::new con reserva antes de decrypt. |
| `SecretStreamState` | Estado secretstream propio embebido/movible sin lock; requerirá owner nativo alineado y prueba directa del estado antes de inicializar. |
| Windows `OwnedClipboard::copy_then`, `crypt`; macOS `macos_clipboard.m` | UTF16 Vec, salida DPAPI LocalAlloc y NSString; no ejecutados aquí. RED nativo antes de migrar helper propio; heaps/clipboard del SO conservan sus límites. |

Fallbacks: no añadido ni alterado en este corte; en `dpapi_unprotect` el fallo
ProtectedBytes se agrupa como `ChannelAuthenticationError`, ocultando la
categoría de alloc/lock (sin devolver plaintext alternativo). Se preserva.
Inventario global/fallbacks heredados de fase4 en [ticket28](ticket-28.md#inventario-de-fase-4-y-fronteras-conservadas).
W5 GREEN histórico leído en [integración](integration-26-28.md), no revalidado
nativamente por estos tests Linux. Heaps internos de libsodium/KDF/TLS,
registros/stack del compilador, swap/FDE y recolectores externos no acreditados.

No cambio de puerta de una vía en este candidato. Para seams públicos futuros:
A) ownership protegido de extremo a extremo, con cambio coordinado de callers;
B) escritura por callback hacia un destino protegido propiedad del consumidor,
sin devolver secretos por valor. Recomendación A por menor complejidad y una
única representación; requieren asignación/decisión antes de ejecutar el seam.
Siguiente paso: revisar/integrar este candidato exacto, luego asignar un RED
nativo o FFI de uno de los gaps. Sin nueva investigación general, dispatch,
publicación, clean compartido ni barrida52. Gates nativos/humanos y tres G7 REDs
históricos siguen pendientes; revisión final Astra permanece35.

## Seam Windows 1A añadido por autorización expresa del coordinador

Commit nativo exclusivo: `f56c993b2ba3d770f6aae7f5c3401bf0263d98e1`.

Inferido, **sin build/RED/GREEN Windows**: `WindowsServerPipe` añade
`create_agent_instance_for_sids(vault, service_sid, client_sids: &[String], stop, first, instances)`
y `accepted_client_sid(&self) -> Result<&str, ChannelAuthenticationError>`.
La lista requiere rol service S-1-5-80/user S-1-5-21, SID decimal canónico
validado por Windows, sin duplicados/vacíos/broad principals. Texto agregado
de client SIDs <=16 KiB es condición necesaria derivada del config del daemon,
no un cap64 ni prueba de cabida de JSON/framing completo. DACL/kernel valida
la representación final. Cada cliente recibe máscara0x0012019b: data I/O, sin
FILE_CREATE_PIPE_INSTANCE; pipe LOCAL/PIPE_REJECT_REMOTE_CLIENTS.
Instancias preservan exactamente `2..255` de Rust (2–254, 255 rechazado).

El SID guardado procede únicamente de impersonación kernel tras accept
válido/list membership; accessor conserva verify de PID/liveness y falla
sin captura. Nuevo accept elimina estado previo antes de conectar; clone
copia la captura de ese owner. No vincula por sí solo SID con TLSRPK/grant: eso
pertenece al daemon. Caller single-SID mantiene constructor/ACL y comportamiento.

Dos tests source-local Windows preparados: descriptor nativo/ACE exactos y
negativas de SID/byte-bound/instancias; pipe real con SID observado segundo
en la lista, captura antes/después de accept, clones, disconnect y mismatch
con borrado de captura previa. No mocks que anuncien identidad nativa.
Los tests permanecen cfgWindows y **no ejecutados por Linux check**; ningún
dispatch autorizado. Constructor nuevo propaga release/close sin éxito falso.
Heredados preservados: `create_role_instance` ignora retorno LocalFree del
descriptor, `impersonated_client_sid` ignora CloseHandle(token), `sid_string`
ignora LocalFree del string: falla cleanup tras sus operaciones, ocultándolo.
No se alteraron por este seam ni se añade camino de recuperación alternativo.

El coordinador añadió después el seam de config instalada Windows. Se propuso
capability owned con open/read_bounded/verify_snapshot/close y provision_new
mediante staging propio + rename por handle sin replace. **Aún no implementado**:
se pidió el perfil preciso de ancestros Windows (config/directorio privado
SY/service frente a ProgramData/volumen con BA/TrustedInstaller), sin inventar
trust principals ni permitir el installer S-1-5-21 del fixture histórico.
Daemon puede continuar Unix; Windows no gana una validación por symlink_metadata
+ fs::read ni por reutilizar open_regular_file sin consulta de ACL.
