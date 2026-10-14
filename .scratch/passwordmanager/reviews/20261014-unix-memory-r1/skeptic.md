Ya tengo todo lo necesario; redacto el veredicto.

# Skeptic R1: veredicto por candidato

**Resultado:**
- **Daemon `7b7026e`: ISSUES, con 2 bloqueantes P1.**
- **Memoria protegida `a900a69`: PASS a nivel de fuente.** Quedan dos P2.
- **SSH `15bfaa2`: PASS a nivel de fuente.** Sin hallazgos.

No ejecuté nada: ni Cargo, ni labs, ni archivos temporales. "Medido" en este informe significa solo inspección de solo lectura con `git show` y `git diff` sobre SHAs fijados. Las cifras de RED y GREEN son del autor, no mías.

Comprobado (medido): los 6 SHAs resuelven, cada base es ancestro de su head y los diffstat cuadran con el alcance declarado. En el rango del daemon también está `6728bbd` (retirado). Juzgo solo el árbol final en `7b7026e`, donde `safe_parent` vuelve a exigir dueño 0 o el UID actual (`installed_unix.rs:40`).

## Standards

- **AGENTS.md, "no tratar documentación como seguridad validada":** los tres informes se ajustan. Se declaran ISSUES o parciales y marcan Windows, macOS y el proveedor real como NOT_RUN. Sin hallazgo.
- **AGENTS.md, "nunca credenciales reales":** todos los fixtures son sintéticos (semilla RFC 8032, `PM_CHEF_SYNTHETIC_*`). Sin hallazgo.

## Request

- **1A, "admisión requiere ambas fuentes vigentes":** cumple. `accept_one` (`linux.rs:4188`) restringe por UID nativo. `handle_connection` vuelve a cruzar el par (RPK observada, UID). En cada petición se reabre `DelegatedVault`, así que la concesión humana sigue siendo la autoridad. `migrate` exige la concesión vigente de cada RPK (`installed_unix.rs:256-262`). No hay TOFU ni aprendizaje desde etiquetas.
- **2A, "usa la reconciliación existente" y "recuperación sin repetir autenticación":** cumple solo **en parte**, ver P1-1.
- **G4 (`agent-identity.md:117`), "4 conexiones por agente":** queda incumplido una vez hay varios agentes, ver P1-2.

## Design: hallazgos

### P1-1 · BLOCKER · `truthful-state`, `no-fallbacks`

**Dónde:** `7b7026e`, `crates/pm-custody/src/linux.rs:3636-3643` y `3686-3697`, más `installed_unix.rs:385,395,396`.

**Qué pasa:** un lease de reconciliación se cierra como FAILED terminal sin ninguna evidencia del proveedor. `claim_waiting_for_reconciliation` reclama intentos `indeterminate` y `waiting_for_human` (`pm-vault/src/attempts.rs:1144`). Si la custodia no verifica o falta el registro, `use_provider` devuelve `Failed{CUSTODY_UNAVAILABLE}`. Si el adaptador no está disponible o no hay ruta, `call_provider` devuelve `Failed{ADAPTER_UNAVAILABLE | UNSUPPORTED_INTEGRATION}`. `settle(Failed)` es terminal.

**Secuencia que falla:**
1. Un intento `github-rest-bearer` termina INDETERMINATE: hubo timeout tras el envío, o un crash seguido de `recover_inflight`.
2. El adaptador externo se reinicia (el socket desaparece un momento), o se retira o cambia `.adapters`.
3. Pasados unos 100 ms, el worker reclama el intento, `endpoint_ready` falla y el estado queda FAILED terminal.

El camino de laboratorio de la base trata el mismo fallo de conexión como `Err(()) → Indeterminate` (`linux.rs:3674`).

**Por qué bloquea:** contradice `agent-identity.md:152` ("Al vencer ejecución sin evidencia: INDETERMINATE, no FAILED artificial") y la tabla de estados de `spec.md:305`. El ciclo de vida externo del adaptador forma parte de 2A, así que estos reinicios son esperables.

**Origen y cobertura:** el bug es nuevo. Ni `use_provider` ni `call_provider` existían en `ecc2e9d`. La prueba de retirada de config (`chef_runtime_adapter.py:209-216`) solo cubre intentos **nuevos**.

**Evidencia:** inferida, leyendo el código.

**Prueba que lo atraparía (no ejecutada):** extender el lab adapter. Llevar `page=9` a INDETERMINATE, luego desenlazar el socket o `.adapters`, esperar 1 s y comprobar que el estado sigue INDETERMINATE con 0 llamadas nuevas.

### P1-2 · BLOCKER para aceptar 1A como multiagente usable · `truthful-state`, `design`

**Dónde:** `7b7026e`, `linux.rs:4181-4214` y `connection_dispatch.rs:10,45`.

**Qué pasa:** `MAX_AGENT_CONNECTIONS = 4` sigue siendo un único contador global en la vía de agentes. Con `ecc2e9d` solo un UID podía conectar, así que en la práctica era un límite por agente. `7b7026e` admite varios pares del registro, y el agente A puede ocupar los 4 slots (hasta 5 min cada uno por el timeout de inactividad) y dejar fuera al agente B.

**Origen y evidencia:** el mecanismo es heredado, pero que se pueda alcanzar es nuevo. El autor lo midió (A ocupa todo, B queda denegado: dato del autor). Mi conclusión es inferida.

**Alcance:** no bloquea los candidatos de memoria. No pido una arquitectura concreta. Solo constato que no puede presentarse como PASS parcial.

### P2-1 · `no-fallbacks` (heredado, ahora activado)

**Dónde:** `linux.rs:804`, `961` y `975`.

**Qué pasa:** `serve-vault` ordinario ahora siempre arranca el worker y `recover_inflight`.
- **Fallback heredado en `:961`:** si `DelegatedVault::open` falla al arrancar, se omite `recover_inflight` en silencio y los intentos `running` quedan atascados hasta otro reinicio.
- **Fallback heredado en `:975`:** errores descartados con `let _ =`.
- **Coste:** a partir de ahora, todo daemon ordinario sondea cada 5 ms con dos transacciones IMMEDIATE.

El autor lista estos fallbacks. Lo nuevo es que ahora actúan también en el daemon ordinario. Evidencia inferida; el coste no está medido. No pido cambiarlos.

### P2-2 · `prove`

**Dónde:** `7b7026e`, sin pruebas de Rust para `Registry::parse`, `parse_routes`, `safe_parent` ni `read_installed`.

**Qué pasa:** la regresión depende de labs de Python que requieren root, namespace y chroot, y no están en `scripts/`. Medido: `git grep chef_runtime` no devuelve nada.

Un detalle menor: `chef_runtime_adapter.py:173` acepta CANCELLED **o** INDETERMINATE como resultado válido.

### P2-3 · `prove`

**Dónde:** `a900a69`, `pm-crypto/src/root.rs`.

**Qué pasa:** solo `sign_detached` (vía `PasskeyKeyPair::sign`) y los dos sitios de grant tienen una prueba que fallaría si se revierte el cambio. Los otros 6 destinos Ed25519 (`generate`, `from_seed`, `AuditDeviceKeyPair`, `create_human_root`, `unlock_with_key`) y el préstamo en `decode_sealed_key_context` (`:4434`) podrían revertirse sin que ninguna prueba falle. Evidencia inferida.

**Resto del candidato:** `decoder.bytes()` y su comprobación de longitud producen el mismo `InvalidFormat` que `decode_bytes` (`:5382`), así que no hay cambio de comportamiento. `ProtectedBytes::allocate` comprueba `sodium_mlock` explícitamente, sin fallback (`:224-235`). KDF, wire y presupuesto no cambian.

### SSH `15bfaa2`: sin hallazgos

- `field_parts` codifica el frame con el mismo layout que `put_bytes`: opcode, longitud u32 big-endian y datos.
- `MAX_FRAME` se sigue aplicando en `write_frame`.
- El JSON se reproduce byte a byte, y la prueba lo compara con un literal independiente.
- La prueba de puntero en `parse_consumer_reference` detectaría que se vuelva a copiar el texto.

Siguen pendientes, y el autor ya los reconoce: el buffer de referencia retenido y los buffers de terceros.

## Cobertura no ejecutada

Todo esto es NOT_RUN:
- `cargo test -p pm-crypto --test protected_signing --test protected_grant_context`
- `cargo test -p pm-ssh-client wire_memory_tests`
- `python3 crates/pm-custody/tests/chef_runtime_chroot.py {registry,adapter} …` bajo el namespace subuid/subgid del ticket 03
- `scripts/check.sh` completo (el autor no tiene un rc0 global)
- Windows, macOS, proveedor real e integración de los SHAs hermanos exactos

Esto es una revisión de fuente para aceptar o no el merge, no una certificación nativa ni de seguridad.
