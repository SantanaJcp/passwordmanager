# Architect R2: veredicto **PASS** (solo fuente) para D1 y D2 en `894aa3600610e23a1834d831668bf66dc2bb7112`

D1 y D2 quedan resueltos a nivel de fuente en el head final. No queda ningún P0/P1 previo. No ejecuté nada: no hubo Cargo, ni labs, ni archivos temporales. Todo lo de abajo sale de leer los objetos fijados con `git show 894…:path` y `git diff`. Las cifras de RED y GREEN son del autor, no mías.

## Comprobaciones previas (medido, solo lectura)

- Los tres SHAs (`ecc2e9d…`, `7b7026e…`, `894aa36…`) resuelven con `rev-parse --verify`, y `7b7026e` es ancestro de `894aa36`.
- El delta correctivo es un solo commit, `894aa360`: 10 ficheros, +777/−44.
- Todo el cambio de fuente queda en `connection_dispatch.rs`, `linux.rs` y `agent_wire.rs`. El resto son fixtures, el ejemplo y el informe nuevo. No hay cambios en `lib.rs` ni en ramas hermanas.

## Standards

- **`no-fallbacks`:** no aparece ningún camino alternativo nuevo.
  - La ruta `Provider::Installed` sin registro sigue rechazando.
  - Los `Failed` locales de intentos nuevos se mantienen (`linux.rs:3714-3730`).
  - El único añadido es un diagnóstico por stderr con códigos fijos y deduplicado por hilo. No incluye texto del proveedor.
- **`truthful-state`:** el informe del autor se declara ISSUES para el producto. Windows, macOS, el proveedor real y SSH real siguen NOT_RUN, y no promociona nada parcial.

## Request

- **"4 conexiones por agente" (`agent-identity.md:117`):** resuelto para agentes con identidad TLS distinta. El detalle está en D1.
- **2A, "recuperación sin repetir autenticación" e "INDETERMINATE, no FAILED artificial":** resuelto para todos los fallos locales previos al proveedor. El detalle está en D2.
- **Lo que no cambia:** revocación y cancelación siguen siendo autoridad terminal. `AUTHORITY_REVOKED` sigue intacto en `linux.rs:3671`.

## Design

### D1 (P1 en R1): **RESUELTO**

Inferido, leyendo el código en `894`:

1. **Antes de TLS, presupuesto por UID.** `RegisteredConnections::new` (`connection_dispatch.rs:133-160`) asigna a cada UID un presupuesto de `4 × N_uid`, calculado del registro validado que se carga una sola vez al arrancar (`linux.rs:1025-1034`).
   - El total de workers es `4 × N`, con `checked_mul`.
   - Las RPK duplicadas se rechazan.
   - Un UID desconocido no consigue permiso: `dispatch` devuelve `Ok(false)` en `:167-180`.
   - El permiso nativo vive dentro del cierre (`:177`), así que dura toda la conexión.
2. **Después del handshake y antes de leer el magic, presupuesto por RPK.** `admit_agent_tls` (`linux.rs:4397-4431`) se invoca en `:4342`, antes de `tls.read_exact(&mut request)` en `:4352`.
   - Termina el handshake con `complete_io`, que respeta el timeout de 15 s del socket.
   - Comprueba la ALPN y `admission.verify()`.
   - Exige que el par (RPK observada, UID) esté en el registro.
   - Toma uno de los 4 permisos de esa RPK (`connection_dispatch.rs:119`).
   - Una etiqueta del cliente no añade entradas.
3. **Liberación.** Los permisos son RAII: se sueltan al rechazar, al cerrar y si el handler entra en pánico. Además, `agent_wire.rs:83` cierra el canal tras una respuesta `[5]`. Comprobé que `[5]` solo puede ser `AgentRevoked` (`attempt_error_status`, `:370`), porque las respuestas de passkey empiezan por `0`.

**Repro original de R1 (A en UID 2001 con 4 conexiones, B en UID 2002):** en `894` B toma permisos de su propio UID y de su propia RPK, así que se admite. El autor lo midió con UIDs separados y compartidos: A4+B4, el quinto de cada uno denegado, y un quinto A sin magic cerrado antes de leer.

**Residual, sin bloqueo:** si dos RPK comparten UID, antes del handshake comparten la capacidad nativa. Un handshake que se queda colgado puede retrasar al otro hasta que salte el timeout.
- Es la misma entidad del sistema operativo, que ya puede leer la clave del otro. Por eso no hay separación que proteger, y está dentro de la latitud de representación de 1A.
- El autor lo declara en el informe (`chef-daemon-admission-20261014.md:39-41`).
- No es un hallazgo nuevo.

### D2 (P1 en R1): **RESUELTO**

Inferido. Los tres puntos que terminalizaban localmente ahora pasan por `local_provider_failure`:
- `linux.rs:3649` (fallo de custodia o falta de registro)
- `:3697` (`select`)
- `:3700` (`Installed(None)`)

Con `lease.reconciliation_only()` esa función devuelve `AttemptOutcome::Indeterminate` (`:3727`). En vault, `settle(Indeterminate)` deja `terminal=false` y `terminal_at_us=NULL` (`attempts.rs:1285ff`).

Revisé el resto del recorrido de reconciliación por si quedaba otro terminal local:
- **Adaptador controlado** (`call_controlled_provider`): un fallo de conexión o de codificación da `Err` y por tanto `Indeterminate`. Los `Failed` solo salen de un estado que reporta el propio adaptador (2/4/5/6), es decir, con evidencia del proveedor.
- **SSH** (`call_ssh_provider`): en reconciliación devuelve `WaitingForHuman` sin contactar al adaptador. El `INTEGRITY_FAILURE` local solo está en la vía de intentos nuevos.
- **Revocación:** solo `AgentRevoked`, `AccessSuspended` y `CredentialUnavailable` dan terminal, y son autoridad legítima.

No queda ningún camino que reconcilie hacia un terminal sin evidencia del proveedor o sin revocación o cancelación con autoridad. El autor midió los 8 casos RED en `7b` y los mismos 8 en GREEN, con una sola llamada de login.

**Nota heredada, no es hallazgo:** durante una caída larga, el worker vuelve a reclamar el intento cada ~100 ms (`attempts.rs:1142`). Cada `settle` añade una fila de auditoría, hasta que el intento vence a las 24 h (`ATTEMPT_LIFETIME_US`). Esa cadencia ya existía en la reconciliación. El cambio solo hace que también se alcance cuando falla la configuración o la custodia.

## Cobertura no ejecutada

Todo esto queda NOT_RUN por mi parte:
- `scripts/cargo-local.sh test -p pm-custody --locked --offline`, con las tres unitarias nuevas de `registered`.
- `chef_runtime_admission.py` y `chef_runtime_reconciliation.py`, en el namespace del ticket 03 con los mapas de subuid y subgid.
- `scripts/check.sh` una vez sobre los SHAs hermanos exactos, seguido de `kitchen integrate`.
- Windows, macOS, el proveedor real y SSH real.

## Veredicto

- **`894aa36`: PASS a nivel de fuente para D1 y D2.** Es aceptación de fuente para el merge, no una certificación nativa, de seguridad ni de G7.
- Para dar el lote por PASS falta la integración de los SHAs hermanos exactos.
