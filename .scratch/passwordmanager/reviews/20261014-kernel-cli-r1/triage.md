# Triage R1 — SID, config pública Windows y entrada humana

Vector: SID `ea57a717..f56c993b`; config `a900a69f..2801c489`; CLI `2f818c7..4c3a90c8`. Revisiones independientes configuradas Claude Opus 5.5 high Standard: [Skeptic](skeptic.md), [Architect](architect.md), [Minimalist](minimalist.md). Solo fuente; ninguna ejecución nativa. No P0, CLI y SID sin P1.

## Bloqueo de perfil: evidencia y alcance

Skeptic/Architect P1 (Minimalist P2): un ACE Users aplicable `0x2|0x4|0x10|0x100` hace fallar la política estricta en un ancestro. Se supone ACL stock de ProgramData; NO medido en Windows. Se conserva como riesgo de disponibilidad/fixture pendiente, no agujero probado ni razón para relajar permisos.

Comprobación directa del coordinador: `docs/design/distribution.md:44` selecciona ProgramFiles/releases para código y ProgramData para **datos**. No fija allí la nueva configuración administrativa **pública**. `InstalledConfigFile` recibe Path explícito; corpus acepta raíz ambiental explícita y no contiene guard de prefijo ProgramData. Documentación/comentario de fixture sí lo propone. Por tanto «todos los hosts/producto fallan» presupone un layout todavía no implementado. No descartamos la incompatibilidad de esa propuesta; no declaramos P1 cerrado por esta distinción.

Acción técnica reversible al mismo owner: proponer PUBLIC cfg/fixture protegida ProgramFiles/config separada de código releases inmutable y datos ProgramData intactos; documentar preflight requerido, sin fallback automático de ubicación, ampliación ACL ni instalación real. No nueva decisión sobre formato/autoridad 1A/2A. Medición ACL nativa sigue requiriendo permiso 3, no se ejecuta ni se infieren defaults de ProgramFiles. R2 solo previa objeción de perfil/proof cuando haya SHA exacto y prerrequisitos, nunca ronda genérica.

## Findings acotados aceptados

- Afirmación de handles metadata «sin share-delete» no demuestra bloqueo de rename/delete: corregir informe, preservar ACL y revalidación por nombre/identidad. No inventar locking o acceso privilegiado.
- Tests que mutan seguridad tras snapshot prueban cambio, no clasificador/ACE/owner inicial: agregar stable-bad inicial-open y ancestros. Native corpus permanece NOT_RUN.
- SID canonicalización: round-trip con formatter checked existente, liberar SID incluso con fallo; native overflow NOT_RUN.
- Documentar una conexión/instancia sin DisconnectNamedPipe; clones correctos hoy, no futuro reaccept inventado.
- Driver de negativos de owner puede requerir SYSTEM/capacidad específica; no afirmar virtual-service universal ni enabling en producto.

P2 superficie Windows `--console-diagnostics` heredada ahora pública: no leak visto, mantener visibilidad para documentación en composición. Duplicación, dos bools publicación y hardening doble son P3 no bloqueantes, no framework/refactor abierto.

API aún sin consumers Windows; provider/registry ordinarios no implementados. No Linux=Windows, G7, soporte nativo, producto terminado, ticket closure o certificación.

## Resultado de corrección recibida

`e18cf389c91623072d7e8584860e9ca85a6f5356`, delta desde `2801c489`, tres archivos propios: windows.rs, installed_config_windows.rs (tests), informe. Coordinator inspeccionó SID delta y reporte; APIs/política/16KiB/bounds no cambian. Autor shared Linux6/6/fmt/clippy0; nuevos SID/FFI/corpus Windows **NOT_RUN**. Hipótesis stock-ProgramData permanece abierta, no cerrada por sugerir otra ubicación. No R2 despachada ni dependencias integradas.

Principios: `truthful-state`, `evidence`, `prove`, `design`, `no-fallbacks`, `small-owned`, `cross-review`. Tarea correctiva: `pm-chef-20261014-native-profile-proof-r3` (followup de implementación, NO R3 de revisión).
