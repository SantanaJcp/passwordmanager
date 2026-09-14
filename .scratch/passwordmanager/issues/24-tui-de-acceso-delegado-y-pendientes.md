# 24 — TUI de acceso delegado y pendientes

Type: task
Status: resolved
Owner: sol-24
Blocked by: 08,13,23
Spec: ../spec.md
Requirements: R01,R06,R07,R12,R13
Model: gpt-5.6-luna

## Objective
Alta/revoke/conjunto común/suspensión completos vía motor humano real; pendientes listan contexto seguro y cancelan, consumen confirmación UP/UV del proveedor existente, no fabrican evidencia; bloquear TUI conserva autonomía y suspensión/espera/expiración/revoke se muestran con estado correcto.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G4; G3; G7; V03–V05,V10–V12,V24; H16–17,23–30,48,53.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Alta/revoke/conjunto común/suspensión completos vía motor humano real.
- [x] pendientes listan contexto seguro y cancelan, consumen confirmación UP/UV del proveedor existente, no fabrican evidencia.
- [x] bloquear TUI conserva autonomía y suspensión/espera/expiración/revoke se muestran con estado correcto.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Integrado: la TUI Ratatui/Crossterm usa los opcodes humanos cerrados 54–59
sobre los motores de autoridad e intentos existentes para alta, revocación,
suspensión/reanudación, conjunto común y pendientes. La confirmación passkey
muestra el contexto cerrado, exige `APPROVE <request_id>` por teclado y abre un
canal humano nuevo con reautenticación maestra antes de enviar UP/UV; el agente
no puede declarar esa evidencia. El laboratorio real comprueba lock humano
independiente, dos agentes sobre el mismo conjunto, cancelación terminal,
rechazo tras expiración o revocación y ausencia de secretos/contexto libre en
la pantalla. Evidencia y límites exactos en
[ticket-24](../../../docs/verification/ticket-24.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Claimed tras integración y resolución23 en `0b897c1`, con18/18labs de merger. Sol medium por composición de autoridad, suspensión y confirmación UP/UV humana; no adelanta revisión formal ni modifica modelo de seguridad.


2026-09-14 — Merger Sol distinto integró `36934b3` sin conflictos textuales
como `77a5198`, preservando los cambios documentales de raíz y la TUI23. Verificó
`git diff --check`, `scripts/check.sh`, clean locked/offline (44.43 s) y una
única barrida ordenada con acumulación y propagación explícita de fallos:
`count=19 failures=0`. En ella pasaron la TUI real de autoridad/pendientes y el
recorrido Keycloak 26.7.3 + CFT fijado con `UP=TUI-keyboard` y
`UV=fresh-second-human-channel`. No hubo skips ni retries. Ticket resuelto; no
acredita targets nativos, navegador de producto, ticket25 ni revisión formal
Astra.
