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
no puede declarar esa evidencia. La verificación real cubre lock humano
independiente, dos agentes sobre el mismo conjunto, cancelación terminal y los
negativos de expiración/revocación sin secretos ni contexto libre expuesto.
Evidencia, RED preservados y límites exactos en
[ticket-24](../../../docs/verification/ticket-24.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Claimed tras integración y resolución23 en `0b897c1`, con18/18labs de merger. Sol medium por composición de autoridad, suspensión y confirmación UP/UV humana; no adelanta revisión formal ni modifica modelo de seguridad.

2026-09-14 — RED de integración del merger: el candidato `36934b3` se integró
sin conflictos como `77a5198`; `git diff --check`, `scripts/check.sh`, clean
locked/offline (44.43 s) y los 19 cuerpos funcionales terminaron en PASS. Sin
embargo, el nuevo lab TUI oculta el error de su cleanup mediante
`shutil.rmtree(root, ignore_errors=True)` y la corrida dejó el directorio real
`/tmp/pm-tui-access-linux-lab-c4d1o_6i` con subdirectorios/fixtures sintéticos
de UIDs mapeados 100002–100005. El proceso devolvió 0, por lo que el gate no
propaga todos sus fallos y su `count=19 failures=0` no basta para resolver el
ticket bajo la prohibición de fallbacks/errores ocultos. La resolución
provisional `0c1e656` se revirtió de forma no destructiva en `3205ae9`; ticket
permanece claimed a la espera de una corrección del autor y nueva verificación
independiente. No se atribuye fallo funcional al motor ni se repiten los labs.


2026-09-14 — Merger Sol corrigió en integración únicamente el fallback nuevo
del harness: inventario estricto de la raíz propia, limpieza con cada UID
mapeado, errores propagados y PASS posteriores a confirmar ausencia. Conservó
el RED original y el primer RED estricto de `terminal.raw`; la regresión
final no agregó residuos. En ventana Linux local exclusiva pasaron
`git diff --check`, `scripts/check.sh`, clean locked/offline (1m 01s) y una sola
barrida ordenada: `count=19 failures=0 ticket24-cleanup-set-changed=0`. No hubo
skips ni retries, y no quedaron procesos/residuos nuevos propios. Ticket
resuelto; no acredita targets nativos, Chromium de producto, ticket25 ni
revisión formal Astra.
