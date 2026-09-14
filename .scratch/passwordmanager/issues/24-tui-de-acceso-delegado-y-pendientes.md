# 24 — TUI de acceso delegado y pendientes

Type: task
Status: claimed
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
- [ ] Alta/revoke/conjunto común/suspensión completos vía motor humano real.
- [ ] pendientes listan contexto seguro y cancelan, consumen confirmación UP/UV del proveedor existente, no fabrican evidencia.
- [ ] bloquear TUI conserva autonomía y suspensión/espera/expiración/revoke se muestran con estado correcto.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

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
