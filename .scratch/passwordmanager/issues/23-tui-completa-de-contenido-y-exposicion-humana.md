# 23 — TUI completa de contenido y exposición humana

Type: task
Status: open
Owner: unassigned
Blocked by: 05,18
Spec: ../spec.md
Requirements: R01,R03,R04,R05,R12
Model: gpt-5.6-luna

## Objective
Todos los tipos, búsqueda/organización/generador/historia/papelera/purga operan vía motor real por teclado; unlock/lock, idle/reveal expiry, copiar explícito con API/helper fijado y carrera de clipboard cumplen G7 sin OSC52 oculto; resize/80×24/Unicode/control sequences se prueban en PTY y terminal nativo Linux, sin pérdida de datos ni secretos por seleccionar fila.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G1 terminal; G7; V02,V07,V20,V24; H3–11,43–45.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Todos los tipos, búsqueda/organización/generador/historia/papelera/purga operan vía motor real por teclado.
- [ ] unlock/lock, idle/reveal expiry, copiar explícito con API/helper fijado y carrera de clipboard cumplen G7 sin OSC52 oculto.
- [ ] resize/80×24/Unicode/control sequences se prueban en PTY y terminal nativo Linux, sin pérdida de datos ni secretos por seleccionar fila.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
