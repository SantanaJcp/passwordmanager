# 06 — Auditoría cifrada y purga explícita

Type: task
Status: claimed
Owner: sol-06
Blocked by: 04
Spec: ../spec.md
Requirements: R05,R09
Model: gpt-5.6-sol

## Objective
Eventos de actor/credencial/operación/resultado se escriben atómicamente con las mutaciones y sin KH durante autonomía; errores/crashes no guardan payloads secretos; purga humana con alcance confirmado deja evidencia visible de discontinuidad y no borra autoridad antirreplay.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G7; G2§9; V23; H31,58.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Eventos de actor/credencial/operación/resultado se escriben atómicamente con las mutaciones y sin KH durante autonomía.
- [x] errores/crashes no guardan payloads secretos.
- [x] purga humana con alcance confirmado deja evidencia visible de discontinuidad y no borra autoridad antirreplay.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Candidato implementado en `codex/pm-06`; evidencia reproducible en
[ticket-06](../../../docs/verification/ticket-06.md). Pendiente de integración
y verificación por merger; no resolver todavía.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera paralela 05/06 tras integración verificada de 04. Conservar motor/commit compartidos, sin revisión formal Astra por ticket.
