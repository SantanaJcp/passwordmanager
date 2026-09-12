# 18 — Historial, papelera y purga humana

Type: task
Status: open
Owner: unassigned
Blocked by: 05,16
Spec: ../spec.md
Requirements: R04,R05,R17
Model: gpt-5.6-sol

## Objective
Interfaz humana lista versiones perdedoras y restaura como nueva revisión; delete/restore/purge y carreras con sync cumplen ADR0002 sin caducidad automática; adjuntos/revisiones afectadas se purgan con alcance y límites visibles, sin resurrección por replay ni eliminación de autoridad necesaria.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G5; G6; ADR0002; V02,V15–V17; H8–11,54–55.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Interfaz humana lista versiones perdedoras y restaura como nueva revisión.
- [ ] delete/restore/purge y carreras con sync cumplen ADR0002 sin caducidad automática.
- [ ] adjuntos/revisiones afectadas se purgan con alcance y límites visibles, sin resurrección por replay ni eliminación de autoridad necesaria.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
