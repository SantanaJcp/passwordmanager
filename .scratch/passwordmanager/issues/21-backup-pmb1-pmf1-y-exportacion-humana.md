# 21 — Backup PMB1/PMF1 y exportación humana

Type: task
Status: open
Owner: unassigned
Blocked by: 18,06
Spec: ../spec.md
Requirements: R04,R05,R18,R19
Model: gpt-5.6-sol

## Objective
Export/restore nativo reproduce inventario completo de tipos/campos/historial/adjuntos/settings/auditoría y autoridad histórica, sin privadas nativas/grants activos/intentos; plaintext requiere confirmación humana y alcance/permisos seguros, agente directo es denegado; streams corruptos/límites/crash fallan antes del commit y sin sobrescribir datos válidos.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G6§§5–6; G2; G7; V02,V20–V22; H2,14–15,39.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Export/restore nativo reproduce inventario completo de tipos/campos/historial/adjuntos/settings/auditoría y autoridad histórica, sin privadas nativas/grants activos/intentos.
- [ ] plaintext requiere confirmación humana y alcance/permisos seguros, agente directo es denegado.
- [ ] streams corruptos/límites/crash fallan antes del commit y sin sobrescribir datos válidos.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
