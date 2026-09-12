# 07 — Registro, revocación y conjunto común

Type: task
Status: open
Owner: unassigned
Blocked by: 05,06
Spec: ../spec.md
Requirements: R06,R07,R08,R09,R11,R12
Model: gpt-5.6-sol

## Objective
Alta humana, bootstrap/identidad RPK, generations y revocación individual persisten; dos agentes ven exactamente el mismo conjunto habilitado y metadata mínima, importados/no autenticables excluidos; bloqueo humano no suspende delegación, suspensión global sí persiste y cada uso verifica autoridad. Implementar eventos locales del contrato G5, no autoridad provisional basada en timestamps.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G4§§7,9; G5§9; G2; V03–V05,V12; H16–18,28–30.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Alta humana, bootstrap/identidad RPK, generations y revocación individual persisten.
- [ ] dos agentes ven exactamente el mismo conjunto habilitado y metadata mínima, importados/no autenticables excluidos.
- [ ] bloqueo humano no suspende delegación, suspensión global sí persiste y cada uso verifica autoridad. Implementar eventos locales del contrato G5, no autoridad provisional basada en timestamps.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
