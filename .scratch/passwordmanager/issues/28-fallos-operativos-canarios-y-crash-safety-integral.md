# 28 — Fallos operativos, canarios y crash safety integral

Type: task
Status: open
Owner: unassigned
Blocked by: 09,10,11,12,14,15,17,18,19,20,21,22,25
Spec: ../spec.md
Requirements: R09,R10,R13,R15,R18
Model: gpt-5.6-sol

## Objective
Fault injection en boundaries reales de fsync/WAL/staging/commit/outbox/audit y disco lleno conserva atomicidad/autoridad y nunca doble login ciego; canarios activos/históricos cubren stdout/stderr/logs/errores/argv/env/temp/dumps y recursos de agente; memoria/dump/clock/rate límites G7 y pérdida de custodia producen fallo documentado, sin tests verdes por redacción posterior. Ports nativos se vuelven a ejecutar en 30–32.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G7; G2/G4/G5/G6; V05,V07–V08,V20–V23; H43,45,52–53,58–59,64.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Fault injection en boundaries reales de fsync/WAL/staging/commit/outbox/audit y disco lleno conserva atomicidad/autoridad y nunca doble login ciego.
- [ ] canarios activos/históricos cubren stdout/stderr/logs/errores/argv/env/temp/dumps y recursos de agente.
- [ ] memoria/dump/clock/rate límites G7 y pérdida de custodia producen fallo documentado, sin tests verdes por redacción posterior. Ports nativos se vuelven a ejecutar en 30–32.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
