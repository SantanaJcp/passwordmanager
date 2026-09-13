# 16 — Reductor firmado de contenido y autoridad

Type: task
Status: claimed
Owner: sol-16
Blocked by: 07
Spec: ../spec.md
Requirements: R05,R06,R16,R17
Model: gpt-5.6-sol

## Objective
G5 con DAG firmado, generations/cortes, desempate exacto y antirreplay pasa permutaciones 2/3 dispositivos, forks, reloj adelantado y revocación cruzada; delete frente edit deja ganador en papelera y solo restore explícito activa; checkpoints/purga conservan headers y no reviven autoridad/elementos ante omisión/replay. Sin timestamp LWW para revocaciones.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G5§9; ADR0002; V15–V18; H35–37,54–55.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] G5 con DAG firmado, generations/cortes, desempate exacto y antirreplay pasa permutaciones 2/3 dispositivos, forks, reloj adelantado y revocación cruzada.
- [ ] delete frente edit deja ganador en papelera y solo restore explícito activa.
- [ ] checkpoints/purga conservan headers y no reviven autoridad/elementos ante omisión/replay. Sin timestamp LWW para revocaciones.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera paralela08/16 tras07 integrado/verificado. 19 también desbloqueado y en cola de capacidad; se conserva merger separado.
