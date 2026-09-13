# 20 — Importador 1PUX3 y adjuntos hostiles

Type: task
Status: claimed
Owner: sol-20
Blocked by: 19
Spec: ../spec.md
Requirements: R04,R07,R19
Model: gpt-5.6-sol

## Objective
Fixtures 1PUX3 incorporan todos los campos/tipos acordados usando staging común; ZIP traversal/bomb/enlaces/duplicados/truncado y adjuntos inválidos son rechazados con límites exactos; reporte conserva pérdida/no importable explícita y ningún caso habilita agente ni escribe fuera de staging seguro.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G6§§3–4; V19,V22; H12–13,46–47.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Fixtures 1PUX3 incorporan todos los campos/tipos acordados usando staging común.
- [ ] ZIP traversal/bomb/enlaces/duplicados/truncado y adjuntos inválidos son rechazados con límites exactos.
- [ ] reporte conserva pérdida/no importable explícita y ningún caso habilita agente ni escribe fuera de staging seguro.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado tras19 integrado, mientras se coordina integración17 y se conserva trabajo18 aislado.
