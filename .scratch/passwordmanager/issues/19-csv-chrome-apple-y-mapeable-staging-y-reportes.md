# 19 — CSV Chrome/Apple y mapeable, staging y reportes

Type: task
Status: claimed
Owner: sol-19
Blocked by: 05,07
Spec: ../spec.md
Requirements: R04,R07,R19
Model: gpt-5.6-sol

## Objective
Fixtures sintéticos de los tres orígenes conservan campos/tipos exportados, Unicode y desconocidos o los reportan individualmente; preview/mapping/duplicados/confirmación escribe transacción humana paginada de eventos y objetos, sin auto-enable; truncado/límites/columnas y crash rechazan sin parcialidad, sin leer bases privadas ni borrar fuente. Motor/import contract completo antes de encargar UI mecánica.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G6§§3–4; G4§9; V04,V19,V22; H12–13,46–47.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Fixtures sintéticos de los tres orígenes conservan campos/tipos exportados, Unicode y desconocidos o los reportan individualmente.
- [ ] preview/mapping/duplicados/confirmación escribe transacción humana paginada de eventos y objetos, sin auto-enable.
- [ ] truncado/límites/columnas y crash rechazan sin parcialidad, sin leer bases privadas ni borrar fuente. Motor/import contract completo antes de encargar UI mecánica.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera real17/19; 08candidato listo para integraciónserial delmerger. ReviewformalAstraalfinal.
