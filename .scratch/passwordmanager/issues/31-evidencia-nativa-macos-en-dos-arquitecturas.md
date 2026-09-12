# 31 — Evidencia nativa macOS en dos arquitecturas

Type: task
Status: open
Owner: unassigned
Blocked by: 24,28,29
Spec: ../spec.md
Requirements: R01,R02,R09,R10,R11
Model: gpt-5.6-sol

## Objective
Mismos ciclos y adversarios en Intel Y Apple silicon nativos; Terminal.app/clipboard/canal humano CLI-first completos; firma/notarización de release real se separa de fixture sintético y evidencia faltante queda explícita, sin afirmar instalación firmada de producción. Para cierre de producto, evidencia real requerida por G8 debe existir.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G1/G7/G8; V01–V27 aplicables; H30,40,59–62.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

Entornos/artefactos externos de aceptación deben existir realmente. Ausencia de evidencia mantiene el ticket sin resolver; revisión de agentes no sustituye revisión independiente especializada.

## Acceptance criteria
- [ ] Mismos ciclos y adversarios en Intel Y Apple silicon nativos.
- [ ] Terminal.app/clipboard/canal humano CLI-first completos.
- [ ] firma/notarización de release real se separa de fixture sintético y evidencia faltante queda explícita, sin afirmar instalación firmada de producción. Para cierre de producto, evidencia real requerida por G8 debe existir.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
