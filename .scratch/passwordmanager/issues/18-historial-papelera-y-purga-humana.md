# 18 — Historial, papelera y purga humana

Type: task
Status: resolved
Owner: sol-18
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
- [x] Interfaz humana lista versiones perdedoras y restaura como nueva revisión.
- [x] delete/restore/purge y carreras con sync cumplen ADR0002 sin caducidad automática.
- [x] adjuntos/revisiones afectadas se purgan con alcance y límites visibles, sin resurrección por replay ni eliminación de autoridad necesaria.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato `14d21a10b4de84fa5132321d8f9944680ad1af0b`,
descendiente de la base sincronizada de 17, e integrado sin reescritura mediante
`58b67801ca7bc489ca3f538b08ce2d838c6f8f0e` sobre la rama unificada. Historia,
restore con claves/revisión nuevas,
papelera sin caducidad y purga humana con alcance firmado usan el único
`HumanVault::commit` y el reductor causal existente. La evidencia TDD, límites,
recorrido TLS/RPK y verificación unificada está en
[`docs/verification/ticket-18.md`](../../../docs/verification/ticket-18.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado tras dependencias05/16 verificadas; historia/papelera/purga pública desbloquea backup y TUI.

2026-09-13 — El merger dedicado integró el candidato sin conflictos y verificó
3 pruebas de lifecycle, 7 del reductor incluida convergencia de 120
permutaciones, `check.sh`, build limpio offline y los ocho laboratorios Linux.
El laboratorio público restauró los siete tipos y adjuntos inline/stream con
ciphertext nuevo, comprobó papelera durable, alcance firmado, rollback de
auditoría, respuesta perdida/replay y bloqueo antirresurrección tras purga. Se
preservaron el grafo map5 de 17 y los cambios documentales de 10/13; no se
integró ni resolvió 20 y no hubo push ni review formal Astra.
