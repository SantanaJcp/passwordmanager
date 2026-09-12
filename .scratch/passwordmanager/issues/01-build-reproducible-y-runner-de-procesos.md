# 01 — Build reproducible y runner de procesos

Type: task
Status: claimed
Owner: sol-01
Blocked by: none
Spec: ../spec.md
Requirements: R01,R02,R20
Model: gpt-5.6-sol
Labels: ready-for-agent

## Objective
Workspace mínimo y ejecutable CLI arrancan con toolchain seleccionado; Cargo.lock/features y libsodium C verificadas sin fetch-latest; runner lanza procesos reales con directorios temporales y conserva exit/status, build y canarios. Inventario inicial de componentes/licencias no afirma auditoría final.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: §5–6; G1§8; G8§2.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Workspace mínimo y ejecutable CLI arrancan con toolchain seleccionado.
- [ ] Cargo.lock/features y libsodium C verificadas sin fetch-latest.
- [ ] runner lanza procesos reales con directorios temporales y conserva exit/status, build y canarios. Inventario inicial de componentes/licencias no afirma auditoría final.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-12 — Reclamado por Sol para worktree aislado codex/pm-01; el merger decidirá resolución tras integrar/verificar.
