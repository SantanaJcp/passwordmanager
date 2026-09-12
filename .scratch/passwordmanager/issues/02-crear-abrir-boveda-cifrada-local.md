# 02 — Crear/abrir bóveda cifrada local

Type: task
Status: open
Owner: unassigned
Blocked by: 01
Spec: ../spec.md
Requirements: R01,R04,R09,R15,R18
Model: gpt-5.6-sol

## Objective
CLI humana crea bóveda real sin red/cuenta y vuelve a abrir tras restart; suite G2 de bytes/contexto/propósito, KDF, AAD, envoltorios y parser adversario pasa; contraseña errónea/archivo alterado/version incompatible no mutan bóveda válida. SQLite/WAL solo reciben objetos precifrados y ninguna raíz se serializa en claro.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G2§§7–9; G6§2; V01,V07,V21; H1,43.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] CLI humana crea bóveda real sin red/cuenta y vuelve a abrir tras restart.
- [ ] suite G2 de bytes/contexto/propósito, KDF, AAD, envoltorios y parser adversario pasa.
- [ ] contraseña errónea/archivo alterado/version incompatible no mutan bóveda válida. SQLite/WAL solo reciben objetos precifrados y ninguna raíz se serializa en claro.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
