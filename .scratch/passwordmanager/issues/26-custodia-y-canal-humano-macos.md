# 26 — Custodia y canal humano macOS

Type: task
Status: open
Owner: unassigned
Blocked by: 03,07,08
Spec: ../spec.md
Requirements: R01,R02,R09,R10,R11
Model: gpt-5.6-sol

## Objective
Port nativo `_passwordmanager`/LaunchDaemon, peer bilateral y claves/ACL G1 pasa proceso real; TUI CLI-first no hereda autoridad por mismo usuario, acceso indebido y pérdida de condiciones fallan cerrados; clipboard/terminal y persistencia de suspensión/identidad están conectados a APIs nativas, no stubs Unix genéricos. Evidencia ambos CPU/reboot en 31.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G1/G2/G4/G7; V05,V08,V12–V13,V24; H30,40,59.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Port nativo `_passwordmanager`/LaunchDaemon, peer bilateral y claves/ACL G1 pasa proceso real.
- [ ] TUI CLI-first no hereda autoridad por mismo usuario, acceso indebido y pérdida de condiciones fallan cerrados.
- [ ] clipboard/terminal y persistencia de suspensión/identidad están conectados a APIs nativas, no stubs Unix genéricos. Evidencia ambos CPU/reboot en 31.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
