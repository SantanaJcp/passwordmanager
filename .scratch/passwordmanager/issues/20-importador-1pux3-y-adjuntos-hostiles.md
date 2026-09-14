# 20 — Importador 1PUX3 y adjuntos hostiles

Type: task
Status: resolved
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
- [x] Fixtures 1PUX3 incorporan todos los campos/tipos acordados usando staging común.
- [x] ZIP traversal/bomb/enlaces/duplicados/truncado y adjuntos inválidos son rechazados con límites exactos.
- [x] reporte conserva pérdida/no importable explícita y ningún caso habilita agente ni escribe fuera de staging seguro.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato `170c1e5c484af4ba195387633334c2be073aacb3`,
integrado sin reescritura mediante
`5b9fe57f1a0055dc967f490617a25ad23562778f` sobre la rama unificada. El
lector 1PUX v3 hostil, el transporte de descriptor `SCM_RIGHTS`, el staging
cifrado por chunks y el commit/import report reutilizan las autoridades y
transacciones existentes. La evidencia TDD, límites exactos, recorrido
TLS/RPK multi-UID y verificación unificada está en
[`docs/verification/ticket-20.md`](../../../docs/verification/ticket-20.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado tras19 integrado, mientras se coordina integración17 y se conserva trabajo18 aislado.

2026-09-13 — El merger dedicado resolvió dos conflictos aditivos conservando
los comandos/opcodes 25–30 de historia junto al opcode humano 31 de 1PUX y la
dependencia `zip` fijada. `check.sh`, el build limpio offline y los nueve
laboratorios Linux pasaron. El laboratorio 1PUX atravesó el archivo mayor al
frame por descriptor privado 0400, 21 chunks, rollback tras crash/auditoría,
traversal/symlink sin efecto, reintento idempotente y cero auto-enable. Se
preservaron sync17, historia18, CSV19 e intentos CLI/MCP; no se integró 10, 13
ni 21 y no hubo push, cleanup de worktrees ni review formal Astra.
