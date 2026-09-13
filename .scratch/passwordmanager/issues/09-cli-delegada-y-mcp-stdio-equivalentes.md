# 09 — CLI delegada y MCP stdio equivalentes

Type: task
Status: claimed
Owner: luna-09
Blocked by: 08
Spec: ../spec.md
Requirements: R01,R08,R09,R13
Model: gpt-5.6-luna

## Objective
Las cinco operaciones CLI/MCP usan el mismo motor por TLS/RPK y pasan comparación de schemas/estados/errores; frame privado 1MiB, límites, versión, JSON malicioso y diagnóstico separado se comprueban; ningún comando humano/reveal/export/generic-sign es invocable por identidad agente. Capabilities solo incluye evidencia disponible, no catálogo entero.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G4§7; §7.4; V05,V25; H18–19,22,41,63.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Las cinco operaciones CLI/MCP usan el mismo motor por TLS/RPK y pasan comparación de schemas/estados/errores.
- [ ] frame privado 1MiB, límites, versión, JSON malicioso y diagnóstico separado se comprueban.
- [ ] ningún comando humano/reveal/export/generic-sign es invocable por identidad agente. Capabilities solo incluye evidencia disponible, no catálogo entero.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado para Luna después de08 integrado; interfacesCLI/MCP sobrecontratos reales existentes.
