# 09 — CLI delegada y MCP stdio equivalentes

Type: task
Status: resolved
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
- [x] Las cinco operaciones CLI/MCP usan el mismo motor por TLS/RPK y pasan comparación de schemas/estados/errores.
- [x] frame privado 1MiB, límites, versión, JSON malicioso y diagnóstico separado se comprueban.
- [x] ningún comando humano/reveal/export/generic-sign es invocable por identidad agente. Capabilities solo incluye evidencia disponible, no catálogo entero.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato completo
`7399b039d8308f19186f5f2153fe13ea9d2bfb10` y el correctivo de gates
`8429cdb86e36f210494bc30cc4b02cf97a5472b1`, ambos descendientes del
trabajo iniciado en `0868cb96a0b02cc5a2dff17b50c40918a7ab7ac9`.
La historia quedó preservada mediante los merges
`88f469f90fea3af1b5f89f053c134fa11e54640c` y
`9577040850919cdee10c4fe57023b3315ae95e9f`. La evidencia exacta está en
[`docs/verification/ticket-09.md`](../../../docs/verification/ticket-09.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado para Luna después de08 integrado; interfacesCLI/MCP sobrecontratos reales existentes.

2026-09-12 — Merger rechazó inicialmente las supresiones globales de Clippy;
sin ellas el gate detectó 22 errores en `pm-interface`. Luna entregó el
correctivo, se repitieron los gates sin esas supresiones y pasaron 53 pruebas,
los cinco laboratorios Linux y el build limpio offline, todos con exit 0. No
se ejecutó revisión formal Astra ni se añadió superficie humana o de tickets
10+.
