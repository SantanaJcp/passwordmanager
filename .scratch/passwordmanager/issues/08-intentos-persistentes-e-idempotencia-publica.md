# 08 — Intentos persistentes e idempotencia pública

Type: task
Status: resolved
Owner: sol-08
Blocked by: 07
Spec: ../spec.md
Requirements: R08,R09,R13
Model: gpt-5.6-sol

## Objective
start/get/cancel con revisión fijada y ownership producen estados G4, TTL/errores estables; desafío pausa solo un intento y solo evidencia confiable reanuda, con cancel/revoke/expiry impidiendo uso; crash/pérdida de respuesta mantiene intento/recibo, un único ejecutor y estado INDETERMINATE donde no puede conciliar, jamás login ciego repetido. Proveedor controlado externo para esta suite.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G4; §8; V10–V12,V22; H19,22–27,51–53.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] start/get/cancel con revisión fijada y ownership producen estados G4, TTL/errores estables.
- [x] desafío pausa solo un intento y solo evidencia confiable reanuda, con cancel/revoke/expiry impidiendo uso.
- [x] crash/pérdida de respuesta mantiene intento/recibo, un único ejecutor y estado INDETERMINATE donde no puede conciliar, jamás login ciego repetido. Proveedor controlado externo para esta suite.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato `28ad9bff6b871022210ab7ec85bd28a0a85f6e95`,
partiendo de `261ebe2c1a3408671aabdd8379ad583105f0aab2` e integrado
semánticamente sobre el HEAD unificado con SOLO16 como
`080c4fa23dd4deafb6b1dc37a6148f1b72a2df77`. La evidencia exacta está en
[`docs/verification/ticket-08.md`](../../../docs/verification/ticket-08.md).
La implementación reutiliza `AgentIdentity` y `DelegatedVault::authorize` de
SOLO07, sin un ledger o reductor alternativo, y conserva los forks, firmas y
reducción causal de SOLO16.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera paralela08/16 tras07 integrado/verificado. 19 también desbloqueado y en cola de capacidad; se conserva merger separado.

2026-09-12 — Merger dedicado verificó la composición posterior con SOLO16,
49 pruebas de workspace, los cinco laboratorios Linux actuales, el test causal
y el build limpio offline. Todos terminaron con exit 0. No se ejecutó revisión
formal Astra ni se agregó superficie de adaptadores/CLI/MCP de tickets 09+.
