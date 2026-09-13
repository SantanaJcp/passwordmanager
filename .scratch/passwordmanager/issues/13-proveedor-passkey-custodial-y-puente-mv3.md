# 13 — Proveedor passkey custodial y puente MV3

Type: task
Status: claimed
Owner: sol-13
Blocked by: 05,08
Spec: ../spec.md
Requirements: R03,R04,R09,R13
Model: gpt-5.6-sol

## Objective
Alta humana genera clave propia y persiste exactamente datos G6; MV3/Native Messaging transportan peticiones acotadas, sin clave JS ni admin UI, y rechazan origen/documento/extension/host falsos; puente y confirmación mínima real TUI implementan UP/UV enlazado al intento y no firman antes de presencia/verificación ni tras revoke. Prueba aquí no sustituye login P4.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 B2; G8§4; V05,V08–V11; H48.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Alta humana genera clave propia y persiste exactamente datos G6.
- [x] MV3/Native Messaging transportan peticiones acotadas, sin clave JS ni admin UI, y rechazan origen/documento/extension/host falsos.
- [x] puente y confirmación mínima real TUI implementan UP/UV enlazado al intento y no firman antes de presencia/verificación ni tras revoke. Prueba aquí no sustituye login P4.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Candidato implementado en `codex/pm-13`: clave Ed25519 propia bajo custodia,
alta G6 auditable/atómica con habilitación humana separada, proveedor ligado al
intento/revocación, MV3/Native Messaging acotado y TUI `/dev/tty` con UP/UV
fresco. El laboratorio recorre CFT real → MV3 → Native Messaging → TLS-RPK →
custodia y las negativas de origen/documento/extensión/host/replay/revoke. La
evidencia exacta y límites (incluidos no-login-P4 y CFT solo como instrumento)
están en [ticket-13](../../../docs/verification/ticket-13.md). Falta únicamente
la verificación/integración del merger para marcar el último criterio y resolver.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol para passkeypropia/puente yUP/UV humano real; loginP4 sigue14.
