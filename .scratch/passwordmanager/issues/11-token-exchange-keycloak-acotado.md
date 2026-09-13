# 11 — Token exchange Keycloak acotado

Type: task
Status: claimed
Owner: sol-11
Blocked by: 08
Spec: ../spec.md
Requirements: R03,R08,R09,R14
Model: gpt-5.6-sol

## Objective
P2 real entrega B distinto de A con subject/audience verificados; reflect/redirect/auxiliares/audience no autorizada son rechazados sin fuga; revocación antes de POST impide nuevo uso, sin pretender anular token emitido. No exchange genérico.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3§4; V06–V07,V11,V27; P2; H20,22.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] P2 real entrega B distinto de A con subject/audience verificados.
- [ ] reflect/redirect/auxiliares/audience no autorizada son rechazados sin fuga.
- [ ] revocación antes de POST impide nuevo uso, sin pretender anular token emitido. No exchange genérico.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado conKeycloak10 integrado paraexchangeV2acotado; no endpointarbitrario ni fallbacklegacy.
