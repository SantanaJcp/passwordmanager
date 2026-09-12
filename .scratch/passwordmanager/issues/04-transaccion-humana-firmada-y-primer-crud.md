# 04 — Transacción humana firmada y primer CRUD

Type: task
Status: claimed
Owner: sol-04
Blocked by: 03
Spec: ../spec.md
Requirements: R03,R04,R06,R09
Model: gpt-5.6-sol

## Objective
Crear/leer/editar/eliminar una contraseña por canal humano real usa prepare/commit/receipt y SK_H; challenge vencido/body cambiado/rol falso/replay son rechazados; pérdida de respuesta/commit interrumpido recupera recibo o no-op sin escritura parcial. No aceptar `role=human` por request.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G4§9; G2§9; G6§2; V02,V05,V22; H4,63.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Crear/leer/editar/eliminar una contraseña por canal humano real usa prepare/commit/receipt y SK_H.
- [ ] challenge vencido/body cambiado/rol falso/replay son rechazados.
- [ ] pérdida de respuesta/commit interrumpido recupera recibo o no-op sin escritura parcial. No aceptar `role=human` por request.
- [ ] El commit durable de G4 §9 incluye el registro cifrado mínimo de auditoría de la operación en la misma transacción que eventos/partes/challenge/outbox. Un fallo de auditoría impide la mutación; no usar callbacks vacíos ni escrituras posteriores. El ticket 06 amplía segmentos/consulta/purga sobre este mecanismo ya real.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-12 — Astra explicitó el registro cifrado mínimo de auditoría en el commit atómico G4; 06 amplía ese mecanismo. No cambia el DAG ni el contrato.

2026-09-12 — Reclamado por Sol tras 03 integrado/verificado; mantener registro de auditoría cifrado atómico mínimo para extensiones paralelas 05/06.
