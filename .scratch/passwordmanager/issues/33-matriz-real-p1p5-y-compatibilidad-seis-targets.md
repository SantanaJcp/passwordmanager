# 33 — Matriz real P1–P5 y compatibilidad seis targets

Type: task
Status: open
Owner: unassigned
Blocked by: 10,11,12,14,15,30,31,32
Spec: ../spec.md
Requirements: R02,R03,R08,R09,R13,R14
Model: gpt-5.6-sol

## Objective
P1/P4 ejecutados con Chromium propio y passkey custodial propia en los seis targets, incluyendo Windows ARM64; P2/P3/P5 contra contrapartes reales autorizadas y matriz custodio/destino relevante, con casos adversarios y login/resultados útiles; capabilities publica únicamente fila aprobada de build/entorno y V27 comprueba ausencia de administración de sesiones/acciones. Un doble o assertion/firma aislada no satisface login.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 P1–P5; G8; V06–V11,V27; H20–22,48–50.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

Entornos/artefactos externos de aceptación deben existir realmente. Ausencia de evidencia mantiene el ticket sin resolver; revisión de agentes no sustituye revisión independiente especializada.

## Acceptance criteria
- [ ] P1/P4 ejecutados con Chromium propio y passkey custodial propia en los seis targets, incluyendo Windows ARM64.
- [ ] P2/P3/P5 contra contrapartes reales autorizadas y matriz custodio/destino relevante, con casos adversarios y login/resultados útiles.
- [ ] capabilities publica únicamente fila aprobada de build/entorno y V27 comprueba ausencia de administración de sesiones/acciones. Un doble o assertion/firma aislada no satisface login.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
