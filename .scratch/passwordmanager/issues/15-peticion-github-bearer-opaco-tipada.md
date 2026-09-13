# 15 — Petición GitHub bearer opaco tipada

Type: task
Status: claimed
Owner: sol-15
Blocked by: 08
Spec: ../spec.md
Requirements: R03,R08,R09,R14
Model: gpt-5.6-sol

## Objective
`github-rest-bearer/1` acepta exclusivamente `github-assigned-issues/1` del contrato y produce lista/respuesta permitida sin token/headers; ataques URL/header injection/redirect/reflexión/errores/cuota/SSO fallan con resultados públicos seguros; canarios no aparecen en canales agente y no nace proxy arbitrario ni política de negocio. Dobles adversarios aquí; proveedor autorizado real en 33.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 B3; V06–V07,V27; P5; H20,50.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] `github-rest-bearer/1` acepta exclusivamente `github-assigned-issues/1` del contrato y produce lista/respuesta permitida sin token/headers.
- [ ] ataques URL/header injection/redirect/reflexión/errores/cuota/SSO fallan con resultados públicos seguros.
- [ ] canarios no aparecen en canales agente y no nace proxy arbitrario ni política de negocio. Dobles adversarios aquí.
- [ ] proveedor autorizado real en 33.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Claimed por Sol medium desde integración verificada de 22; 08 resuelto. Adaptador tipado y dobles adversarios en este corte; proveedor autorizado real permanece en 33.
