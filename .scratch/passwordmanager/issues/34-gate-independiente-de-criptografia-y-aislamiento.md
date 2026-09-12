# 34 — Gate independiente de criptografía y aislamiento

Type: task
Status: open
Owner: unassigned
Blocked by: 28,30,31,32,33
Spec: ../spec.md
Requirements: R09,R10,R18
Model: gpt-6-astra

## Objective
Revisor independiente identificado recibe composición real, código, threat model y evidencias; informe examina criptografía/FFI/claves/parser, aislamiento y actualización y hallazgos críticos se corrigen con regresión y revalidación; informe/version/alcance permanece accesible sin secretos. Falta de tercero = abierto, no sustituir con aprobación de Astra/Sol.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: §12.3; G2/G7/G8; V07–V08,V18,V21.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

Entornos/artefactos externos de aceptación deben existir realmente. Ausencia de evidencia mantiene el ticket sin resolver; revisión de agentes no sustituye revisión independiente especializada.

## Acceptance criteria
- [ ] Revisor independiente identificado recibe composición real, código, threat model y evidencias.
- [ ] informe examina criptografía/FFI/claves/parser, aislamiento y actualización y hallazgos críticos se corrigen con regresión y revalidación.
- [ ] informe/version/alcance permanece accesible sin secretos. Falta de tercero = abierto, no sustituir con aprobación de Astra/Sol.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
