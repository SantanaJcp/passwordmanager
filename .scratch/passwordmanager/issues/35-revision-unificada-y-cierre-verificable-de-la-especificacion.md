# 35 — Revisión unificada y cierre verificable de la especificación

Type: task
Status: open
Owner: unassigned
Blocked by: 09,24,25,29,30,31,32,33,34
Spec: ../spec.md
Requirements: R01,R02,R03,R04,R05,R06,R07,R08,R09,R10,R11,R12,R13,R14,R15,R16,R17,R18,R19,R20,R21
Model: gpt-6-astra

## Objective
Code-review de estándares Y contrato en rama unificada no deja hallazgos accionables sin corregir; suite pública completa tiene evidencia para H1–64/V01–V27/P1–P5 y seis targets, LICENSE/fuente/SBOM/certificados/release roles reales cotejados; §15 se actualiza con resultado exacto sin afirmar publicación remota o modificar R01–R21. Si falta evidencia externa, informe de entrega parcial y ticket abierto: nunca resolver spec por presupuesto/tiempo.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: spec completa; code-review; G8; V26; H42,60–64.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

Entornos/artefactos externos de aceptación deben existir realmente. Ausencia de evidencia mantiene el ticket sin resolver; revisión de agentes no sustituye revisión independiente especializada.

## Acceptance criteria
- [ ] Code-review de estándares Y contrato en rama unificada no deja hallazgos accionables sin corregir.
- [ ] suite pública completa tiene evidencia para H1–64/V01–V27/P1–P5 y seis targets, LICENSE/fuente/SBOM/certificados/release roles reales cotejados.
- [ ] §15 se actualiza con resultado exacto sin afirmar publicación remota o modificar R01–R21. Si falta evidencia externa, informe de entrega parcial y ticket abierto: nunca resolver spec por presupuesto/tiempo.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
