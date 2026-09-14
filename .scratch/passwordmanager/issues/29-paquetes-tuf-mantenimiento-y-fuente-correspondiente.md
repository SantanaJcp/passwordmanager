# 29 — Paquetes, TUF, mantenimiento y fuente correspondiente

Type: task
Status: open
Owner: unassigned
Blocked by: 22,25,26,27
Spec: ../spec.md
Requirements: R02,R11,R18,R20
Model: gpt-5.6-sol

## Objective
Payloads/versiones/Chromium/MV3/helpers y grafo auditables producen paquetes previstos y SBOM/fuente/avisos AGPL sin autor inventado; repositorio TUF sintético y mantenimiento local rechazan threshold/firma/path/rollback/security_floor/reloj adversarios sin canal admin delegado; upgrade/quiesce/migración/journal/rollback/uninstall/reinstall preservan datos/identidad/revocaciones, purga separada y explícita. Certificados reales no fingidos.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G8 completo; V13,V21,V26; H42,60–62.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Payloads/versiones/Chromium/MV3/helpers y grafo auditables producen paquetes previstos y SBOM/fuente/avisos AGPL sin autor inventado.
- [ ] repositorio TUF sintético y mantenimiento local rechazan threshold/firma/path/rollback/security_floor/reloj adversarios sin canal admin delegado.
- [ ] upgrade/quiesce/migración/journal/rollback/uninstall/reinstall preservan datos/identidad/revocaciones, purga separada y explícita. Certificados reales no fingidos.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
