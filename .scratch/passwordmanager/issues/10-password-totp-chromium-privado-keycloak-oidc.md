# 10 — Password/TOTP Chromium privado + Keycloak OIDC

Type: task
Status: open
Owner: unassigned
Blocked by: 08
Spec: ../spec.md
Requirements: R03,R08,R09,R13,R14
Model: gpt-5.6-sol

## Objective
Perfil P1 real de laboratorio usa Chromium fijado, Keycloak26.7.3 y code+PKCE; issuer/origen/frame/cuenta/nonce/audience/callback/redirect adversarios fallan antes del secreto; login y TOTP reales entregan solo tokens nuevos permitidos y agente no accede a pipe/perfil/DOM/canarios. Registrar plataforma probada; seis targets se completan en 33.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 cierre/perfiles; G8§4; V06–V11,V27; P1; H20–25.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Perfil P1 real de laboratorio usa Chromium fijado, Keycloak26.7.3 y code+PKCE.
- [ ] issuer/origen/frame/cuenta/nonce/audience/callback/redirect adversarios fallan antes del secreto.
- [ ] login y TOTP reales entregan solo tokens nuevos permitidos y agente no accede a pipe/perfil/DOM/canarios. Registrar plataforma probada.
- [ ] seis targets se completan en 33.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
