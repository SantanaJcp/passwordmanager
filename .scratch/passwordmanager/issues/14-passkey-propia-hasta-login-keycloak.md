# 14 — Passkey propia hasta login Keycloak

Type: task
Status: resolved
Owner: sol-14
Blocked by: 10,13
Spec: ../spec.md
Requirements: R03,R08,R09,R13,R14
Model: gpt-5.6-sol

## Objective
P4 crea passkey propia y la misma clave completa assertion y OIDC verificable en proveedor real; exigencia UP/UV pausa/reanuda solo intento y no puede afirmarla el agente; challenge expirado/restart/revoke cuenta/origen incorrecto nunca producen éxito ni uso de sustituto virtual/llave OS.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 B2; V06,V09–V11,V27; P4; H21,24–25,48.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] P4 crea passkey propia y la misma clave completa assertion y OIDC verificable en proveedor real.
- [x] exigencia UP/UV pausa/reanuda solo intento y no puede afirmarla el agente.
- [x] challenge expirado/restart/revoke cuenta/origen incorrecto nunca producen éxito ni uso de sustituto virtual/llave OS.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Implementado desde candidato `7df6191`, integrado semánticamente en `f778fa7`
y enlazado como padre en `c385262`. La passkey propia completa el assertion real
de Keycloak 26.7.3 con la misma clave y publica solo OIDC validado. UP/UV exige
TTY y reautenticación fresca; expiry, restart, revocación, cuenta y origen
incorrectos quedan cerrados sin autenticador virtual, llave OS ni fallback.
El merger corrigió la colisión de framing del opcode 4 con token exchange y
verificó `check.sh`, build limpio offline, P4 y los 16 labs Linux actuales.
[Evidencia completa](../../../docs/verification/ticket-14.md). Revisión formal
Astra y otros targets permanecen en sus gates posteriores.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Claimed por Sol tras integración verificada de 10 y 13; review Astra solo al finalizar el DAG.

2026-09-13 — Merger separado resolvió los conflictos aditivos con 11/12/21/22,
conservó resultados opacos de `controlled.external` y cerró la colisión de
payload entre WebAuthn y token exchange. Check completo, clean offline y los 16
labs Linux terminaron con exit 0; sin push, limpieza de worktrees ni review
formal Astra.
