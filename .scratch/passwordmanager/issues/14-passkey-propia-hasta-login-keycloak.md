# 14 — Passkey propia hasta login Keycloak

Type: task
Status: claimed
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
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Candidato de implementación completo, pendiente solo de integración y
verificación por merger. P4 registra una passkey propia contra Keycloak 26.7.3,
habilita ese item por acción humana separada, usa la misma clave por
MV3/Native Messaging/TLS-RPK y entrega únicamente un resultado OIDC validado.
UP/UV usa `/dev/tty` con reautenticación fresca. Expiry, restart del proveedor,
revocación, cuenta y origen incorrectos quedan cerrados sin autenticador
virtual, llave de OS ni fallback. Evidencia exacta y límites en
[ticket-14](../../../docs/verification/ticket-14.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Claimed por Sol tras integración verificada de 10 y 13; review Astra solo al finalizar el DAG.
