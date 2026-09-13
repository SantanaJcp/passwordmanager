# 12 — SSH y cuentas de sistema con conexión confirmada

Type: task
Status: claimed
Owner: sol-12
Blocked by: 08
Spec: ../spec.md
Requirements: R03,R08,R09,R14
Model: gpt-5.6-sol

## Objective
Cliente confiable russh propietario del transporte obtiene AuthResult Success con key y password y entrega conexión ligada al consumidor; impostor, host/destino/firma mal ligados y revocación previa fallan; consumidor usa canal posterior sin que motor intermedie/gestione sesión y sin privata/password en sus recursos. Linux/OpenSSH real inicialmente; matriz macOS/Windows en 33.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 B1/B4; V06–V08,V27; P3; H20,49.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Cliente confiable russh propietario del transporte obtiene AuthResult Success con key y password y entrega conexión ligada al consumidor.
- [ ] impostor, host/destino/firma mal ligados y revocación previa fallan.
- [ ] consumidor usa canal posterior sin que motor intermedie/gestione sesión y sin privata/password en sus recursos. Linux/OpenSSH real inicialmente.
- [ ] matriz macOS/Windows en 33.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado paraSSH/systemaccounts porloginrealconfirmado; laboratorio aislado sinmodificar cuentasdelhost.
