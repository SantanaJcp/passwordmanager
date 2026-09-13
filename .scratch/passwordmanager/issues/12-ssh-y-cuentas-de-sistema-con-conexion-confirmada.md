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
- [x] Cliente confiable russh propietario del transporte obtiene AuthResult Success con key y password y entrega conexión ligada al consumidor.
- [x] impostor, host/destino/firma mal ligados y revocación previa fallan.
- [x] consumidor usa canal posterior sin que motor intermedie/gestione sesión y sin privata/password en sus recursos. Linux/OpenSSH real inicialmente.
- [x] matriz macOS/Windows en 33.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Candidato completo en `codex/pm-12`. `pm-ssh-client` fija russh 0.63.3 y conserva el transporte/`Handle` desde KEX y hostkey hasta `AuthResult::Success`; custodia libera password solo después del host verificado o firma exclusivamente el payload RFC 4252 ligado al intento. El `consumer_ref` de 256 bits solo funciona desde el UID instalado y abre/cierra un canal sobre la conexión retenida, sin relay ni API de comandos/sesión en motor, CLI o MCP.

Evidencia exacta, fuentes y límites: [docs/verification/ticket-12.md](../../../docs/verification/ticket-12.md). El laboratorio user+mount namespace ejecutó OpenSSH 10.5p1 real con cuenta sintética para publickey/password, hostkey/usuario/firma incorrectos, consumidor impostor, ownership, revocación previa y partial-success/cancelación. `check.sh`, clean offline build y todos los laboratorios Linux quedaron verdes. La matriz macOS/Windows y targets/algoritmos restantes sigue expresamente en 33. Falta únicamente integración y verificación por merger separado; por ello el ticket permanece `claimed`.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado paraSSH/systemaccounts porloginrealconfirmado; laboratorio aislado sinmodificar cuentasdelhost.
