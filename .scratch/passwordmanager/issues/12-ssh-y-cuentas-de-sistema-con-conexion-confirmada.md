# 12 — SSH y cuentas de sistema con conexión confirmada

Type: task
Status: resolved
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
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Candidato `2af343d523ec3cef5b8af492a0b8d868a2417b90` integrado sin reescribir
historia mediante `9328be55276817cbba2be405328a0d552b96eb03`: `pm-ssh-client`
con russh 0.63.3 conserva el transporte desde KEX/hostkey hasta
`AuthResult::Success`, retiene la conexión para el consumidor UID-bound y la
custodia solo entrega password tras host verificado o firma el payload RFC
4252 ligado al intento. El laboratorio OpenSSH 10.5p1 real pasó key+password,
canal posterior, impostor/host/destino/firma/revoke/partial-success y canarios.

La integración preserva backup/passkey/web/sync y los opcodes humanos ya
publicados; el helper SSH de laboratorio quedó en 45. `check.sh`, build limpio
offline y los trece laboratorios Linux actuales pasaron. La evidencia exacta,
incluidos dos fallos de integración detectados y corregidos antes de resolver,
está en [docs/verification/ticket-12.md](../../../docs/verification/ticket-12.md).
macOS/Windows y otros targets/algoritmos permanecen en el ticket 33.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado paraSSH/systemaccounts porloginrealconfirmado; laboratorio aislado sinmodificar cuentasdelhost.


2026-09-13 — Merger separado integró el candidato sobre el árbol unificado y
preservó los contratos de 1PUX, backup, passkey y web. `check.sh` detectó y
forzó el refactor de los decodificadores combinados; el laboratorio de intentos
detectó que resultados opacos de `controlled.external` no deben parsearse como
JSON. Tras la regresión cerrada, check, build limpio offline y los trece labs
Linux (incluidos SSH/OpenSSH, Keycloak/CFT, passkey/MV3 y backup) quedaron
verdes. No hubo push, limpieza de worktrees ni review formal Astra.
