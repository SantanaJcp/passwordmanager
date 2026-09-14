# 13 — Proveedor passkey custodial y puente MV3

Type: task
Status: resolved
Owner: sol-13
Blocked by: 05,08
Spec: ../spec.md
Requirements: R03,R04,R09,R13
Model: gpt-5.6-sol

## Objective
Alta humana genera clave propia y persiste exactamente datos G6; MV3/Native Messaging transportan peticiones acotadas, sin clave JS ni admin UI, y rechazan origen/documento/extension/host falsos; puente y confirmación mínima real TUI implementan UP/UV enlazado al intento y no firman antes de presencia/verificación ni tras revoke. Prueba aquí no sustituye login P4.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 B2; G8§4; V05,V08–V11; H48.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Alta humana genera clave propia y persiste exactamente datos G6.
- [x] MV3/Native Messaging transportan peticiones acotadas, sin clave JS ni admin UI, y rechazan origen/documento/extension/host falsos.
- [x] puente y confirmación mínima real TUI implementan UP/UV enlazado al intento y no firman antes de presencia/verificación ni tras revoke. Prueba aquí no sustituye login P4.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Candidato `6e614d065457cac6f2bdf4aa7289a5ff5f560502`, integrado sin reescribir
historia mediante `cb5fcc0bfc542f909b56fb73bf5f8ed49ecb38d5`: clave Ed25519 propia bajo custodia,
alta G6 auditable/atómica con habilitación humana separada, proveedor ligado al
intento/revocación, MV3/Native Messaging acotado y TUI `/dev/tty` con UP/UV
fresco. El laboratorio recorre CFT real → MV3 → Native Messaging → TLS-RPK →
custodia y las negativas de origen/documento/extensión/host/replay/revoke. La
evidencia exacta y límites (incluidos no-login-P4 y CFT solo como instrumento)
están en [ticket-13](../../../docs/verification/ticket-13.md). La integración
preserva PMB1/PMF1 y los comandos 1PUX/web sin ampliar la prueba a login P4,
Chromium propio, seis targets o compatibilidad multiplataforma.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol para passkeypropia/puente yUP/UV humano real; loginP4 sigue14.

2026-09-13 — El merger separado resolvió la unión aditiva de exports crypto y
comandos de laboratorio. El primer lab integrado detectó colisión real de los
opcodes humanos provisionales 32–34 con backup: se conservaron backup 32–34,
1PUX 31 y web 40, y passkey se trasladó de forma cerrada a 35–37. `check.sh`
detectó además el límite clippy del dispatcher combinado; se extrajo únicamente
la lectura inicial del prompt/unlock sin cambiar el protocolo. Tests enfocados,
build limpio offline y los doce labs Linux actuales quedaron verdes. No se
integró 12, no hubo push, limpieza de worktrees ni review formal Astra.
