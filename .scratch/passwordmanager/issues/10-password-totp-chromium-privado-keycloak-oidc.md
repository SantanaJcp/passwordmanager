# 10 — Password/TOTP Chromium privado + Keycloak OIDC

Type: task
Status: claimed
Owner: sol-10
Blocked by: 08
Spec: ../spec.md
Requirements: R03,R08,R09,R13,R14
Model: gpt-5.6-sol

## Objective
Perfil P1 real de laboratorio usa Chromium fijado, Keycloak26.7.3 y code+PKCE; configuración de issuer/origen/frame/form-action/cuenta seleccionada/redirect fijado adversaria falla antes de introducir el secreto; callback/state y claims de respuesta (firma, issuer, audience/azp, nonce y subject) se validan al recibirlos, antes de declarar éxito o entregar tokens; login y TOTP reales entregan solo tokens nuevos permitidos y agente no accede a pipe/perfil/DOM/canarios. Registrar plataforma probada; seis targets se completan en 33.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G3 cierre/perfiles; G8§4; V06–V11,V27; P1; H20–25.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Perfil P1 real de laboratorio usa Chromium fijado, Keycloak26.7.3 y code+PKCE.
- [x] configuración de issuer/origen/frame/form-action/cuenta seleccionada/redirect fijado adversaria falla antes de introducir el secreto; callback/state y claims de respuesta (firma, issuer, audience/azp, nonce y subject) se validan al recibirlos, antes de declarar éxito o entregar tokens.
- [x] login y TOTP reales entregan solo tokens nuevos permitidos y agente no accede a pipe/perfil/DOM/canarios. Registrar plataforma probada.
- [x] seis targets se completan en 33.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.

- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Candidato Linux x86_64 implementado en `codex/pm-10`; evidencia exacta en
[`docs/verification/ticket-10.md`](../../../docs/verification/ticket-10.md).
Keycloak 26.7.3 real y CFT 153.0.8010.36 fijado recorren password+TOTP,
Authorization Code+PKCE S256, callback TLS 1.3, validación OIDC y salida cerrada
de tokens nuevos. Un required action real pausa solo el intento y su cancelación
es terminal. CFT es instrumento desechable: no sustituye Chromium propio de
producto ni completa ticket 29/33 o los seis targets.

No se marca resuelto antes del merger. Form-action e iframe hostiles reales no
reciben secreto; cuenta instalada discordante no abre el browser; el agente no
lee perfil/home, memoria del proveedor/browser ni fds CDP. Callback/state y JWT
firmados adversarios fallan antes del éxito/entrega. La revisión formal Astra
final sigue separada.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol para integraciónweb real; no sustituir perfil privado/proveedor por mocks ni declarar P1 sin ejecución.

2026-09-13 — Corregida compresión temporal incorrecta del ticket: G3 «Secuencia y prueba de éxito» ya distingue validación del contexto antes de credenciales y validación de ID token después del intercambio, antes de éxito/entrega. No se puede comprobar un claim de respuesta antes de recibirla. Se conserva el contrato G3, no se elimina ninguna prueba adversaria. Fuente primaria: [OIDC Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) y [ID Token Validation §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). DOM/iframe hostil y acceso adversario a memoria/pipe/perfil siguen requiriendo evidencia real.

2026-09-13 — Candidato acotado ejecutado con Keycloak oficial/CFT fijado,
incluidos DOM/iframe hostiles y denegaciones `/proc`/fds. CFT no sustituye
Chromium propio ni cierra R09/matriz nativa; no resolver antes del merger.

