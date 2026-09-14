# 22 — Recuperación, rotación de vías y compromiso

Type: task
Status: resolved
Owner: sol-22
Blocked by: 21,17
Spec: ../spec.md
Requirements: R06,R18,R19
Model: gpt-5.6-sol

## Objective
Clave externa+backup recuperan en entorno limpio sin keyring original y crean linaje/identidades nuevos; restore a bóveda existente conserva autoridad actual/revocaciones, clave errónea o contenido alterado no mutan; cambio de master/recovery es verificable sin perder acceso y comunica validez/límites de copias viejas, flujo de compromiso desde entorno sano no promete borrar copias expuestas.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G2; G6§6; G7; V17,V21; H38–39,56–57,64.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Clave externa+backup recuperan en entorno limpio sin keyring original y crean linaje/identidades nuevos.
- [x] restore a bóveda existente conserva autoridad actual/revocaciones, clave errónea o contenido alterado no mutan.
- [x] cambio de master/recovery es verificable sin perder acceso y comunica validez/límites de copias viejas, flujo de compromiso desde entorno sano no promete borrar copias expuestas.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Integrado: recuperación PMB1 mediante clave externa sin estado del
equipo fuente, importación bajo linaje/identidades nuevos o autoridad vigente
del destino, y rotación firmada/atómica de master y recuperación. Evidencia
exacta, negativas y límites en
[ticket-22](../../../docs/verification/ticket-22.md). El merger preservó los
opcodes y flujos integrados de backup, passkey, web, exchange y SSH, corrigió
el fallback autorizado de frontera de autoridad corrupta y verificó gates y
los 15 laboratorios Linux en la rama unificada.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Claimed por Sol tras integrar y verificar 21 y 17; implementación aislada, revisión formal Astra solo al final.

2026-09-13 — Merger Sol integró `e6b0255` semánticamente sobre la rama
unificada, preservando passkey, SSH y Keycloak exchange. `check.sh`, clean
offline y la corrida final ordenada de los 15 laboratorios terminaron con exit
0. La revisión formal Astra permanece reservada al cierre del DAG.
