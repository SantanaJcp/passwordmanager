# 21 — Backup PMB1/PMF1 y exportación humana

Type: task
Status: resolved
Owner: sol-21
Blocked by: 18,06
Spec: ../spec.md
Requirements: R04,R05,R18,R19
Model: gpt-5.6-sol

## Objective
Export/restore nativo reproduce inventario completo de tipos/campos/historial/adjuntos/settings/auditoría y autoridad histórica, sin privadas nativas/grants activos/intentos; plaintext requiere confirmación humana y alcance/permisos seguros, agente directo es denegado; streams corruptos/límites/crash fallan antes del commit y sin sobrescribir datos válidos.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G6§§5–6; G2; G7; V02,V20–V22; H2,14–15,39.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Export/restore nativo reproduce inventario completo de tipos/campos/historial/adjuntos/settings/auditoría y autoridad histórica, sin privadas nativas/grants activos/intentos.
- [x] plaintext requiere confirmación humana y alcance/permisos seguros, agente directo es denegado.
- [x] streams corruptos/límites/crash fallan antes del commit y sin sobrescribir datos válidos.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato `2a3415fad0096ffbc2a28bccd6d8c314cd854d8f`,
integrado sin reescribir historia mediante
`3d76d029e5a0b39e7d8d50455978a8b7dc18affc` sobre la rama unificada. PMB1
y PMF1 exportan y verifican el snapshot lógico completo con inventario paginado,
streaming acotado y las vías existentes de contraseña/recuperación; la importación
en bóveda existente recifra con IDs/claves nuevos y conserva autoridad histórica
solo como datos. La exportación plaintext consume una confirmación humana firmada,
de alcance completo, fresca y ligada al estado, y se publica por archivo temporal
0600 y rename atómico. Evidencia TDD, límites, casos adversarios y verificación del
merger: [`docs/verification/ticket-21.md`](../../../docs/verification/ticket-21.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado para backup/exports completos tras18 y06 integrados; no copiarSQLite/WAL ni activarautoridadbackup.

2026-09-13 — El merger separado integró el candidato sobre `60d6016` y resolvió
un único conflicto aditivo: conservó el comando 1PUX y el opcode humano 40 de web
junto a los comandos de backup y el opcode 33 de confirmación plaintext. Los tests
enfocados PMB1/restauración, `check.sh`, build limpio offline y los once laboratorios
Linux actuales pasaron, incluidos Keycloak/CFT real y backup TLS/RPK multi-UID. No
se integró 12, no hubo push, limpieza de worktrees ni review formal Astra.
