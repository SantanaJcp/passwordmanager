# 25 — TUI de migración, recuperación, sync y auditoría

Type: task
Status: resolved
Owner: sol-25
Blocked by: 17,19,20,21,22,23
Spec: ../spec.md
Requirements: R01,R04,R05,R15,R18,R19
Model: gpt-5.6-luna

## Objective
Flujos enteros import preview/mapping/duplicados/errores/confirmación, export/backup/restore/rotación son operables por teclado; emparejar/retirar/offline/sync errors y auditoría/purga funcionan sobre servicios reales; advertencias plaintext/recovery/clipboard/offline y acciones destructivas muestran alcance sin secretos por defecto. No formularios sin operación ni CLI-only como reemplazo de TUI.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: §7.2/§11; G4§9; G6/G7; V14,V19–V24; H2,12–15,31–39,56–58,64.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Flujos enteros import preview/mapping/duplicados/errores/confirmación, export/backup/restore/rotación son operables por teclado.
- [x] emparejar/retirar/offline/sync errors y auditoría/purga funcionan sobre servicios reales.
- [x] advertencias plaintext/recovery/clipboard/offline y acciones destructivas muestran alcance sin secretos por defecto. No formularios sin operación ni CLI-only como reemplazo de TUI.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Implementado en la TUI humana existente, sobre el mismo custodio, motor y canal
TLS/RPK. Los menús de teclado cubren import CSV/1PUX con preview y decisiones,
export/backup/restore/rotaciones, pairing, retiro causal exacto, sync observable
por ID a través de lock/idle/restart, auditoría/purga y descarga streaming de
attachments mayores de 16 MiB. Las confirmaciones destructivas son cerradas,
las previsualizaciones no muestran valores y los fallos no activan rutas
alternativas.

El laboratorio PTY/multi-UID/TLS real pasó, igual que `scripts/check.sh`, el
build limpio/offline y la barrida secuencial integrada de 20 laboratorios
(`failures=0`).
Método, rojos, comandos, resultados y límites están en
[`docs/verification/ticket-25.md`](../../../docs/verification/ticket-25.md).
El candidato queda congelado para merger distinto; el último criterio y el
estado `resolved` pertenecen a esa integración.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 —23 integrado en `0b897c1` desbloquea esta tarea. Conservar cobertura de producto completo: la pantalla23 enumera adjuntos grandes pero todavía no acredita UX TUI de transferencia streaming; componer aquí las operaciones humanas de archivos/descarga/exportación sin imponer el límite de un frame ni usar CLI-only como sustituto. No declarar ese flujo probado por el catálogo de descriptores.

2026-09-13 — Claimed por Sol medium para componer flujos humanos de migración/recuperación/sync/auditoría y transferencia streaming sin pérdida de datos;23 ya integrado. Worktree independiente de24.

2026-09-14 — Merger Sol distinto compuso el candidato `2a01905` sobre 24. El
primer gate exclusivo preservó RED real `19/20`: el sidecar SQLite
`vault.sqlite3-shm` desapareció entre inspección y lectura en el escaneo final
de canarios del fixture token exchange. Con aprobación explícita se pausó y
reanudó el PID custodial propio, con reconocimiento acotado de ambos estados,
lectura de todos los archivos presentes y cleanup estricto antes de `PASS`.
El verde final terminó: token enfocado rc 0, `check.sh` rc 0 (75 s), clean
locked/offline rc 0 (44 s; 11,754 archivos/4.1 GiB) y una única barrida
secuencial `count=20 failures=0` (617 s). No hubo skips, retries de operaciones
ni cambios de deadline. Esta evidencia integra y resuelve 25 sólo para Linux;
no acredita nativos ni la revisión formal final.
