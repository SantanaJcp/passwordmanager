# 04 — Transacción humana firmada y primer CRUD

Type: task
Status: resolved
Owner: sol-04
Blocked by: 03
Spec: ../spec.md
Requirements: R03,R04,R06,R09
Model: gpt-5.6-sol

## Objective
Crear/leer/editar/eliminar una contraseña por canal humano real usa prepare/commit/receipt y SK_H; challenge vencido/body cambiado/rol falso/replay son rechazados; pérdida de respuesta/commit interrumpido recupera recibo o no-op sin escritura parcial. No aceptar `role=human` por request.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G4§9; G2§9; G6§2; V02,V05,V22; H4,63.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Crear/leer/editar/eliminar una contraseña por canal humano real usa prepare/commit/receipt y SK_H.
- [x] challenge vencido/body cambiado/rol falso/replay son rechazados.
- [x] pérdida de respuesta/commit interrumpido recupera recibo o no-op sin escritura parcial. No aceptar `role=human` por request.
- [x] El commit durable de G4 §9 incluye el registro cifrado mínimo de auditoría de la operación en la misma transacción que eventos/partes/challenge/outbox. Un fallo de auditoría impide la mutación; no usar callbacks vacíos ni escrituras posteriores. El ticket 06 amplía segmentos/consulta/purga sobre este mecanismo ya real.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Integrados los commits candidatos `c6159fa9aa5cf06a0b784e90f37eec022cd4a24e` y `04d434c424c2441385ccf4d32e62af7710c08f5a`, sobre base `cd74aed649966287c214538e37c17e2efc698123`, mediante el merge no destructivo `4a190ecaa2d08f7469a60d2fb3484588d9897fcb` en `codex/implement-passwordmanager`. En ese merge los 16 paths del candidato coincidían byte por byte con lo integrado y `git diff --check cd74aed..04d434c` terminó con exit 0.

Evidencia observada en la rama unificada:

- `./scripts/clean-offline-build.sh` — exit 0; verificó ambos hashes de libsodium, eliminó 5863 archivos/799.5 MiB del target y compiló el workspace completo con lockfile y modo offline en 15.89 s.
- `./scripts/check.sh` — exit 0; `fmt`, `check`, tests y `clippy` pasaron con lockfile y modo offline. Resultado: 26 tests pasaron, 0 fallaron y 0 fueron ignorados; cuatro corresponden al motor de transacciones humanas.
- `./scripts/test-linux-custody-lab.sh` — exit 0; el laboratorio previo multi-UID/TLS RPK/ALPN/reinicio continuó conectado y verde, con bootstrap sintético SHA-256 `65eff10a7d4787e7bac4daff19d2333b38a43c84f2bf5a15568bf2d05cd1511e`.
- `./scripts/test-linux-human-transaction-lab.sh` — exit 0; recorrió procesos públicos reales por UID humano y `SO_PEERCRED`, TLS 1.3 RPK mutuo y ALPN `pm-human/1` hasta el handler custodio y SQLite. Observó `human_crud=prepare-commit-receipt` y `human_negatives=wrong-role,body-change,audit-failure atomicity=no-partial replay=receipt response-loss=recovered`, con bootstrap sintético SHA-256 `3b384610ab6cb649143bbf32af7ad29198c3aad73302a520b6318b232767a408`.
- El fallo de auditoría se inyectó en SQLite y fue alcanzado por commit sobre ese canal TLS: no cambió ítem, revisión, evento de autoridad, outbox, recibo, clave/head/registro de auditoría ni consumo del challenge. Tras retirar el trigger, create/edit/delete escribieron auditoría cifrada atómicamente; pérdida de respuesta y replay recuperaron el recibo sin reaplicar el efecto.
- Ambos laboratorios imprimieron exactamente `LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN`; no quedó proceso `pm-custody` ni estado persistente del laboratorio. Se conservaron Rust `1.98.1` y fuente/hash de libsodium; `Cargo.lock` integrado tiene SHA-256 `155ef9f01a88a75f399021e32d9833dc42a136b89d590e6d9edb6350b58aa634`.
- La evidencia TDD, el red específico que probó que `c6159fa` aún no atravesaba el transporte, comandos y límites quedan en `docs/verification/ticket-04.md`, ahora completado con esta verificación de integración.

Límite real: se verificó laboratorio Linux x86_64 con reinicio de proceso, no reboot del host, perfil systemd/FDE de producción, otros targets, sync/reducción multi-dispositivo, autorización delegada, autenticación externa ni consulta/segmentación/purga completa de auditoría. La revisión formal Astra permanece diferida hasta integrar todos los tickets.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-12 — Astra explicitó el registro cifrado mínimo de auditoría en el commit atómico G4; 06 amplía ese mecanismo. No cambia el DAG ni el contrato.

2026-09-12 — Reclamado por Sol tras 03 integrado/verificado; mantener registro de auditoría cifrado atómico mínimo para extensiones paralelas 05/06.

2026-09-12 — Merger integró el candidato completo hasta `04d434c` como `4a190ec` y ejecutó build/check y ambos laboratorios multi-UID. Todo terminó con exit 0; el recorrido 04 quedó compuesto sobre TLS RPK/ALPN de 03, incluida atomicidad de auditoría y recuperación de recibo. Ticket resuelto; revisión formal reservada al cierre del DAG.
