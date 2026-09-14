# 07 — Registro, revocación y conjunto común

Type: task
Status: resolved
Owner: sol-07
Blocked by: 05,06
Spec: ../spec.md
Requirements: R06,R07,R08,R09,R11,R12
Model: gpt-5.6-sol

## Objective
Alta humana, bootstrap/identidad RPK, generations y revocación individual persisten; dos agentes ven exactamente el mismo conjunto habilitado y metadata mínima, importados/no autenticables excluidos; bloqueo humano no suspende delegación, suspensión global sí persiste y cada uso verifica autoridad. Implementar eventos locales del contrato G5, no autoridad provisional basada en timestamps.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G4§§7,9; G5§9; G2; V03–V05,V12; H16–18,28–30.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Alta humana, bootstrap/identidad RPK, generations y revocación individual persisten.
- [x] dos agentes ven exactamente el mismo conjunto habilitado y metadata mínima, importados/no autenticables excluidos.
- [x] bloqueo humano no suspende delegación, suspensión global sí persiste y cada uso verifica autoridad. Implementar eventos locales del contrato G5, no autoridad provisional basada en timestamps.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
El candidato `29089a383b9bab212184a963609a55046c9d2949`, hijo directo de
`104e19eca882d80a53ea503aca7060b21d37864e`, se integró sin conflictos y sin
reescritura como merge `07b9b025a285b124a08a4e81014e3dfc3f806b62` en
`codex/implement-passwordmanager`.

Evidencia observada en la rama unificada:

- `./scripts/cargo-local.sh test -p pm-vault --test delegated_authorization --locked --offline` — exit 0; 3 pasaron. Verificó conjunto común para dos RPK, lock humano independiente, suspensión global, revocación terminal, generación 2, reinicio, corrupción rechazada y rollback de autoridad cuando falla auditoría.
- `./scripts/test-linux-authorization-lab.sh` — exit 0; dos agentes/UID/RPK distintos recibieron exactamente el mismo conjunto mínimo por TLS 1.3 `pm-agent/1`; el flujo humano TLS `pm-human/1` persistió enrolamiento, suspend/resume, revoke/re-enrol y receipt replay, con auditoría atómica.
- `./scripts/check.sh` — exit 0; inputs fijados, fmt, check, 40 tests y clippy pasaron sin skips.
- `./scripts/clean-offline-build.sh` — exit 0; inputs fijados verificados, 9109 archivos/1.3 GiB eliminados y workspace offline compilado en 19.53 s.
- `./scripts/test-linux-custody-lab.sh` — exit 0; bootstrap sintético SHA-256 `d6a12b9661003ad8062ba2289eeb116b230b48e4c27b79fb731ee5ad22f648f9`.
- `./scripts/test-linux-human-transaction-lab.sh` — exit 0; CRUD/atomicidad/auditoría 06 pasaron; bootstrap sintético SHA-256 `0932cc447fe041750ed64bcd78fe50efe5da603b7d9ac26dd01dcf0662736814`.
- `./scripts/test-linux-content-lab.sh` — exit 0; contenido/streaming/SIGKILL y auditoría pasaron; bootstrap sintético SHA-256 `1d7e0a701b0e2ff15095c70fb1edc4a419e4a7de9f482b7ff8d036586b2ad4bf`.
- `git diff --check 104e19e..29089a3` y el árbol integrado terminaron sin errores ni marcadores de conflicto.

La evidencia detallada está en
[ticket-07](../../../docs/verification/ticket-07.md). Solo se observó Linux
x86_64 y reinicio de proceso; no reboot de host, servicio/FDE productivo ni
otros targets. No se ejecutaron acciones de proveedores, uso delegado real,
sync/reducción multi-dispositivo ni alcance 08+. La revisión formal Astra
permanece diferida hasta el final del DAG.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol tras05/06 integrados yverificados; nueva frontera07. No reviewformalAstra por ticket.

2026-09-13 — Merger integró `29089a3` como `07b9b02` y verificó clean offline build, check (40 tests) y todos los laboratorios Linux vigentes. El E2E real probó dos agentes RPK, conjunto común, lock distinto de suspend, revoke/generation 2, reinicio y auditoría atómica; ticket resuelto sin anticipar revisión Astra.
