# 06 — Auditoría cifrada y purga explícita

Type: task
Status: resolved
Owner: sol-06
Blocked by: 04
Spec: ../spec.md
Requirements: R05,R09
Model: gpt-5.6-sol

## Objective
Eventos de actor/credencial/operación/resultado se escriben atómicamente con las mutaciones y sin KH durante autonomía; errores/crashes no guardan payloads secretos; purga humana con alcance confirmado deja evidencia visible de discontinuidad y no borra autoridad antirreplay.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G7; G2§9; V23; H31,58.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Eventos de actor/credencial/operación/resultado se escriben atómicamente con las mutaciones y sin KH durante autonomía.
- [x] errores/crashes no guardan payloads secretos.
- [x] purga humana con alcance confirmado deja evidencia visible de discontinuidad y no borra autoridad antirreplay.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Integrado el candidato `09dbae4c426ad427ebea0e542384e6464680e23d`, hijo directo de la base `6760f2bed2b0b447396a5cd647a855361d0c0e76`, mediante el merge no destructivo `994092c3c45dea9f8da56432d55ee0afa5f9d64f` en `codex/implement-passwordmanager`. `git diff --check 6760f2b..09dbae4` terminó con exit 0.

El candidato paralelo 06 y el 05 ya integrado modificaban cinco seams comunes. La resolución reconstruyó base/ours/theirs por intención: conserva `vault_items.kind`, `attachment_parts`, `human_staging.item_kind/attachments` y el digest de package+attachments de 05 junto con `audit_generation/audit_through_seq`, query/purge y custodia de 06. Las escrituras de contenido fijan ambos campos de purga a `None`; la purga no lleva package, kind ni attachments. `encode_event_manifest` liga ambos grupos, y continúa existiendo un único `HumanVault::commit`. En el RPC se reservaron 14/15/16 para autonomía/query/purga de auditoría sin colisionar con 9–13 de contenido. No quedaron marcadores de conflicto y el check del workspace compiló antes de concluir el merge.

Evidencia observada en la rama unificada:

- `./scripts/clean-offline-build.sh` — exit 0; verificó ambos hashes de libsodium, eliminó 6360 archivos/971.6 MiB del target y compiló el workspace completo con lockfile y modo offline en 15.70 s.
- `./scripts/check.sh` — exit 0; `fmt`, `check`, tests y `clippy` pasaron con lockfile y modo offline. Resultado unificado: 36 tests pasaron, 0 fallaron y 0 fueron ignorados; seis corresponden al ciclo de auditoría.
- `./scripts/test-linux-custody-lab.sh` — exit 0; preservó el laboratorio multi-UID/TLS RPK/ALPN/reinicio, con bootstrap sintético SHA-256 `e40f1b37b2ad358feeb02d5eec37ddd853d7996147a1d4cbd1d9fee6000ff9db`.
- `./scripts/test-linux-human-transaction-lab.sh` — exit 0; por el canal humano real observó `audit=encrypted,signed,segmented,query,purge autonomous_without_kh=device-custody human_path=mutual-tls-rpk`, además de atomicidad/no parcial del commit compartido. Bootstrap sintético SHA-256 `7fed6a0d60c83b3d58398cbf7240abcd1cea12a63a9241f8c0852efcf1045037`.
- `./scripts/test-linux-content-lab.sh` — exit 0; ejecutó en el mismo laboratorio compuesto tanto `content=all-types+organization+generator` como el ciclo completo de auditoría, verificando que 05 y 06 no quedaron como tramos desconectados. Bootstrap sintético SHA-256 `8aaec8d888e09ba531357456508901d2322de73f00020f4b3396f5bde9777fad`.
- Los laboratorios confirmaron custodia `0400`, autonomía tras soltar `K_H`, firma de dispositivo, query humana, purga firmada con discontinuidad visible, autoridad/outbox retenidos y reinicio de proceso con la misma custodia. Todos imprimieron `LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN`; no quedó proceso `pm-custody`.
- Se conservaron Rust `1.98.1` y fuente/hash de libsodium. `Cargo.lock`, heredado del 05, permanece fijado con SHA-256 `155ef9f01a88a75f399021e32d9833dc42a136b89d590e6d9edb6350b58aa634`. La evidencia TDD y límites criptográficos están en [ticket-06](../../../docs/verification/ticket-06.md).

Límite real: se verificó Linux x86_64 y reinicio de proceso, no reboot del host, perfil systemd/FDE productivo ni otros targets. Una reversión completa de base requiere un ancla independiente más nueva para detectarse; anchoring, sync/restore multi-dispositivo y backup permanecen en tickets posteriores. El ticket 05 sigue abierto por su gap independiente de streaming 16 MiB–16 GiB. La revisión formal Astra permanece diferida hasta integrar todos los tickets.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera paralela 05/06 tras integración verificada de 04. Conservar motor/commit compartidos, sin revisión formal Astra por ticket.

2026-09-13 — Merger integró `09dbae4` como `994092c`, resolvió cinco conflictos preservando simultáneamente los contratos 05/06 y ejecutó build, check y todos los laboratorios Linux existentes. Todo terminó con exit 0; 36 tests y el flujo real cifrado/firmado/segmentado/query/purge quedaron verdes. Ticket 06 resuelto; 05 permanece abierto y la revisión formal sigue reservada al cierre del DAG.
