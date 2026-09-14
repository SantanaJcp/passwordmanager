# 16 — Reductor firmado de contenido y autoridad

Type: task
Status: resolved
Owner: sol-16
Blocked by: 07
Spec: ../spec.md
Requirements: R05,R06,R16,R17
Model: gpt-5.6-sol

## Objective
G5 con DAG firmado, generations/cortes, desempate exacto y antirreplay pasa permutaciones 2/3 dispositivos, forks, reloj adelantado y revocación cruzada; delete frente edit deja ganador en papelera y solo restore explícito activa; checkpoints/purga conservan headers y no reviven autoridad/elementos ante omisión/replay. Sin timestamp LWW para revocaciones.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G5§9; ADR0002; V15–V18; H35–37,54–55.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] G5 con DAG firmado, generations/cortes, desempate exacto y antirreplay pasa permutaciones 2/3 dispositivos, forks, reloj adelantado y revocación cruzada.
- [x] delete frente edit deja ganador en papelera y solo restore explícito activa.
- [x] checkpoints/purga conservan headers y no reviven autoridad/elementos ante omisión/replay. Sin timestamp LWW para revocaciones.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato `56b41ee3b9871bd8163ccc6594498728d2d52ea6`
y su evidencia correctiva `4f4cc328ee3f5f53564c503d099db266e51349bf`,
partiendo directamente de `261ebe2c1a3408671aabdd8379ad583105f0aab2`.
La implementación quedó integrada sin conflictos como
`93bcc785234b995e4adcaabc064662a179b7536e` y la
verificación del merger está registrada en
[`docs/verification/ticket-16.md`](../../../docs/verification/ticket-16.md).
El reductor usa la tabla `authority_events` existente, conserva forks con un
índice de slot no único, admite firma humana nula solo para join/checkpoint y
mantiene operativo `DelegatedVault::authorize`.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera paralela08/16 tras07 integrado/verificado. 19 también desbloqueado y en cola de capacidad; se conserva merger separado.

2026-09-12 — Merger dedicado comprobó rango directo, integración no
destructiva, seams públicos sobre `HumanVault`/`DelegatedVault`, 6 pruebas
causales, 46 pruebas de workspace, los cuatro laboratorios Linux actuales y
build limpio offline. Todos terminaron con exit 0; no se ejecutó revisión
formal Astra ni se amplió el alcance a sync/transporte del ticket 17.
