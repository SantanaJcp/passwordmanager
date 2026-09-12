# 17 — Sync autohospedado y emparejamiento E2EE

Type: task
Status: open
Owner: unassigned
Blocked by: 16
Spec: ../spec.md
Requirements: R06,R15,R16,R17
Model: gpt-5.6-sol

## Objective
Dos/tres custodios reales y servidor opaco emparejan/retiran mediante autoridad humana y convergen; offline mantiene uso con última autoridad y retiro conocido bloquea siguiente uso, reconexión idempotente sin compartir DB/WAL; ciphertext/tráfico/servidor no contienen claves/secretos y alteración/falta de objetos jamás activa revisión parcial.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G5§9; G4§9; V14–V18; H32–37.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Dos/tres custodios reales y servidor opaco emparejan/retiran mediante autoridad humana y convergen.
- [ ] offline mantiene uso con última autoridad y retiro conocido bloquea siguiente uso, reconexión idempotente sin compartir DB/WAL.
- [ ] ciphertext/tráfico/servidor no contienen claves/secretos y alteración/falta de objetos jamás activa revisión parcial.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.
