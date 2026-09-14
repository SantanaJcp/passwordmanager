# 17 — Sync autohospedado y emparejamiento E2EE

Type: task
Status: resolved
Owner: sol-17
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
- [x] Dos/tres custodios reales y servidor opaco emparejan/retiran mediante autoridad humana y convergen.
- [x] offline mantiene uso con última autoridad y retiro conocido bloquea siguiente uso, reconexión idempotente sin compartir DB/WAL.
- [x] ciphertext/tráfico/servidor no contienen claves/secretos y alteración/falta de objetos jamás activa revisión parcial.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato `afdf9edfdd598b982bea28b971d7bcce39081b2b`,
descendiente de `996ac5d47e3a58e805f9a2ac39c9ca7ce96a13d8`, e
integrado sin reescribir historia mediante
`da335d595e16c3a7660286d3a7d0cab8c3b4cdae` sobre la rama unificada con
08/09/19 preservados. Dos conflictos se resolvieron conservando a la vez los
reason codes y contratos de intentos existentes, el body map4/map5 con
`object_manifest_digest` y las interfaces de sync. La evidencia TDD, E2E real,
límites y verificación unificada está en
[`docs/verification/ticket-17.md`](../../../docs/verification/ticket-17.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera real17/19; 08candidato listo para integraciónserial delmerger. ReviewformalAstraalfinal.

2026-09-13 — El merger dedicado verificó el candidato sobre el árbol unificado
con 08/09/19: 5 pruebas sync E2E, 6 de autorización delegada, 3 CSV, contrato
CLI/MCP, 62 pruebas del workspace, `check.sh`, build limpio offline y los siete
laboratorios Linux terminaron con exit 0. El recorrido compuesto ejercitó tres
custodios, TLS 1.3/RPK/ALPN real, servidor opaco, objetos/adjuntos y descriptores
paginados, retry idempotente/backpressure, activación grafo+autoridad en una
transacción, omisión y crash rollback. No se tocó el checkpoint 18, no se hizo
push ni revisión formal Astra; Internet público y servicio de producción siguen
fuera de la evidencia.
