# 19 — CSV Chrome/Apple y mapeable, staging y reportes

Type: task
Status: resolved
Owner: sol-19
Blocked by: 05,07
Spec: ../spec.md
Requirements: R04,R07,R19
Model: gpt-5.6-sol

## Objective
Fixtures sintéticos de los tres orígenes conservan campos/tipos exportados, Unicode y desconocidos o los reportan individualmente; preview/mapping/duplicados/confirmación escribe transacción humana paginada de eventos y objetos, sin auto-enable; truncado/límites/columnas y crash rechazan sin parcialidad, sin leer bases privadas ni borrar fuente. Motor/import contract completo antes de encargar UI mecánica.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G6§§3–4; G4§9; V04,V19,V22; H12–13,46–47.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Fixtures sintéticos de los tres orígenes conservan campos/tipos exportados, Unicode y desconocidos o los reportan individualmente.
- [x] preview/mapping/duplicados/confirmación escribe transacción humana paginada de eventos y objetos, sin auto-enable.
- [x] truncado/límites/columnas y crash rechazan sin parcialidad, sin leer bases privadas ni borrar fuente. Motor/import contract completo antes de encargar UI mecánica.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Resuelto por el candidato `8801a5ad47d178010e74b7af382a024330f5d665`,
descendiente directo de `996ac5d47e3a58e805f9a2ac39c9ca7ce96a13d8`,
e integrado sin reescribir historia mediante
`25cc2b049375ea065c5607014e83f10b52781db6`. El único conflicto, en los
imports de custodia Linux, se resolvió conservando simultáneamente las
interfaces de intentos 08/09 y las nuevas interfaces CSV. La evidencia
TDD, del laboratorio real y de la verificación unificada está en
[`docs/verification/ticket-19.md`](../../../docs/verification/ticket-19.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera real17/19; 08candidato listo para integraciónserial delmerger. ReviewformalAstraalfinal.

2026-09-12 — El merger dedicado verificó el candidato sobre la rama unificada
con 08/09/16: 3 pruebas CSV, 6 causales, 2 CLI delegadas, 56 pruebas de
integración del workspace, build limpio offline y los seis laboratorios Linux
actuales terminaron con exit 0. El laboratorio CSV ejercitó import Chrome,
enable humano separado, reemplazo atómico, disable G5/reductor, pérdida de
respuesta, reinicio y skip exacto; el fallo de auditoría no dejó efecto
parcial. No se integraron 17/10 ni se ejecutó revisión formal Astra.
