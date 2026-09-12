# 03 — Custodia Linux nativa, peer bilateral y fail-closed

Type: task
Status: open
Owner: unassigned
Blocked by: 02
Spec: ../spec.md
Requirements: R02,R09,R10,R11
Model: gpt-5.6-sol

## Objective
Servicio/perfiles de laboratorio separan custodio/humano/agente; peer impostor y lectura/sustitución de recursos protegidos son denegados; claves/bootstrap sobreviven a reinicio de proceso sin TUI y fallos detectables de ACL/identidad/clave devuelven CUSTODY_UNAVAILABLE. Reboot real completo queda además en 30.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G1; G4§§4,7; G7; V05,V08,V13; H59.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Sondeo de laboratorio Linux](../../../docs/verification/linux-lab-preflight.md) — viabilidad del entorno solamente, no aceptación del producto.
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Servicio/perfiles de laboratorio separan custodio/humano/agente.
- [ ] peer impostor y lectura/sustitución de recursos protegidos son denegados.
- [ ] claves/bootstrap sobreviven a reinicio de proceso sin TUI y fallos detectables de ACL/identidad/clave devuelven CUSTODY_UNAVAILABLE. Reboot real completo queda además en 30.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-12 — Sondeo no privilegiado verificó que userns con sub-UIDs permite laboratorio multi-UID real. No implementa 03 ni sustituye TLS/RPK, códigos públicos y tests del producto; perfil de producción/reboot permanecen sujetos a evidencia nativa.
