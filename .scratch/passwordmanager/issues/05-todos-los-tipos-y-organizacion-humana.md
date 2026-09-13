# 05 — Todos los tipos y organización humana

Type: task
Status: claimed
Owner: sol-05
Blocked by: 04
Spec: ../spec.md
Requirements: R03,R04,R05,R09
Model: gpt-5.6-sol

## Objective
Roundtrip exacto de password/TOTP/passkey/SSH/token/nota/archivo, campos desconocidos preservables y adjuntos Unicode; buscar/etiquetar/favoritos/generador funcionan vía caso de uso humano con configuración y fallo RNG; índices, staging y archivos no filtran canarios y límites/tamaños se rechazan sin truncar. No passkey virtual como autenticación real.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G6§§2–3; G2; G7; V02,V07; H4–6.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Roundtrip exacto de password/TOTP/passkey/SSH/token/nota/archivo, campos desconocidos preservables y adjuntos Unicode.
- [ ] buscar/etiquetar/favoritos/generador funcionan vía caso de uso humano con configuración y fallo RNG.
- [ ] índices, staging y archivos no filtran canarios y límites/tamaños se rechazan sin truncar. No passkey virtual como autenticación real.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Integración parcial `ca1309d` del candidato `1f63086`, sin resolución: clean offline build, check (30 tests) y labs 03/04/05 pasan, pero no acreditan streaming de adjuntos >16 MiB. El autor está corrigiendo el límite in-memory heredado de `FileCiphertext`/RPC para cumplir G6 hasta 16 GiB. No bajar el límite del contrato ni desbloquear 07 con esta entrega parcial.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera paralela 05/06 tras integración verificada de 04. Conservar motor/commit compartidos, sin revisión formal Astra por ticket.

2026-09-13 — Merger conservó merge parcial no destructivo y checks verdes; autor reportó gap de streaming/rango de archivos antes del cierre. 05 sigue claimed hasta implementar y verificar ese criterio.
