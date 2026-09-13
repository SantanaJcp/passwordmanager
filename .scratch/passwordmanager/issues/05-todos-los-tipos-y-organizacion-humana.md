# 05 — Todos los tipos y organización humana

Type: task
Status: resolved
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
- [x] Roundtrip exacto de password/TOTP/passkey/SSH/token/nota/archivo, campos desconocidos preservables y adjuntos Unicode.
- [x] buscar/etiquetar/favoritos/generador funcionan vía caso de uso humano con configuración y fallo RNG.
- [x] índices, staging y archivos no filtran canarios y límites/tamaños se rechazan sin truncar. No passkey virtual como autenticación real.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
El correctivo `9ea748aef95ca0e0c1fa1f0e5223c8e0f1468789` se integró de forma no
destructiva mediante `d7f0389` sobre la rama unificada que ya contenía 05
parcial y 06. La resolución preservó simultáneamente los campos/digests de
staging de contenido y auditoría, el único motor `HumanVault::commit`, los
opcodes de auditoría 14–16 y los nuevos opcodes de streaming 17–18.

Evidencia observada en la rama unificada:

- `./scripts/cargo-local.sh test -p pm-vault --test content_records --locked --offline` — 5 pasaron; incluye transferencia exacta de 16 MiB + 4096 bytes en 17 chunks, fuentes cortas/largas rechazadas y staging vacío tras fallo.
- `./scripts/cargo-local.sh test -p pm-vault --test audit_lifecycle --locked --offline` — 6 pasaron; la integración no degradó auditoría 06.
- `./scripts/check.sh` — exit 0; build/check/clippy y 37 tests pasaron sin skips.
- `./scripts/clean-offline-build.sh` — exit 0; hashes fijados verificados, 9325 archivos/1.3 GiB eliminados y workspace offline compilado en 17.73 s.
- `./scripts/test-linux-custody-lab.sh` — exit 0; bootstrap sintético SHA-256 `bd43b3a183b1938b646ccd9cbbd32b2e2096295ed53de08222c91729e62e3c2e`.
- `./scripts/test-linux-human-transaction-lab.sh` — exit 0; CRUD/atomicidad/auditoría real quedaron verdes; bootstrap sintético SHA-256 `be1a032e9ec67776789067ecb3c2b4ad19b76cf8eed5f3e6636f377bb0fac555`.
- `./scripts/test-linux-content-lab.sh` — exit 0; recorrió UID/`SO_PEERCRED`/TLS 1.3 RPK/ALPN, archivo real de 16 MiB + 4096, chunks de 1 MiB, límite declarado 16 GiB aceptado sin asignarlo, 16 GiB + 1 rechazado, fuente truncada y `SIGKILL` a mitad de transacción con rollback tras reinicio. También imprimió los PASS de auditoría 06. Bootstrap sintético SHA-256 `9bf2607c20b65e66fdc81d6dd213cbddcdffc7cdedb2307838e7cb0afb4d84e7`.

Evidencia completa en [ticket-05](../../../docs/verification/ticket-05.md).
Solo se observó Linux x86_64 y reinicio de proceso; reboot de host,
systemd/FDE productivo y otros sistemas siguen sin ejecutarse. La revisión
formal Astra permanece diferida hasta el final del DAG.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Reclamado por Sol en frontera paralela 05/06 tras integración verificada de 04. Conservar motor/commit compartidos, sin revisión formal Astra por ticket.

2026-09-13 — Merger conservó merge parcial no destructivo y checks verdes; autor reportó gap de streaming/rango de archivos antes del cierre. 05 sigue claimed hasta implementar y verificar ese criterio.

2026-09-13 — Merger integró el correctivo `9ea748a` como `d7f0389`, resolvió semánticamente contenido+auditoría y verificó clean offline build, check (37 tests) y todos los laboratorios 03/04/05/06. El proceso real transfirió 16 MiB + 4096, comprobó chunks de 1 MiB, límites 16 GiB/16 GiB+1, truncado y rollback por `SIGKILL`; ticket resuelto sin revisión formal Astra anticipada.
