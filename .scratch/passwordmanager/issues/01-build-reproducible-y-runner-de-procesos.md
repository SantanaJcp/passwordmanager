# 01 — Build reproducible y runner de procesos

Type: task
Status: resolved
Owner: sol-01
Blocked by: none
Spec: ../spec.md
Requirements: R01,R02,R20
Model: gpt-5.6-sol
Labels: ready-for-agent

## Objective
Workspace mínimo y ejecutable CLI arrancan con toolchain seleccionado; Cargo.lock/features y libsodium C verificadas sin fetch-latest; runner lanza procesos reales con directorios temporales y conserva exit/status, build y canarios. Inventario inicial de componentes/licencias no afirma auditoría final.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: §5–6; G1§8; G8§2.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Workspace mínimo y ejecutable CLI arrancan con toolchain seleccionado.
- [x] Cargo.lock/features y libsodium C verificadas sin fetch-latest.
- [x] runner lanza procesos reales con directorios temporales y conserva exit/status, build y canarios. Inventario inicial de componentes/licencias no afirma auditoría final.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Integrado el candidato `331881b5829f6b344d856bdf105b432ddc04f233`, hijo directo de la base `7d541a2c7569c6db97f23c8f5f48eef74fed96d6`, mediante el merge no destructivo `8f37b39d8cfdb1ac0ec0fecaa06069e7c0d0a7b2` en `codex/implement-passwordmanager`. Los 26 paths del candidato coinciden byte por byte con los integrados y `git diff --check 7d541a2..331881b` terminó con exit 0.

Evidencia observada en la rama unificada:

- `./scripts/clean-offline-build.sh` — exit 0; verificó ambos hashes de libsodium, limpió el target y compiló el workspace completo con lockfile y modo offline usando Rust 1.98.1.
- `./scripts/check.sh` — exit 0; `fmt`, `check`, tests y `clippy` pasaron con lockfile y modo offline. Resultado: 9 tests pasaron, 0 fallaron y 0 fueron ignorados (CLI 1, enlace libsodium 1, runner de procesos 7).
- `./target/debug/pm --version` — exit 0; salida exacta: `passwordmanager 0.1.0 (libsodium 1.0.22)`.
- La evidencia TDD red/green, comandos y límites está preservada en `docs/verification/ticket-01.md`; los contratos de build e inventario inicial están en `docs/build/reproducible-build.md` y `docs/build/component-inventory.md`.

Límite real: la comprobación fue solo en Linux x86_64. No certifica los otros cinco targets, seguridad del producto, release readiness ni auditoría final de licencias. La revisión formal Astra permanece diferida hasta integrar todos los tickets por instrucción del usuario; este cierre registra comprobación de alcance e integración, no esa revisión final.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-12 — Reclamado por Sol para worktree aislado codex/pm-01; el merger decidirá resolución tras integrar/verificar.

2026-09-12 — Merger integró `331881b` como `8f37b39`, comprobó identidad de los 26 paths y ejecutó `clean-offline-build.sh`, `check.sh` y `pm --version`, todos con exit 0. Ticket resuelto; revisión formal diferida al cierre del DAG.
