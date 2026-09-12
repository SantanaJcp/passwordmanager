# 02 — Crear/abrir bóveda cifrada local

Type: task
Status: resolved
Owner: sol-02
Blocked by: 01
Spec: ../spec.md
Requirements: R01,R04,R09,R15,R18
Model: gpt-5.6-sol

## Objective
CLI humana crea bóveda real sin red/cuenta y vuelve a abrir tras restart; suite G2 de bytes/contexto/propósito, KDF, AAD, envoltorios y parser adversario pasa; contraseña errónea/archivo alterado/version incompatible no mutan bóveda válida. SQLite/WAL solo reciben objetos precifrados y ninguna raíz se serializa en claro.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G2§§7–9; G6§2; V01,V07,V21; H1,43.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] CLI humana crea bóveda real sin red/cuenta y vuelve a abrir tras restart.
- [x] suite G2 de bytes/contexto/propósito, KDF, AAD, envoltorios y parser adversario pasa.
- [x] contraseña errónea/archivo alterado/version incompatible no mutan bóveda válida. SQLite/WAL solo reciben objetos precifrados y ninguna raíz se serializa en claro.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

### Límite de aceptación G2 de este corte

- Cubrir formato CBOR determinista y límites adversarios, contexto/propósito/AAD completos de G2 §§7–9, sobres, KDF, conservación ante error y vectores sintéticos de formatos.
- Incluir base humana KH/SK_H y raíz PK_H confiable, vía KR con reintroducción al alta, y manifiesto con partes/sobres externos sin ciclos; no reducir este ticket a cifrar/abrir un blob.
- Los flujos operativos de CRUD firmado (04), tipos (05), disponibilidad/autoridad (07/16), backup/rotación/restore (21/22) y evidencia nativa/independiente (30–34) conservan sus tickets. Los vectores de sus formatos no equivalen a esos flujos ni a «G2 completo validado».

## Answer
Integrado el candidato `1605e5c1be5f813f399de87f3316ce90038d8b83`, hijo directo de la base `bf76a58e25a53ab95b46b73351c7ec16b66737a9`, mediante el merge no destructivo `949578569bd3817740c2b4ef741ffd3a5a16c8e8` en `codex/implement-passwordmanager`. Los 17 paths del candidato coinciden byte por byte con los integrados y `git diff --check bf76a58..1605e5c` terminó con exit 0.

Evidencia observada en la rama unificada:

- `./scripts/clean-offline-build.sh` — exit 0; verificó ambos hashes de libsodium, eliminó 3597 archivos/300.6 MiB del target y compiló el workspace completo con lockfile y modo offline en 13.67 s.
- `./scripts/check.sh` — exit 0; `fmt`, `check`, tests y `clippy` pasaron con lockfile y modo offline. Resultado: 21 tests pasaron, 0 fallaron y 0 fueron ignorados, incluidos CLI real, vectores G2 y conservación atómica de la bóveda.
- Ejecución manual con datos sintéticos y dos procesos reales: `pm vault create PATH` terminó con exit 0, exigió reintroducir el código `PMR1-…` antes de publicar; luego `pm vault open PATH` terminó con exit 0 y observó el mismo ID. Ambos `stderr` quedaron vacíos; contraseña, código e ID sintéticos no se registran aquí.
- `./target/debug/pm --version` — exit 0; salida exacta: `passwordmanager 0.1.0 (libsodium 1.0.22)`.
- Se conservan Rust `1.98.1` y el árbol fuente/hash de libsodium sin cambios respecto de la base. `Cargo.lock` queda fijado y su SHA-256 integrado es `09f81fbdfb6587b4fc6c0c7bd5bd9c943519aa97d4234444840a4b1e0c571e81`.
- La evidencia TDD red/green, comandos, formatos cubiertos y límites está preservada en `docs/verification/ticket-02.md`.

Límite real: la comprobación fue solo en Linux x86_64. No valida flujos operativos posteriores de CRUD/autoridad/reducer/backup, custodia nativa, los otros cinco targets ni revisión criptográfica independiente. La revisión formal Astra permanece diferida hasta integrar todos los tickets por instrucción del usuario; este cierre registra comprobación de alcance e integración, no esa revisión final.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-12 — Astra concretó el límite de aceptación G2 del corte: fundamento criptográfico completo, sin absorber flujos operativos asignados posteriormente ni declarar validación runtime global.

2026-09-12 — Reclamado por Sol tras integrar y verificar 01; worktree aislado codex/pm-02. Review formal Astra reservado al final del DAG.

2026-09-12 — Merger integró `1605e5c` como `9495785`, comprobó identidad de los 17 paths, preservación de toolchain/libsodium y ejecutó build offline, suite completa y CLI create/open real, todo con exit 0. Ticket resuelto; revisión formal diferida al cierre del DAG.
