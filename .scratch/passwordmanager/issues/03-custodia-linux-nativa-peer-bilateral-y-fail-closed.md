# 03 — Custodia Linux nativa, peer bilateral y fail-closed

Type: task
Status: resolved
Owner: sol-03
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
- [x] Servicio/perfiles de laboratorio separan custodio/humano/agente.
- [x] peer impostor y lectura/sustitución de recursos protegidos son denegados.
- [x] claves/bootstrap sobreviven a reinicio de proceso sin TUI y fallos detectables de ACL/identidad/clave devuelven CUSTODY_UNAVAILABLE. Reboot real completo queda además en 30.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Integrado el candidato `67fd43a0efe2188275446dd63dce1047588d434a`, hijo directo de la base `9025dee1bef97b549caa2d60fd9bd3842a6a1a01`, mediante el merge no destructivo `aa03433e828c832c0b77056b88024eb1cd8e1cb0` en `codex/implement-passwordmanager`. Los 10 paths del candidato coinciden byte por byte con los integrados y `git diff --check 9025dee..67fd43a` terminó con exit 0.

Evidencia observada en la rama unificada:

- `./scripts/clean-offline-build.sh` — exit 0; verificó ambos hashes de libsodium, eliminó 4416 archivos/508.7 MiB del target y compiló el workspace completo con lockfile y modo offline en 16.27 s.
- `./scripts/check.sh` — exit 0; `fmt`, `check`, tests y `clippy` pasaron con lockfile y modo offline. Resultado: 22 tests pasaron, 0 fallaron y 0 fueron ignorados; el proceso real `pm-custody` devolvió el contrato fail-closed en el test de bootstrap.
- `./scripts/test-linux-custody-lab.sh` — exit 0 en user namespace descartable sin sudo. Observó UID 1 custodio, UID 2 humano y UID 3 agente; separación por peer nativo, denegaciones de lectura/sustitución, TLS 1.3 con RPK mutuo y ALPN por rol. Tras un segundo proceso custodio, el agente reconectó y el bootstrap conservó SHA-256 `e5e753fe46a7a9bc6d9fa36f0fb01aaf5dc8ecfb5d43847e9877c211652da141`.
- El laboratorio imprimió exactamente `LIMIT reboot_host=NOT_RUN production_systemd_fde=NOT_RUN`. Al terminar no quedó proceso `pm-custody`; el harness retiró su directorio temporal y no creó usuarios, servicios ni configuración persistente del host.
- Se conservan Rust `1.98.1` y el árbol fuente/hash de libsodium sin cambios respecto de la base. `Cargo.lock` queda fijado y su SHA-256 integrado es `d822e15c2f938f4bde02c4bee40d462d4aef3c97a494ad328089aecc0e9b8e67`.
- La evidencia TDD red/green, comandos, aserciones públicas y límites está preservada en `docs/verification/ticket-03.md`.

Límite real: se verificó un reinicio de proceso en laboratorio Linux x86_64 no privilegiado, no reboot del host, perfil systemd/FDE de producción, Linux AArch64, macOS ni Windows. La revisión formal Astra permanece diferida hasta integrar todos los tickets por instrucción del usuario; este cierre registra comprobación de alcance e integración, no esa revisión final.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-12 — Sondeo no privilegiado verificó que userns con sub-UIDs permite laboratorio multi-UID real. No implementa 03 ni sustituye TLS/RPK, códigos públicos y tests del producto; perfil de producción/reboot permanecen sujetos a evidencia nativa.

2026-09-12 — Reclamado por Sol después de integrar/verificar 02. Laboratorio descartable multi-UID permitido sin modificar cuentas/configuración del host; no equivale a perfil de producción certificado.

2026-09-12 — Merger integró `67fd43a` como `aa03433`, comprobó identidad de los 10 paths y preservación de toolchain/libsodium, y ejecutó build offline, suite completa y laboratorio multi-UID real, todo con exit 0. Ticket resuelto; reboot/perfil de producción permanecen en 30 y la revisión formal al cierre del DAG.
