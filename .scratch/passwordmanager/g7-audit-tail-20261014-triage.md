# Triage del witness G7 acotado

Resultado `e44854e451b4dea705fdf57972ea3bb3ba78ae1d`: **BLOCKED** para la pregunta bootstrap + vault. Informe del worker [local](/home/santana/.t3/worktrees/passwordmanager/t3-01325f72/docs/verification/chef-g7-audit-tail-20261014.md). Principios: `prove`, `truthful-state`, `evidence`, `small-owned`, `no-fallbacks`.

## Evidencia aceptada, sin cierre del contrato

- Worker midió dos baselines originales rc1, dos witnesses ambiguos rc1 y dos controles completed rc0. Counts RDWR, retorno y primera aserción originales preservados.
- Bootstrap: counts10→12; registro11 `AuthUse/Accepted`, registro12 `AuthState/Indeterminate`; actorAgent y mismo attempt autenticados. Prefijo ciphertext y filas de once tablas de autoridad/receipt idénticos; provider calls1, estadoindeterminate, terminal_at_us null. Esto no acredita login nuevo, éxito externo ni nueva autoridad terminal en esas fronteras.
- Seis consultas válidas autenticaron firma/AEAD/hash-chain desde seq1; seis tamper controls devolvieron exactamente `Crypto(Authentication)`. Parent inspeccionó los seis logs y verificó los hashes de seis snapshots conservados, recibos, manifest y copia del helper ejecutado. No ejecutó Cargo ni labs.
- Vault: segunda captura no progresó durante pausa SIGSTOP, observador interrumpido, daemon reanudado explícitamente. Un snapshot válido, `capture_errors=[KeyboardInterrupt]`. Captura y conclusión de cola **inválidas**; no extrapolar bootstrap.

## Límites y procedencia

Trace + pausa perturban scheduling. Counts RDWR puede checkpoint y permanece original. Es una observación perturbadora, no prueba de ausencia de efectos. No invariancia de todos los estados intermedios.

La consulta pública abre una copia y agrega HumanUnlock, luego valida los registros; no autentica el manifiesto original antes del unlock, que reconstruye el manifiesto de la copia. El propio log declara `original_manifest_preunlock_verified=false`. Reason/frontier no expuestos por AuditRecordView.

Helper ambiguo ejecutado y conservado SHA256 `203f06f07cb2a689e8fd447ab22a8b23feba2eb117245bb5a3ad650137537801`. Helper final agregó guard BUSY/LOCKED/budget, ejecutado solo por controles completed; no atribuirle ambiguos previos ni rerun. Guard y controles no vuelven válida la captura vault.

Diff productivo/custody_loss_lab/attempts_lab/manifests vacío contra `8cd45529`; nuevos lector Rust, sidecar Python e informe solamente. Parent verificó AST/diff, sin revisión de seguridad independiente ni fullcheck. Lector nuevo usa `std::os::unix` sin gate: inferencia de brecha de compilación all-target en no-Unix si se promueve a candidato multiplataforma. **e448 se conserva como evidencia separada, no se agrega al vector del producto**.

## Acción

Termina la serie finita; sin búsqueda de una corrida favorable, nueva matriz, relajación de oracle o cierre G7. La retención EIO/ENOSPC1/1/17 y la representación prepared/durable requieren el acuerdo4 y su prueba específica. G7 y vault semantics pendientes. Caller migrations y alineación de guía siguen; final composición exacta pendiente. Permisos3/4 no ampliados.
