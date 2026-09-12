# Tickets de implementación v1.0

DAG aprobado por el usuario. Estados/propietarios/evidencia residen únicamente en cada ticket; este índice no duplica estados.

[Especificación](../spec.md) · [DAG y cobertura](../implementation-plan.md) · [Ejecución](../execution.md)

| Ticket | Dependencias | Modelo |
|---|---|---|
| [01 — Build reproducible y runner de procesos](01-build-reproducible-y-runner-de-procesos.md) | none | Sol |
| [02 — Crear/abrir bóveda cifrada local](02-crear-abrir-boveda-cifrada-local.md) | 01 | Sol |
| [03 — Custodia Linux nativa, peer bilateral y fail-closed](03-custodia-linux-nativa-peer-bilateral-y-fail-closed.md) | 02 | Sol |
| [04 — Transacción humana firmada y primer CRUD](04-transaccion-humana-firmada-y-primer-crud.md) | 03 | Sol |
| [05 — Todos los tipos y organización humana](05-todos-los-tipos-y-organizacion-humana.md) | 04 | Sol |
| [06 — Auditoría cifrada y purga explícita](06-auditoria-cifrada-y-purga-explicita.md) | 04 | Sol |
| [07 — Registro, revocación y conjunto común](07-registro-revocacion-y-conjunto-comun.md) | 05,06 | Sol |
| [08 — Intentos persistentes e idempotencia pública](08-intentos-persistentes-e-idempotencia-publica.md) | 07 | Sol |
| [09 — CLI delegada y MCP stdio equivalentes](09-cli-delegada-y-mcp-stdio-equivalentes.md) | 08 | Luna |
| [10 — Password/TOTP Chromium privado + Keycloak OIDC](10-password-totp-chromium-privado-keycloak-oidc.md) | 08 | Sol |
| [11 — Token exchange Keycloak acotado](11-token-exchange-keycloak-acotado.md) | 08 | Sol |
| [12 — SSH y cuentas de sistema con conexión confirmada](12-ssh-y-cuentas-de-sistema-con-conexion-confirmada.md) | 08 | Sol |
| [13 — Proveedor passkey custodial y puente MV3](13-proveedor-passkey-custodial-y-puente-mv3.md) | 05,08 | Sol |
| [14 — Passkey propia hasta login Keycloak](14-passkey-propia-hasta-login-keycloak.md) | 10,13 | Sol |
| [15 — Petición GitHub bearer opaco tipada](15-peticion-github-bearer-opaco-tipada.md) | 08 | Sol |
| [16 — Reductor firmado de contenido y autoridad](16-reductor-firmado-de-contenido-y-autoridad.md) | 07 | Sol |
| [17 — Sync autohospedado y emparejamiento E2EE](17-sync-autohospedado-y-emparejamiento-e2ee.md) | 16 | Sol |
| [18 — Historial, papelera y purga humana](18-historial-papelera-y-purga-humana.md) | 05,16 | Sol |
| [19 — CSV Chrome/Apple y mapeable, staging y reportes](19-csv-chrome-apple-y-mapeable-staging-y-reportes.md) | 05,07 | Sol |
| [20 — Importador 1PUX3 y adjuntos hostiles](20-importador-1pux3-y-adjuntos-hostiles.md) | 19 | Sol |
| [21 — Backup PMB1/PMF1 y exportación humana](21-backup-pmb1-pmf1-y-exportacion-humana.md) | 18,06 | Sol |
| [22 — Recuperación, rotación de vías y compromiso](22-recuperacion-rotacion-de-vias-y-compromiso.md) | 21,17 | Sol |
| [23 — TUI completa de contenido y exposición humana](23-tui-completa-de-contenido-y-exposicion-humana.md) | 05,18 | Luna |
| [24 — TUI de acceso delegado y pendientes](24-tui-de-acceso-delegado-y-pendientes.md) | 08,13,23 | Luna |
| [25 — TUI de migración, recuperación, sync y auditoría](25-tui-de-migracion-recuperacion-sync-y-auditoria.md) | 17,19,20,21,22,23 | Luna |
| [26 — Custodia y canal humano macOS](26-custodia-y-canal-humano-macos.md) | 03,07,08 | Sol |
| [27 — Custodia y canal humano Windows](27-custodia-y-canal-humano-windows.md) | 03,07,08 | Sol |
| [28 — Fallos operativos, canarios y crash safety integral](28-fallos-operativos-canarios-y-crash-safety-integral.md) | 09,10,11,12,14,15,17,18,19,20,21,22,25 | Sol |
| [29 — Paquetes, TUF, mantenimiento y fuente correspondiente](29-paquetes-tuf-mantenimiento-y-fuente-correspondiente.md) | 22,25,26,27 | Sol |
| [30 — Evidencia nativa Linux en dos arquitecturas](30-evidencia-nativa-linux-en-dos-arquitecturas.md) | 24,28,29 | Sol |
| [31 — Evidencia nativa macOS en dos arquitecturas](31-evidencia-nativa-macos-en-dos-arquitecturas.md) | 24,28,29 | Sol |
| [32 — Evidencia nativa Windows en dos arquitecturas](32-evidencia-nativa-windows-en-dos-arquitecturas.md) | 24,28,29 | Sol |
| [33 — Matriz real P1–P5 y compatibilidad seis targets](33-matriz-real-p1p5-y-compatibilidad-seis-targets.md) | 10,11,12,14,15,30,31,32 | Sol |
| [34 — Gate independiente de criptografía y aislamiento](34-gate-independiente-de-criptografia-y-aislamiento.md) | 28,30,31,32,33 | Astra coordina; revisor independiente externo |
| [35 — Revisión unificada y cierre verificable de la especificación](35-revision-unificada-y-cierre-verificable-de-la-especificacion.md) | 09,24,25,29,30,31,32,33,34 | Astra review; merger dedicado ejecuta |
