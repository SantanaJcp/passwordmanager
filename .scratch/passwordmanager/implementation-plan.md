# DAG aprobado — implementación completa (35 tickets)

Fecha: 2026-09-12. Entregable de coordinación/revisión, sin implementación; granularidad y orden aprobados por el usuario al responder «autorizado». Fuente: `.scratch/passwordmanager/spec.md` v1.0 §§0–16, `AGENTS.md`, `docs/agents/issue-tracker.md`, `CONTEXT.md` y anexos incorporados por §5.3. La autorización posterior del usuario comunicada por el orquestador permite ahora ejecutar; no atribuir esa autorización a la especificación histórica.

## 1. Condiciones de arranque y límites de ejecución

**Confirmado documentalmente:** contratos G1–G8 cerrados; los 64 recorridos están incluidos; cero perfiles certificados. No exigir producto validado para comenzar ni reemplazarlo por una investigación general. Implementar checks fallidos como gates, no como capacidades fingidas.

**Precondiciones del mecanismo de trabajo:**

1. Sin commit base no pueden crearse worktrees del proyecto. **Actualización comunicada por root:** baseline `a7597be` y rama `codex/implement-passwordmanager` creados. Usarlos preservando todo el trabajo documental; no reset/clean ni borrar `.scratch/`.
2. Crear primero los tickets locales con el formato del tracker. Cada implementador reclama exclusivamente un ticket de la frontera: `open → claimed → resolved`, y solo resuelve con evidencia entregada. Ausencia de resultado requerido no satisface dependencia. Un bloqueo conserva `open`, no inventa un estado `blocked`.
3. Un worktree/rama por implementador, basado en HEAD integrado con todas sus dependencias. Astra coordina/revisa; Sol seguridad/composición/protocolos y Luna trabajo mecánico delimitado. Merger dedicado integra serialmente y ejecuta suite completa. Usar hasta dos implementadores cuando la cuarta plaza la necesita el merger.
4. **Actualización comunicada por root:** el usuario autorizó crear repositorio público y subir documentación/código. Origin https://github.com/SantanaJcp/passwordmanager configurado y base master publicada. PR unificado borrador: https://github.com/SantanaJcp/passwordmanager/pull/1.
5. Baseline de versiones seleccionado no equivale a resolución real. Ticket 01 debe comprobar fuentes/hashes/toolchain/build. Si una versión no existe, no compila o incumple un contrato concreto, guardar evidencia y corregir el contrato propietario + §15; no cambiar silenciosamente a `latest`, sustituir libsodium ni simular construcción exitosa.

**No impiden comenzar, sí impiden cerrar el producto o anunciar soporte:**

- Disponibilidad no verificada de seis entornos nativos desechables (Linux x86_64/aarch64, macOS Intel/ARM, Windows x64/ARM64), FDE bajo condiciones G1, reboot y privilegio administrativo de laboratorio. Cross-build/WSL/emulación no sustituyen V13/V24 ni certifican otro target.
- Chromium propio fijado y extension/Native Messaging en seis targets, especialmente Windows ARM64. P1/P4 pueden refutar la realización. Browser instalado del humano o autenticador virtual no son sustitutos de producción.
- Acceso a proveedores reales autorizados para la matriz; Keycloak sintético local y OpenSSH de laboratorio pueden desarrollarse primero. GitHub real/Apple Remote Login/Windows OpenSSH no deben configurarse o usarse con credenciales ajenas sin autorización. Los dobles externos son válidos para ataques reproducibles, no acreditan compatibilidad del proveedor real.
- Revisión independiente criptográfica y de aislamiento: un agente implementador o la revisión final del mismo equipo no se autocalifican como esa evidencia.
- Certificados Developer ID/Installer/notarización/Authenticode, raíz TUF, dos custodios independientes de firma y atribución real. Solo claves sintéticas de test en laboratorio; ninguna compra/publicación/firma real implícita.
- Tiempo/espacio del build Chromium, toolchains o permisos de red no están verificados en este análisis. Reportarlos como incertidumbre de infraestructura, no como hallazgo confirmado.

Los gates de entorno son dependencias de evidencia, no excusa para eliminar funcionalidades. Si no hay recursos externos, cerrar lo implementado con estado exacto y conservar 30–35 abiertos según corresponda; no declarar la especificación completa.

## 2. Reglas comunes de aceptación y tamaño

Cada ticket debe convertirse en archivo `issues/NN-<slug>.md` con `Spec: ../spec.md`, Requirements, Owner y deps exactas. Añadir punteros a §5.3 y anexos, no copiar schemas a otra fuente normativa. Tickets publicados en [índice local](issues/README.md); esta tabla define dependencias/alcance, no duplica sus estados.

Todos los tickets de código: pruebas red/green, comandos exactos, commit, fixtures sintéticos y evidencia de interfaz pública aplicable. Ningún motor/DB/autoridad mockeado en aceptación; dobles solo en proveedor externo. Todos los criterios siguientes son conjuntivos y binarios. Un `skip`, stub, `todo!`, respuesta estática de éxito o capability no ejecutada **no satisface** el criterio. Cada suite conserva historia/V/P, build, OS/CPU, pasos, resultado y artefactos revisados por canarios. Los scopes no autorizan datos reales en archivos/logs.

Tickets 02–08 son tracer bullets acumulativos, no capas desconectadas: CLI humana/proceso real + SQLite temporal están presentes desde creación, y cada corte añade un recorrido observable. Interfaces internas no deben exponerse solo para mocks. Luna recibe contratos ya integrados; no decide primitivas, autoridad o aislamiento. Si el tamaño real exige división, actualizar DAG local antes de despachar, preservando criterios y sin tareas ocultas paralelas.

## 3. DAG aprobado

| ID / título | Modelo / dependencias | Corte entregable y criterios binarios | Punteros |
|---|---|---|---|
| **01 — Build reproducible y runner de procesos** | Sol / none | Workspace mínimo y ejecutable CLI arrancan con toolchain seleccionado; Cargo.lock/features y libsodium C verificadas sin fetch-latest; runner lanza procesos reales con directorios temporales y conserva exit/status, build y canarios. Inventario inicial de componentes/licencias no afirma auditoría final. | §5–6; G1§8; G8§2 |
| **02 — Crear/abrir bóveda cifrada local** | Sol / 01 | CLI humana crea bóveda real sin red/cuenta y vuelve a abrir tras restart; suite G2 de bytes/contexto/propósito, KDF, AAD, envoltorios y parser adversario pasa; contraseña errónea/archivo alterado/version incompatible no mutan bóveda válida. SQLite/WAL solo reciben objetos precifrados y ninguna raíz se serializa en claro. | G2§§7–9; G6§2; V01,V07,V21; H1,43 |
| **03 — Custodia Linux nativa, peer bilateral y fail-closed** | Sol / 02 | Servicio/perfiles de laboratorio separan custodio/humano/agente; peer impostor y lectura/sustitución de recursos protegidos son denegados; claves/bootstrap sobreviven a reinicio de proceso sin TUI y fallos detectables de ACL/identidad/clave devuelven CUSTODY_UNAVAILABLE. Reboot real completo queda además en 30. | G1; G4§§4,7; G7; V05,V08,V13; H59 |
| **04 — Transacción humana firmada y primer CRUD** | Sol / 03 | Crear/leer/editar/eliminar una contraseña por canal humano real usa prepare/commit/receipt y SK_H; challenge vencido/body cambiado/rol falso/replay son rechazados; pérdida de respuesta/commit interrumpido recupera recibo o no-op sin escritura parcial. No aceptar `role=human` por request. | G4§9; G2§9; G6§2; V02,V05,V22; H4,63 |
| **05 — Todos los tipos y organización humana** | Sol / 04 | Roundtrip exacto de password/TOTP/passkey/SSH/token/nota/archivo, campos desconocidos preservables y adjuntos Unicode; buscar/etiquetar/favoritos/generador funcionan vía caso de uso humano con configuración y fallo RNG; índices, staging y archivos no filtran canarios y límites/tamaños se rechazan sin truncar. No passkey virtual como autenticación real. | G6§§2–3; G2; G7; V02,V07; H4–6 |
| **06 — Auditoría cifrada y purga explícita** | Sol / 04 | Eventos de actor/credencial/operación/resultado se escriben atómicamente con las mutaciones y sin KH durante autonomía; errores/crashes no guardan payloads secretos; purga humana con alcance confirmado deja evidencia visible de discontinuidad y no borra autoridad antirreplay. | G7; G2§9; V23; H31,58 |
| **07 — Registro, revocación y conjunto común** | Sol / 05,06 | Alta humana, bootstrap/identidad RPK, generations y revocación individual persisten; dos agentes ven exactamente el mismo conjunto habilitado y metadata mínima, importados/no autenticables excluidos; bloqueo humano no suspende delegación, suspensión global sí persiste y cada uso verifica autoridad. Implementar eventos locales del contrato G5, no autoridad provisional basada en timestamps. | G4§§7,9; G5§9; G2; V03–V05,V12; H16–18,28–30 |
| **08 — Intentos persistentes e idempotencia pública** | Sol / 07 | start/get/cancel con revisión fijada y ownership producen estados G4, TTL/errores estables; desafío pausa solo un intento y solo evidencia confiable reanuda, con cancel/revoke/expiry impidiendo uso; crash/pérdida de respuesta mantiene intento/recibo, un único ejecutor y estado INDETERMINATE donde no puede conciliar, jamás login ciego repetido. Proveedor controlado externo para esta suite. | G4; §8; V10–V12,V22; H19,22–27,51–53 |
| **09 — CLI delegada y MCP stdio equivalentes** | Luna / 08 | Las cinco operaciones CLI/MCP usan el mismo motor por TLS/RPK y pasan comparación de schemas/estados/errores; frame privado 1MiB, límites, versión, JSON malicioso y diagnóstico separado se comprueban; ningún comando humano/reveal/export/generic-sign es invocable por identidad agente. Capabilities solo incluye evidencia disponible, no catálogo entero. | G4§7; §7.4; V05,V25; H18–19,22,41,63 |
| **10 — Password/TOTP Chromium privado + Keycloak OIDC** | Sol / 08 | Perfil P1 real de laboratorio usa Chromium fijado, Keycloak26.7.3 y code+PKCE; configuración de issuer/origen/frame/form-action/cuenta seleccionada/redirect fijado adversaria falla antes de introducir el secreto; callback/state y claims de respuesta (firma, issuer, audience/azp, nonce y subject) se validan al recibirlos, antes de declarar éxito o entregar tokens; login y TOTP reales entregan solo tokens nuevos permitidos y agente no accede a pipe/perfil/DOM/canarios. Registrar plataforma probada; seis targets se completan en 33. | G3 cierre/perfiles; G8§4; V06–V11,V27; P1; H20–25 |
| **11 — Token exchange Keycloak acotado** | Sol / 08 | P2 real entrega B distinto de A con subject/audience verificados; reflect/redirect/auxiliares/audience no autorizada son rechazados sin fuga; revocación antes de POST impide nuevo uso, sin pretender anular token emitido. No exchange genérico. | G3§4; V06–V07,V11,V27; P2; H20,22 |
| **12 — SSH y cuentas de sistema con conexión confirmada** | Sol / 08 | Cliente confiable russh propietario del transporte obtiene AuthResult Success con key y password y entrega conexión ligada al consumidor; impostor, host/destino/firma mal ligados y revocación previa fallan; consumidor usa canal posterior sin que motor intermedie/gestione sesión y sin privata/password en sus recursos. Linux/OpenSSH real inicialmente; matriz macOS/Windows en 33. | G3 B1/B4; V06–V08,V27; P3; H20,49 |
| **13 — Proveedor passkey custodial y puente MV3** | Sol / 05,08 | Alta humana genera clave propia y persiste exactamente datos G6; MV3/Native Messaging transportan peticiones acotadas, sin clave JS ni admin UI, y rechazan origen/documento/extension/host falsos; puente y confirmación mínima real TUI implementan UP/UV enlazado al intento y no firman antes de presencia/verificación ni tras revoke. Prueba aquí no sustituye login P4. | G3 B2; G8§4; V05,V08–V11; H48 |
| **14 — Passkey propia hasta login Keycloak** | Sol / 10,13 | P4 crea passkey propia y la misma clave completa assertion y OIDC verificable en proveedor real; exigencia UP/UV pausa/reanuda solo intento y no puede afirmarla el agente; challenge expirado/restart/revoke cuenta/origen incorrecto nunca producen éxito ni uso de sustituto virtual/llave OS. | G3 B2; V06,V09–V11,V27; P4; H21,24–25,48 |
| **15 — Petición GitHub bearer opaco tipada** | Sol / 08 | `github-rest-bearer/1` acepta exclusivamente `github-assigned-issues/1` del contrato y produce lista/respuesta permitida sin token/headers; ataques URL/header injection/redirect/reflexión/errores/cuota/SSO fallan con resultados públicos seguros; canarios no aparecen en canales agente y no nace proxy arbitrario ni política de negocio. Dobles adversarios aquí; proveedor autorizado real en 33. | G3 B3; V06–V07,V27; P5; H20,50 |
| **16 — Reductor firmado de contenido y autoridad** | Sol / 07 | G5 con DAG firmado, generations/cortes, desempate exacto y antirreplay pasa permutaciones 2/3 dispositivos, forks, reloj adelantado y revocación cruzada; delete frente edit deja ganador en papelera y solo restore explícito activa; checkpoints/purga conservan headers y no reviven autoridad/elementos ante omisión/replay. Sin timestamp LWW para revocaciones. | G5§9; ADR0002; V15–V18; H35–37,54–55 |
| **17 — Sync autohospedado y emparejamiento E2EE** | Sol / 16 | Dos/tres custodios reales y servidor opaco emparejan/retiran mediante autoridad humana y convergen; offline mantiene uso con última autoridad y retiro conocido bloquea siguiente uso, reconexión idempotente sin compartir DB/WAL; ciphertext/tráfico/servidor no contienen claves/secretos y alteración/falta de objetos jamás activa revisión parcial. | G5§9; G4§9; V14–V18; H32–37 |
| **18 — Historial, papelera y purga humana** | Sol / 05,16 | Interfaz humana lista versiones perdedoras y restaura como nueva revisión; delete/restore/purge y carreras con sync cumplen ADR0002 sin caducidad automática; adjuntos/revisiones afectadas se purgan con alcance y límites visibles, sin resurrección por replay ni eliminación de autoridad necesaria. | G5; G6; ADR0002; V02,V15–V17; H8–11,54–55 |
| **19 — CSV Chrome/Apple y mapeable, staging y reportes** | Sol / 05,07 | Fixtures sintéticos de los tres orígenes conservan campos/tipos exportados, Unicode y desconocidos o los reportan individualmente; preview/mapping/duplicados/confirmación escribe transacción humana paginada de eventos y objetos, sin auto-enable; truncado/límites/columnas y crash rechazan sin parcialidad, sin leer bases privadas ni borrar fuente. Motor/import contract completo antes de encargar UI mecánica. | G6§§3–4; G4§9; V04,V19,V22; H12–13,46–47 |
| **20 — Importador 1PUX3 y adjuntos hostiles** | Sol / 19 | Fixtures 1PUX3 incorporan todos los campos/tipos acordados usando staging común; ZIP traversal/bomb/enlaces/duplicados/truncado y adjuntos inválidos son rechazados con límites exactos; reporte conserva pérdida/no importable explícita y ningún caso habilita agente ni escribe fuera de staging seguro. | G6§§3–4; V19,V22; H12–13,46–47 |
| **21 — Backup PMB1/PMF1 y exportación humana** | Sol / 18,06 | Export/restore nativo reproduce inventario completo de tipos/campos/historial/adjuntos/settings/auditoría y autoridad histórica, sin privadas nativas/grants activos/intentos; plaintext requiere confirmación humana y alcance/permisos seguros, agente directo es denegado; streams corruptos/límites/crash fallan antes del commit y sin sobrescribir datos válidos. | G6§§5–6; G2; G7; V02,V20–V22; H2,14–15,39 |
| **22 — Recuperación, rotación de vías y compromiso** | Sol / 21,17 | Clave externa+backup recuperan en entorno limpio sin keyring original y crean linaje/identidades nuevos; restore a bóveda existente conserva autoridad actual/revocaciones, clave errónea o contenido alterado no mutan; cambio de master/recovery es verificable sin perder acceso y comunica validez/límites de copias viejas, flujo de compromiso desde entorno sano no promete borrar copias expuestas. | G2; G6§6; G7; V17,V21; H38–39,56–57,64 |
| **23 — TUI completa de contenido y exposición humana** | Luna / 05,18 | Todos los tipos, búsqueda/organización/generador/historia/papelera/purga operan vía motor real por teclado; unlock/lock, idle/reveal expiry, copiar explícito con API/helper fijado y carrera de clipboard cumplen G7 sin OSC52 oculto; resize/80×24/Unicode/control sequences se prueban en PTY y terminal nativo Linux, sin pérdida de datos ni secretos por seleccionar fila. | G1 terminal; G7; V02,V07,V20,V24; H3–11,43–45 |
| **24 — TUI de acceso delegado y pendientes** | Luna / 08,13,23 | Alta/revoke/conjunto común/suspensión completos vía motor humano real; pendientes listan contexto seguro y cancelan, consumen confirmación UP/UV del proveedor existente, no fabrican evidencia; bloquear TUI conserva autonomía y suspensión/espera/expiración/revoke se muestran con estado correcto. | G4; G3; G7; V03–V05,V10–V12,V24; H16–17,23–30,48,53 |
| **25 — TUI de migración, recuperación, sync y auditoría** | Luna / 17,19,20,21,22,23 | Flujos enteros import preview/mapping/duplicados/errores/confirmación, export/backup/restore/rotación son operables por teclado; emparejar/retirar/offline/sync errors y auditoría/purga funcionan sobre servicios reales; advertencias plaintext/recovery/clipboard/offline y acciones destructivas muestran alcance sin secretos por defecto. No formularios sin operación ni CLI-only como reemplazo de TUI. | §7.2/§11; G4§9; G6/G7; V14,V19–V24; H2,12–15,31–39,56–58,64 |
| **26 — Custodia y canal humano macOS** | Sol / 03,07,08 | Port nativo `_passwordmanager`/LaunchDaemon, peer bilateral y claves/ACL G1 pasa proceso real; TUI CLI-first no hereda autoridad por mismo usuario, acceso indebido y pérdida de condiciones fallan cerrados; clipboard/terminal y persistencia de suspensión/identidad están conectados a APIs nativas, no stubs Unix genéricos. Evidencia ambos CPU/reboot en 31. | G1/G2/G4/G7; V05,V08,V12–V13,V24; H30,40,59 |
| **27 — Custodia y canal humano Windows** | Sol / 03,07,08 | Port nativo servicio virtual/DACL/DPAPI y peer bilateral G1 pasa proceso real; sustitución/impersonación/dump/lectura y fallos de custodia se rechazan; ConPTY/clipboard y persistencia están conectados a APIs nativas sin conceder admin al agente. Evidencia ambos CPU/reboot en 32. | G1/G2/G4/G7; V05,V08,V12–V13,V24; H30,40,59 |
| **28 — Fallos operativos, canarios y crash safety integral** | Sol / 09,10,11,12,14,15,17,18,19,20,21,22,25 | Fault injection en boundaries reales de fsync/WAL/staging/commit/outbox/audit y disco lleno conserva atomicidad/autoridad y nunca doble login ciego; canarios activos/históricos cubren stdout/stderr/logs/errores/argv/env/temp/dumps y recursos de agente; memoria/dump/clock/rate límites G7 y pérdida de custodia producen fallo documentado, sin tests verdes por redacción posterior. Ports nativos se vuelven a ejecutar en 30–32. | G7; G2/G4/G5/G6; V05,V07–V08,V20–V23; H43,45,52–53,58–59,64 |
| **29 — Paquetes, TUF, mantenimiento y fuente correspondiente** | Sol / 22,25,26,27 | Payloads/versiones/Chromium/MV3/helpers y grafo auditables producen paquetes previstos y SBOM/fuente/avisos AGPL sin autor inventado; repositorio TUF sintético y mantenimiento local rechazan threshold/firma/path/rollback/security_floor/reloj adversarios sin canal admin delegado; upgrade/quiesce/migración/journal/rollback/uninstall/reinstall preservan datos/identidad/revocaciones, purga separada y explícita. Certificados reales no fingidos. | G8 completo; V13,V21,V26; H42,60–62 |
| **30 — Evidencia nativa Linux en dos arquitecturas** | Sol / 24,28,29 | En x86_64 Y aarch64 nativos desechables: install→reboot FDE→autonomía sin KH/TUI→upgrade/fallo/rollback→uninstall/reinstall pasa; ataques de memoria/archivos/peer/binario y aislamiento TUI/clipboard pasan; recorrido íntegro TUI Ghostty teclado/resize y todos V aplicables conservan evidencia por target. Un CPU ausente mantiene ticket sin resolver. | G1/G7/G8; V01–V27 aplicables; H30,40,59–62 |
| **31 — Evidencia nativa macOS en dos arquitecturas** | Sol / 24,28,29 | Mismos ciclos y adversarios en Intel Y Apple silicon nativos; Terminal.app/clipboard/canal humano CLI-first completos; firma/notarización de release real se separa de fixture sintético y evidencia faltante queda explícita, sin afirmar instalación firmada de producción. Para cierre de producto, evidencia real requerida por G8 debe existir. | G1/G7/G8; V01–V27 aplicables; H30,40,59–62 |
| **32 — Evidencia nativa Windows en dos arquitecturas** | Sol / 24,28,29 | Mismos ciclos y adversarios en x64 Y ARM64 nativos; Windows Terminal/ConPTY/clipboard/servicio y DACL probados; Authenticode/MSI real separado de claves sintéticas, ninguna prueba WSL/emulada cuenta como nativa. Cierre final requiere firmas reales G8, no solo test. | G1/G7/G8; V01–V27 aplicables; H30,40,59–62 |
| **33 — Matriz real P1–P5 y compatibilidad seis targets** | Sol / 10,11,12,14,15,30,31,32 | P1/P4 ejecutados con Chromium propio y passkey custodial propia en los seis targets, incluyendo Windows ARM64; P2/P3/P5 contra contrapartes reales autorizadas y matriz custodio/destino relevante, con casos adversarios y login/resultados útiles; capabilities publica únicamente fila aprobada de build/entorno y V27 comprueba ausencia de administración de sesiones/acciones. Un doble o assertion/firma aislada no satisface login. | G3 P1–P5; G8; V06–V11,V27; H20–22,48–50 |
| **34 — Gate independiente de criptografía y aislamiento** | Astra coordina; usuario realiza validación humana final / 28,30,31,32,33 | El usuario, como revisor humano separado de los agentes implementadores, recibe composición real, código, threat model y evidencias; informe examina criptografía/FFI/claves/parser, aislamiento y actualización y hallazgos críticos se corrigen con regresión y revalidación; informe/version/alcance permanece accesible sin secretos. Falta de informe y aceptación humana = abierto, no sustituir con aprobación de Astra/Sol ni presentar como auditoría externa certificada. | §12.3; G2/G7/G8; V07–V08,V18,V21 |
| **35 — Revisión unificada y cierre verificable de la especificación** | Astra review; merger dedicado ejecuta / 09,24,25,29,30,31,32,33,34 | Code-review de estándares Y contrato en rama unificada no deja hallazgos accionables sin corregir; suite pública completa tiene evidencia para H1–64/V01–V27/P1–P5 y seis targets, LICENSE/fuente/SBOM/certificados/release roles reales cotejados; §15 se actualiza con resultado exacto sin afirmar publicación remota o modificar R01–R21. Si falta evidencia externa, informe de entrega parcial y ticket abierto: nunca resolver spec por presupuesto/tiempo. | spec completa; code-review; G8; V26; H42,60–64 |

## 4. Cobertura explícita de historias (responsable primario, complementos entre paréntesis)

| Historias | Tickets |
|---|---|
| 1 | 02 |
| 2 | 21 (22,25) |
| 3 | 23 |
| 4 | 05 (04,23) |
| 5–6 | 05 (23) |
| 7 | 23 |
| 8–11 | 18 (23) |
| 12–13 | 19,20 (25) |
| 14–15 | 21 (25) |
| 16–18 | 07 (09,24) |
| 19 | 08 (09) |
| 20 | 10,11,12,15 (33) |
| 21 | 10,14 (33) |
| 22 | 08,09 (33) |
| 23–27 | 08 (10,14,24) |
| 28–30 | 07 (24,26,27,30–32) |
| 31 | 06 (25) |
| 32–35 | 17 (25) |
| 36–37 | 16,18 (17) |
| 38–39 | 22 (21,25) |
| 40 | 23–25 (26–27,30–32) |
| 41 | 09 |
| 42 | 29 (35) |
| 43 | 02 (23,28) |
| 44–45 | 23 (28,30–32) |
| 46–47 | 19,20 (25) |
| 48 | 13,14 (24,33) |
| 49 | 12 (33) |
| 50 | 15 (33) |
| 51–53 | 08 (24,28) |
| 54–55 | 16,18 |
| 56–57 | 22 (25) |
| 58 | 06 (25) |
| 59 | 03,26,27 (28,30–32) |
| 60–62 | 29 (30–32,35) |
| 63 | 04,09 |
| 64 | 22 (25,28) |

## 5. Cobertura de aceptación observable

- V01: 02,03,30–32. V02: 04,05,18,21,23. V03–04: 07,09,19,24. V05: 03,04,07–09,13,26–28,30–32.
- V06: 10–12,14–15,33. V07: 02,05,06,10–15,23,28,30–34. V08: 03,10,12–14,26–28,30–34. V09: 10,13,14,33.
- V10–11: 08,10,13,14,24,28,33. V12: 07,08,24,26,27,30–32. V13: 03,26,27,29–32.
- V14: 17,25. V15: 16–18. V16: 16,18. V17: 16–18,22. V18: 16,17,34.
- V19: 19,20,25. V20: 21,23,25,28. V21: 02,21,22,28–32,34. V22: 04,08,19–21,28.
- V23: 06,25,28,30–32. V24: 23–27,30–32. V25: 09,28. V26: 29,35. V27: 10–12,14,15,33.
- P1: 10 → 33. P2: 11 → 33. P3: 12 → 33. P4: 13 → 14 → 33. P5: 15 → 33.
- R21 se preserva por exclusión explícita: no ticket de plugin Omarchy, no dependencia del shell/Electron. R14 tiene gate V27, no tickets de logout, control de acciones ni sesiones posteriores.

## 6. Recomendación de despacho

Frente inicial: **01**. Tras bootstrap, encadenar **02→03→04** como primer recorrido humano funcional; luego **05 y 06** pueden ejecutarse aislados. **07→08** habilita temprano experimentos de realización **10/11/12/13/15**, con 09 mecánico paralelo. Priorizar P1 y P4 Windows ARM64 antes de invertir en cosmetización completa; no esconder una refutación en un mock.

Los bloques sync **16→17/18**, importación **19→20**, ports **26/27** y clientes **23–25** avanzan según frontera sin duplicar decisiones. Entrega parcial de un ticket NO desbloquea otro; si se requiere una interfaz antes, dividir formalmente el ticket en tracker, no pasarse archivos no integrados entre agentes.

Merger: comprobar commit esperado/deps resueltas, merge, suite completa, registrar evidencia y liberar frontera. Las pruebas Linux rápidas en cada merge no reemplazan los gates 30–34. No borrar worktrees con trabajo pendiente. Astra reserva la revisión formal para el gate unificado final 35 por instrucción posterior del usuario; no declara revisión independiente por revisarse a sí mismo.
