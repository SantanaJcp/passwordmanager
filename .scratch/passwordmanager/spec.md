# Password manager agent-first — especificación técnica v1.0

Fecha: 2026-09-12.
Labels: ready-for-agent

Publicación: especificación canónica en seguimiento local; síntesis `to-spec` de contratos cerrados, no ticket de ejecución.

## 0. Estado, autoridad y límites de este documento

- **Contrato funcional: confirmado por el usuario.** Esta especificación formaliza la entrevista grill-me y su confirmación final.
- **Implementación: no autorizada en esta etapa.** No existe código de producto ni pruebas runtime del motor.
- **Diseño técnico: G1–G8 cerrados documentalmente para el alcance y perfiles declarados.** Selecciones de ingeniería y contratos concretos enlazados en sección 15; no algoritmos atribuidos al usuario ni seguridad/compatibilidad certificadas. Pruebas nativas, revisión independiente y evidencia de publicación siguen pendientes de ejecución.
- **Preparación:** contratos completos para descomponer y planificar el trabajo, con criterios de aceptación y validación crítica explícitos. Crear tickets, prototipos o código requiere autorización separada. La etiqueta `ready-for-agent` se aplica ahora por la síntesis `to-spec`: significa especificación preparada para descomposición, no autorización de ejecución ni seguridad certificada. La sección 15 distingue diseño cerrado y ejecución pendiente.
- No es un MVP ni una lista de funciones para posponer. La única integración expresamente diferida es el plugin Omarchy, que pertenecerá a otro repositorio.
- Ante discrepancias con recomendaciones históricas de `docs/research`, prevalece el contrato confirmado resumido aquí. Las comparaciones históricas siguen siendo evidencia, no especificaciones alternativas. Las secciones de contratos seleccionados identificadas en §5.3 se incorporan como anexos normativos de esta especificación: no elegir alternativas históricas ni duplicar sus schemas en otro documento.

## 1. Problema y solución

### Problema

Los humanos y agentes de desarrollo necesitan autenticarse en plataformas web, sistemas y servidores. Entregar contraseñas al contexto del modelo o a procesos bajo su control expone secretos. Un gestor exclusivo para humanos interrumpe el trabajo autónomo; un servidor de secretos que permita extraerlos no satisface la garantía acordada.

### Solución

Una bóveda local cifrada con motor independiente, CLI, MCP y TUI completa. El humano administra sus datos y autoriza agentes. Los agentes registrados comparten un conjunto explícito de credenciales habilitadas y solicitan su utilización mediante integraciones verificadas, sin obtener el secreto almacenado.

La responsabilidad termina en el uso de la credencial para autenticar. No incluye decidir qué puede hacer la cuenta después, gestionar sesiones externas ni proteger cookies/tokens emitidos posteriormente por el servicio.

## 2. Contrato de producto aprobado

| ID | Requisito |
|---|---|
| R01 | Motor independiente, CLI, MCP y TUI completa, sin Electron ni dependencia del shell Omarchy. |
| R02 | Linux, macOS y Windows como objetivos iniciales de soporte; no presentar compilación cruzada como prueba nativa. |
| R03 | Contraseñas, TOTP, passkeys, claves SSH, tokens/API keys, notas y archivos seguros. |
| R04 | Gestión humana: crear, consultar, revelar, copiar, editar, eliminar, importar y exportar; confirmar exportación sin cifrar. |
| R05 | Búsqueda, etiquetas, favoritos, generador, historial, papelera, backups cifrados y registro de accesos sin secretos. |
| R06 | Registro humano inicial y revocación individual de agentes; no aceptar cualquier proceso por conocer el endpoint. |
| R07 | Un conjunto común de credenciales habilitadas para todos los agentes autorizados; sin reglas por proyecto ni listas distintas por agente. |
| R08 | Agentes consultan metadatos autorizados y solicitan una credencial por identificador; no elección adivinada de cuenta. |
| R09 | No entregar secretos de la bóveda a agentes ni permitir que sus herramientas los extraigan dentro del modelo de aislamiento soportado. |
| R10 | Agentes aislados del sistema custodio, sin facultades administrativas sobre él. |
| R11 | Autorizaciones persistentes y revocables tras reinicios, sin entregar contraseña maestra al agente. |
| R12 | Bloqueo de TUI independiente de suspensión global de nuevas autenticaciones de agentes. |
| R13 | Exigencia humana: pausa inmediata solo de esa autenticación, sin intentar otra vía automáticamente; reanudación al verificar resolución. |
| R14 | Sin controles sobre acciones, permisos o sesiones externas posteriores a la autenticación. |
| R15 | Uso local sin cuenta obligatoria; sincronización opcional E2EE mediante servidor autohospedable; sin SaaS oficial. |
| R16 | Operación offline con última autorización conocida; revocaciones remotas al recibirlas mediante sincronización. |
| R17 | Conflictos de contenido: last-write-wins por timestamp, con historial, sin resolución manual ni pausa por conflicto. |
| R18 | Recuperación mediante clave externa y copia cifrada; sin puerta trasera del operador ni recuperación garantizada si se pierden todas las vías. |
| R19 | Importar 1Password .1pux, Chrome, Contraseñas de Apple y CSV mapeable; exportación/restauración nativa cifrada de todos los tipos internos. |
| R20 | AGPL-3.0 como base, permitiendo cobro bajo las obligaciones aplicables; no prohibición no comercial ni relicenciamiento automático de clientes independientes. |
| R21 | Plugin Omarchy después de definir este producto, en otro repositorio. |

## 3. Vocabulario y actores

El vocabulario canónico se mantiene en [CONTEXT.md](../../CONTEXT.md), conforme a las [convenciones de dominio](../../docs/agents/domain.md). Este resumen debe mantenerse alineado sin alterar el contrato funcional.

- **Humano propietario:** persona que administra la bóveda y habilita acceso delegado. El contrato no define organizaciones, equipos humanos ni administración empresarial.
- **Agente registrado:** cliente con identidad verificable y autorización vigente para el conjunto común. Su nombre visible no es prueba de identidad.
- **Motor custodio:** componente con acceso al material criptográfico y autoridad para aplicar permisos de la bóveda.
- **Cliente:** TUI, CLI o adaptador MCP. Invocar una interfaz no concede por sí mismo privilegios humanos.
- **Elemento:** dato de la bóveda. Puede ser una credencial utilizable para autenticar o contenido humano, como una nota o archivo.
- **Credencial habilitada:** elemento apto para autenticación que el humano incorporó al conjunto común.
- **Integración de autenticación:** adaptador confiable que utiliza una credencial para un destino y método compatibles. No es un intérprete de acciones arbitrarias con acceso a secretos.
- **Intento de autenticación:** operación individual identificable, con estado, vencimiento y resultado.
- **Sesión externa:** acceso establecido con el proveedor; sus cookies/tokens posteriores quedan fuera de la custodia acordada, salvo que el humano los guarde expresamente como elementos de la bóveda.
- **Dispositivo:** instalación emparejada del propietario. Su identidad es diferente de la identidad de un agente y no se hereda al copiar archivos.
- **Servidor de sincronización:** transporte/almacenamiento de datos cifrados entre dispositivos autorizados, no custodio con capacidad de descifrar.

## 4. Historias de usuario

Todas las historias forman parte del alcance; no son tickets ni autorizan implementación.

1. Como humano, quiero crear una bóveda local sin cuenta remota, para usar el producto sin servicio externo.
2. Como humano, quiero preparar una clave de recuperación y una copia cifrada, para recuperar mis datos si pierdo el equipo o el acceso habitual.
3. Como humano, quiero abrir y bloquear mi TUI, para controlar cuándo mis datos están visibles.
4. Como humano, quiero crear y editar todos los tipos de elementos acordados, para centralizar mis credenciales y datos seguros.
5. Como humano, quiero generar contraseñas configurables, para crear secretos sin inventarlos manualmente.
6. Como humano, quiero buscar y organizar con etiquetas y favoritos, para encontrar elementos rápidamente.
7. Como humano, quiero revelar y copiar un secreto de forma explícita, para usarlo fuera de una integración automática.
8. Como humano, quiero consultar el historial de un elemento, para recuperar información anterior.
9. Como humano, quiero restaurar una versión anterior como una nueva modificación, para corregir un error sin borrar la trazabilidad.
10. Como humano, quiero enviar elementos a la papelera y restaurarlos, para recuperarme de eliminaciones accidentales.
11. Como humano, quiero eliminar definitivamente elementos cuando lo decida, para controlar la retención de mis datos dentro de los límites de copias y dispositivos desconectados.
12. Como humano, quiero importar desde 1Password, Chrome, Apple y CSV, para migrar sin volver a introducir todas mis contraseñas.
13. Como humano, quiero revisar errores, duplicados y datos no importables, para no perder información silenciosamente.
14. Como humano, quiero exportar y restaurar todos los tipos de elementos en formato nativo cifrado, para conservar independencia del producto.
15. Como humano, quiero confirmar una exportación sin cifrar, para reconocer que el archivo contendrá secretos legibles.
16. Como humano, quiero registrar y revocar cada agente, para decidir qué herramientas acceden a mi bóveda.
17. Como humano, quiero habilitar un conjunto común de credenciales, para administrarlo una sola vez para todos mis agentes autorizados.
18. Como agente autorizado, quiero descubrir únicamente los metadatos habilitados, para identificar la credencial que necesito sin leerla.
19. Como agente autorizado, quiero solicitar una credencial concreta por identificador, para no autenticarme con una cuenta elegida por suposición.
20. Como agente autorizado, quiero utilizar una credencial mediante una integración compatible sin recibir el secreto, para continuar el desarrollo sin copiar contraseñas.
21. Como agente autorizado, quiero utilizar los métodos de autenticación soportados, incluidos TOTP y passkeys, para completar los accesos que permitan ejecución autónoma.
22. Como agente autorizado, quiero conocer que una integración no está soportada, para no degradar a una entrega insegura de secretos.
23. Como agente autorizado, quiero que se pause únicamente un intento que necesita intervención humana, para seguir con tareas independientes.
24. Como humano, quiero ver las autenticaciones pendientes en la TUI, para completar las verificaciones exigidas por el proveedor.
25. Como agente autorizado, quiero que ese intento continúe cuando se verifique la resolución humana, para no necesitar una orden adicional de reanudación.
26. Como humano, quiero cancelar un intento pendiente, para evitar que continúe cuando ya no lo necesito.
27. Como agente autorizado, quiero recibir un estado de vencimiento o fallo claro, para no confundir una espera con un acceso completado.
28. Como humano, quiero bloquear mi TUI sin desautorizar agentes, para dejar trabajo autónomo ejecutándose.
29. Como humano, quiero suspender globalmente nuevas autenticaciones de agentes, para detener el uso delegado sin gestionar sesiones externas.
30. Como agente autorizado, quiero conservar la autorización tras reinicios del entorno soportado, para continuar sin pedir la contraseña maestra al humano.
31. Como humano, quiero revisar quién intentó usar qué credencial y con qué resultado, para auditar el acceso sin registrar secretos.
32. Como humano, quiero conectar un servidor de sincronización autohospedado opcional, para usar la misma bóveda en varios dispositivos.
33. Como humano, quiero emparejar y retirar dispositivos explícitamente, para controlar dónde reside mi información.
34. Como humano y agente autorizado, quiero trabajar offline con el estado conocido, para no depender de una conexión continua.
35. Como humano, quiero que las revocaciones remotas se apliquen al sincronizar, para entender cuándo un equipo desconectado recibe mis cambios.
36. Como humano, quiero resolver automáticamente cambios concurrentes por timestamp, para evitar resolución manual de conflictos.
37. Como humano, quiero conservar las versiones desplazadas por esa resolución, para recuperar cambios aunque el orden temporal no refleje mi intención.
38. Como humano, quiero recuperar mi bóveda con la clave externa y una copia cifrada, para restaurar mis datos sin intervención del operador del servidor.
39. Como humano, quiero un error inequívoco ante una copia corrupta o una clave incorrecta, para no sobrescribir una bóveda válida.
40. Como humano, quiero usar la TUI completa en Linux, macOS y Windows, para no depender de Omarchy ni de una aplicación Electron.
41. Como integrador, quiero CLI y MCP con resultados consistentes y versionados, para conectar herramientas sin depender de pantallas de la TUI.
42. Como integrador, quiero respetar la licencia AGPL aplicable incluso al ofrecer un producto comercial, para distribuir legalmente código cubierto y modificaciones.

43. Como humano, quiero que una contraseña maestra incorrecta no modifique mis datos, para poder volver a intentar el acceso sin perder la bóveda.
44. Como humano, quiero que los secretos revelados y el desbloqueo caduquen por inactividad, para reducir su exposición cuando dejo la terminal.
45. Como humano, quiero conocer los límites de limpieza del portapapeles, para no confundir copiar un secreto con poder borrar todas sus copias.
46. Como humano, quiero que una importación conserve o identifique los campos no utilizables, para decidir qué incorporar sin pérdidas silenciosas.
47. Como humano, quiero que los elementos importados no queden habilitados automáticamente para agentes, para revisar primero su uso delegado.
48. Como humano, quiero crear una passkey y confirmar las verificaciones que exija su uso, para autenticar con una credencial propia de la bóveda.
49. Como agente autorizado, quiero recibir un acceso SSH utilizable solo tras un login confirmado, para no confundir una firma emitida con acceso al servidor.
50. Como agente autorizado, quiero obtener la respuesta permitida de una petición autenticada con un token guardado, para usar una integración compatible sin recibir ese token.
51. Como agente autorizado, quiero cancelar y consultar mis propios intentos, para controlar esperas sin acceder a resultados de otros agentes.
52. Como agente autorizado, quiero consultar el mismo intento después de perder la respuesta, para evitar repetir una autenticación de efecto desconocido.
53. Como humano, quiero que revocar mientras una autenticación espera impida continuarla, para retirar mi autorización antes del próximo uso.
54. Como humano, quiero que una edición concurrente no saque de la papelera un elemento eliminado, para que solo una restauración explícita vuelva a activarlo.
55. Como humano, quiero conservar historial y papelera hasta decidir una purga, para no perder información automáticamente por el paso del tiempo.
56. Como humano, quiero que recuperar un backup no reactive agentes antiguos, para recuperar datos sin conceder autoridad obsoleta.
57. Como humano, quiero renovar mi contraseña maestra y mi vía de recuperación, para mantener acceso verificable sin perder mis copias históricas.
58. Como humano, quiero purgar auditoría con un alcance confirmado y visible, para controlar su retención sin aparentar que el registro sigue completo.
59. Como humano, quiero conocer cuándo el entorno no permite custodiar secretos de forma segura, para corregirlo sin recibir una alternativa insegura.
60. Como humano, quiero instalar y actualizar paquetes verificables para mi plataforma, para mantener el producto sin exponer claves ni confiar en descargas alteradas.
61. Como humano, quiero que una actualización fallida preserve datos y revocaciones, para recuperar la instalación sin reactivar accesos retirados.
62. Como humano, quiero desinstalar conservando mis datos salvo purga explícita, para poder reinstalar o recuperar sin borrado inesperado.
63. Como integrador, quiero errores claros ante versiones y entradas incompatibles, para corregir mi cliente sin interpretar respuestas ambiguas.
64. Como humano, quiero contener un equipo o una clave comprometidos desde un entorno sano, para reconstruir mi custodia sin asumir que desaparecieron las copias expuestas.

Las historias 43–64 desglosan fallos y recorridos ya contenidos en R01–R20 y contratos G1–G8; no amplían familias, introducen permisos de negocio ni autorizan ejecución.

## 5. Arquitectura seleccionada: límites profundos, clientes ligeros

### 5.1 Componentes

| Componente | Responsabilidad | Lo que no debe hacer |
|---|---|---|
| Motor | Validar identidad, operaciones humanas/delegadas, disponibilidad de credenciales y transiciones de intentos. | Confiar en un rol declarado por el llamante o administrar acciones posteriores en servicios. |
| Almacén cifrado | Elementos, revisiones, índices protegidos, adjuntos, transacciones y recuperación. | Crear copias plaintext de la bóveda para simplificar consultas. |
| Custodia de claves/plataforma | Material de desbloqueo humano, delegado y de recuperación; identidad, permisos, IPC y ciclo de vida nativo. | Suponer que mismo usuario + otro proceso constituye aislamiento suficiente. |
| Integraciones de autenticación | Usar secretos exclusivamente para el método/destino autorizado y producir estados/resultados. | Exportar secretos a variables, argumentos, stdout o procesos arbitrarios controlados por el agente. |
| Sincronización | Transferir revisiones cifradas y eventos autorizados, aplicar convergencia y registrar recepción. | Descifrar en el servidor, seleccionar credenciales por proyecto o aplicar permisos externos. |
| TUI | Todas las funciones humanas, incluidas recuperación, importación, configuración y pendientes. | Depender del plugin Omarchy o ser una simple pantalla de un producto incompleto. |
| CLI | Superficie automatizable del contrato, salida estructurada y errores estables. | Convertir una invocación del agente en una sesión administrativa humana. |
| MCP | Adaptación al protocolo de las operaciones delegadas. | Custodiar toda la bóveda dentro del proceso lanzado por el agente, ni emitir secretos en logs. |
| Servidor autohospedable | Endpoints de transporte de sincronización y almacenamiento cifrado. | Ofrecer un bypass de recuperación o asumir facturación/operación SaaS oficial. |

Baseline seleccionado: Rust 1.98.1, Ratatui 0.30.2/Crossterm 0.29.0, rusqlite 0.40.2 con SQLite y datos precifrados, libsodium 1.0.22/binding 1.24.0, minicbor 2.3.0 y rustls 0.23.44. Versiones y perfiles de los anexos G1/G2/G8, no nuevas elecciones de esta síntesis. No hay código, manifiesto de dependencias, módulos implementados ni seams de tests existentes en el repositorio inspeccionado: hay documentación y seguimiento local.

### 5.2 Separaciones de autoridad

1. Las identidades humana, de dispositivo y de agente son distintas.
2. El motor comprueba permisos por operación; el esquema CLI/MCP no es la frontera de seguridad.
3. Las operaciones de revelar/exportar/recuperar/habilitar requieren autoridad humana comprobada.
4. Un agente solo accede a metadatos mínimos del conjunto común y a operaciones de autenticación compatibles.
5. Los endpoints, binarios, configuración, claves y mecanismos de actualización del custodio deben quedar fuera del control administrativo del agente.
6. La autorización compartida de credenciales no convierte las identidades de los agentes en una contraseña compartida.

### 5.3 Anexos normativos y ubicación de cada decisión

Esta especificación incorpora **las secciones seleccionadas**, no las alternativas históricas completas. No copiar variantes de schemas entre documentos: modificar su contrato propietario y reflejar el cambio aquí. Prioridad: R01–R21/ADR aceptados → síntesis de esta especificación → contrato seleccionado identificado abajo → evidencia histórica. Un desacuerdo técnico concreto se señala; no se interpreta como permiso para ignorar R09/R14.

| Área | Contrato propietario incorporado | Decisión que debe respetar la implementación |
|---|---|---|
| Plataforma | [Aislamiento G1](../../docs/design/isolation.md) | Custodio persistente separado de ejecución humana temporal y agente; cuentas/ACL/peer y arranque nativos. |
| Cifrado | [G2 §§7–9](../../docs/design/key-hierarchy.md#7-formato-v1-seleccionado) | Suite única, bytes/AAD/firma, claves por propósito, manifiestos y orden de construcción; no cambiar algoritmos al implementar clientes. |
| Autenticación | [G3 cierre B1–B4](../../docs/research/g3-authentication-integrations.md#resolución-de-b1b4--cierre-documental-de-g3), con perfiles Keycloak de la iteración previa allí referenciada | Proveedores, contexto confiable, origen/destino, resultados y pruebas P1–P5; firma sola no demuestra login. |
| Comunicación | [G4 §§7 y 9](../../docs/design/agent-identity.md#7-wireclimcp-v1) | Framing/roles/RPK, cinco operaciones delegadas, comandos humanos, schemas, plazos y commits idempotentes. |
| Sync | [G5 §9](../../docs/design/synchronization.md#9-contrato-g5-seleccionado--cierre-documental) | DAG, reductor, cortes, retención manual, checkpoint cache, bloques y servicio autohospedado. |
| Datos/migración | [G6 §§2–6](../../docs/research/credential-migration.md#2-modelo-lógico-común-y-límites-seleccionados) | Todos los plaintext, mapeos, duplicados/pérdidas, PMB1, inventario y restauración sin autoridad antigua. |
| Operación | [G7](../../docs/design/security-operations.md) | Fallos que impiden uso, memoria/dumps, auditoría, TUI/clipboard, staging y recuperación de compromiso. |
| Entrega | [G8](../../docs/design/distribution.md) | AGPL-3.0-only, licencias/fuente, paquetes, Chromium/MV3, TUF, mantenimiento y rollback. |

Perfiles de custodia seleccionados: Linux kernel≥6.1/glibc≥2.36/systemd≥252 x86_64/aarch64 con cuenta dedicada; macOS≥13 Intel/Apple silicon con pkg/LaunchDaemon; Windows11 x64/ARM64 con servicio de cuenta virtual. FDE es condición del perfil desatendido frente a robo de disco; el producto no configura/desbloquea el disco por el humano. Estos seis targets requieren validación nativa independiente. El baseline no convierte una compilación cruzada o una prueba en Linux en soporte certificado de los demás.

### 5.4 Límites de procesos y dependencias

- **Dominio/casos de uso del motor:** decide autoridad, estados e invariantes; no depende de widgets TUI, MCP ni particularidades del proveedor. Las fachadas traducen solicitudes a esos mismos casos de uso.
- **Módulo criptográfico:** única frontera de primitivas/FFI y buffers sensibles; presenta operaciones tipadas. Almacenamiento recibe ciphertext y transacciones, no K_H. No repartir criptografía entre CLI/TUI/extensión.
- **Ejecutor humano:** puede abrir K_H/SK_H temporalmente y prepara contenido/sobres y comandos firmados. Bloquearlo no mata la delegación. **Custodio persistente:** utiliza SK_D/control y material habilitado, no raíz humana.
- **Adaptadores confiables:** usan material permitido dentro del dominio custodial; el navegador privado/puente y cliente SSH no son procesos arbitrarios del agente. Cliente SSH es dueño del transporte; motor no ofrece comandos posteriores ni políticas de sesión. Extensión sin UI de administración, criptografía privada en custodio.
- **Persistencia/sync:** un escritor local hace commit de contenido, autoridad, outbox y auditoría coherentes. Servidor guarda bloques opacos, nunca decide permisos ni conoce claves. No sincronizar archivos SQLite/WAL abiertos.
- **Distribución:** instalador/mantenimiento administrativo aparte del canal delegado; actualizador valida artefactos, no pide K_H. No se crea un endpoint general de administración para el agente.

Estos límites son contratos de módulos, no un árbol de crates/archivos ya implementado. No introducir interfaces para mockear cada dependencia interna ni otro motor de políticas dentro de adaptadores.

## 6. Modelo de datos y persistencia seleccionados

Modelo lógico, no DDL ni migración ejecutada. Los tipos binarios, schemas de plaintext/ciphertext y composición exacta están fijados en los anexos G2/G5/G6/G7; las entidades siguientes resumen sus responsabilidades, no constituyen un schema alternativo.

| Entidad | Campos/relaciones lógicos | Invariantes |
|---|---|---|
| Vault | Identificador estable, versión de formato, configuración cifrada, referencias de claves envueltas. | Ninguna cuenta cloud obligatoria; material maestro no sale hacia agentes ni servidor. |
| Item | ID, tipo, título, destinos, etiquetas, favorito, estado activo/papelera, revisión visible. | ID estable; ningún secreto se usa como ID o clave de búsqueda exterior. |
| ItemRevision | ID de revisión, ID elemento, autor/dispositivo, timestamp UTC, contenido cifrado, referencia de integridad. | Inmutable; la versión desplazada se conserva según política de historial. |
| Attachment | ID, manifiesto cifrado, contenido cifrado, integridad y referencias. | Un archivo humano no se convierte en descarga accesible al agente. |
| CommonAvailability | IDs de credenciales habilitadas y eventos de modificación autorizados. | Conjunto único compartido; notas/archivos no se exponen automáticamente por estar en la bóveda. |
| AgentIdentity | ID, nombre visible, mecanismo de identidad verificable, dispositivo, estado registrado/revocado. | Nombre o flag CLI no prueban identidad; revocación de un agente no afecta a los demás. |
| DelegatedAccessState | Disponibilidad global, estado de custodia delegada, eventos de revocación. | No incluye contraseña maestra entregable al agente. |
| DeviceIdentity | ID, evidencia criptográfica de emparejamiento, estado activo/retirado. | Copiar una exportación no matricula automáticamente otro dispositivo. |
| AuthenticationAttempt | ID, agente, item/revisión seleccionada, método/destino, estado, timestamps, vencimiento, resultado seguro. | No contiene secretos plaintext en almacenamiento o logs; cada intento es independiente. |
| AuditEvent | ID, actor, operación, IDs afectados, resultado, timestamp, origen del evento. | Sin cuerpos de requests, contraseñas, semillas TOTP, claves privadas, headers sensibles ni volcados de herramientas. |
| SyncEnvelope | ID opaco, revisión/protocolo, ciphertext, prueba de integridad/autorización necesaria, cursor. | No confiar en metadata no autenticada para sobrescribir contenido. |
| RecoveryEnvelope | Versión y parámetros de recuperación, material envuelto y referencias verificables. | El servidor no puede derivar la clave de recuperación ni sustituir al propietario. |

Los valores de tokens/API keys guardados son secretos protegidos. Las cookies/tokens emitidos por el servicio tras autenticar no se convierten automáticamente en elementos custodiados. Esa distinción no autoriza que una integración etiquete el secreto original como «sesión» para devolverlo.

### 6.1 Formatos y transacciones que deben existir

| Conjunto persistido | Formato/identidad | Escritura y recuperación |
|---|---|---|
| Elementos/revisiones/partes | Schemas G6; manifiesto cifrado G2 vincula IDs, headers y hashes; IDs16 bytes, tiempo int64 microsegundos. | Solo revisiones completas, LWW por tupla exacta, historia preservada; título/notas/secretos no se indexan en claro. |
| Claves y autoridad | Sobres separados de KH/KC/KA/KF/KO, SK_D y SK_SD distintos de TLS; eventos humanos/dispositivo G5. | Verificar contexto/firma antes de activar; no interpretar decrypt exitoso como autorización. K_ATT solo para ejecutor, sin requerir KH durante autonomía. |
| Intentos/resultados | Snapshot G4 cifrado, vínculo agente/generación/revisión/ejecutor; índice de idempotencia y recibos. | Commit de intención antes del uso, resultado24h tras terminal e índice7d; pérdida de respuesta no dispara login nuevo. |
| Sincronización | Eventos, headers antirreplay, outbox/recepción, checkpoints e índices por hash. | Operación local sin red; retiros conocidos antes de nuevo uso; caches compactables sin olvidar retiradas ni purgas. |
| Auditoría | Registros/segmentos G7 bajo KAUD por dispositivo/generación. | Escritura con TUI bloqueada, no sync automático; purga humana deja alcance explícito, no elimina autoridad mínima. |
| Backup/importación | Staging cifrado y manifiestos paginados G6; PMB1 exterior/PMF1 secuencial. | Validación completa antes de commit; nueva recuperación genera linaje o importa datos sin reemplazar autoridad vigente. |

No hay tablas ni datos existentes que migrar en este repositorio. La primera implementación debe materializar estas responsabilidades sobre SQLite y aplicar WAL/FULL y controles G7; no se prescribe DDL especulativo ni se usa el archivo SQLite como contrato portable. Incompatibilidad de formato futuro se rechaza sin mutación destructiva; migración posterior sigue staging/validación/commit G6/G8, no sobrescritura in-place.

## 7. Contratos de interfaces seleccionados

Los nombres siguientes son operaciones lógicas; su mapeo seleccionado a RPC v1, CLI y MCP stdio está en [contrato de comunicación §7](../../docs/design/agent-identity.md). No son herramientas ya publicadas. Los schemas de contexto/resultado específicos están fijados por integración G3.

### 7.1 Superficie delegada común a CLI/MCP

| Operación | Entrada | Salida | Restricciones |
|---|---|---|---|
| DiscoverCredentials | Filtros de metadatos, paginación. | ID, título, tipo autenticable, destino/cuenta no secretos y compatibilidad. | Solo conjunto habilitado; no notas libres, adjuntos ni campos arbitrarios. |
| StartAuthentication | ID credencial, método, destino/contexto compatible, clave de idempotencia. | ID de intento, estado y resultado de integración cuando corresponda. | No elegir otra cuenta ni exigir introducir el secreto como argumento. |
| GetAuthentication | ID intento. | Estado, motivo público, vencimiento y resultado disponible. | Autoridad sobre ese intento; no exposición de otro agente por compartir credenciales. |
| CancelAuthentication | ID intento. | Estado final o transición ya completada. | No equivale a logout de una sesión externa ya establecida. |
| GetCapabilities | Consulta de versión/compatibilidad. | Métodos e integraciones verificadas en este entorno. | No afirmar compatibilidad por simple existencia de un elemento en la bóveda. |

El CLI debe ofrecer salida estructurada estable para automatización y reservar diagnósticos no sensibles fuera del canal de resultados. El adaptador MCP utiliza los mismos casos de uso del motor; no implementa otra política de acceso. Se selecciona MCP stdio 2025-11-25 con canal privado motor TLS 1.3/RPK; no servidor MCP HTTP remoto adicional.

### 7.2 Superficie humana

La TUI debe cubrir: inicialización/desbloqueo/bloqueo, CRUD de todos los tipos, revelar/copiar, generador, organización, revisiones/restauración, papelera, importación, exportación, backups, recuperación, agentes, conjunto común, suspensión delegada, dispositivos, sincronización, auditoría y autenticaciones pendientes.

No basta con esconder estas operaciones del listado de herramientas MCP: llamadas directas al motor desde una identidad de agente deben ser rechazadas.

### 7.3 Resultados y fallos

Categorías públicas del núcleo: `UNAUTHORIZED`, `AGENT_REVOKED`, `AGENT_ACCESS_SUSPENDED`, `CREDENTIAL_UNAVAILABLE`, `DESTINATION_MISMATCH`, `UNSUPPORTED_INTEGRATION`, `HUMAN_ACTION_REQUIRED`, `AUTHENTICATION_REJECTED`, `ATTEMPT_EXPIRED`, `ATTEMPT_CANCELLED`, `CUSTODY_UNAVAILABLE`, `SYNC_UNAVAILABLE`, `INVALID_IMPORT` e `INTEGRITY_FAILURE`; se añaden `INVALID_ARGUMENT`, `UNSUPPORTED_VERSION`, `NOT_FOUND`, `IDEMPOTENCY_CONFLICT`, `IDEMPOTENCY_EXPIRED`, `RESULT_EXPIRED`, `RATE_LIMITED`, `CLOCK_UNTRUSTED` e `INTERNAL_ERROR` conforme al [wire v1](../../docs/design/agent-identity.md).

- Error de autorización no debe filtrar existencia/contenido de elementos fuera del conjunto.
- Un estado pendiente no es un éxito ni debe resolverse con un retry infinito.
- Si una operación repetida tiene la misma clave de idempotencia y contenido, devuelve el mismo intento; si el contenido difiere, se rechaza.
- No repetir una autenticación que pudiera haberse completado externamente solo porque se perdió la respuesta local. Registrar y conciliar el resultado o informar que es indeterminado; no anunciar ejecución exactamente una vez en un proveedor sin soporte.
- Redactar errores antes de que entren en logs/salidas; redacción no sustituye aislamiento ni autoriza que el secreto atraviese procesos del agente.

### 7.4 Mapeo público y separación de canales

| Operación lógica | RPC privado v1 | Tool MCP stdio |
|---|---|---|
| GetCapabilities | `pm.v1.capabilities` | `get_capabilities` |
| DiscoverCredentials | `pm.v1.credentials.discover` | `discover_credentials` |
| StartAuthentication | `pm.v1.authentication.start` | `start_authentication` |
| GetAuthentication | `pm.v1.authentication.get` | `get_authentication` |
| CancelAuthentication | `pm.v1.authentication.cancel` | `cancel_authentication` |

CLI: `pm capabilities`, `pm credentials list`, `pm auth start/status/cancel`, `pm mcp`; `pm tui` solo contexto humano. `--json` produce el contrato estructurado; éxito del RPC start no significa autenticación completada. No secretos en argumentos/entorno/stdout de diagnóstico.

Transporte privado JSON-RPC en TLS1.3/RPK, frame de longitud big-endian y máximo1MiB; MCP stdio mantiene su framing propio 2025-11-25. ALPN/peer/identidades separan agente, humano, consumidor confiable, sync y mantenimiento; ni elegir ALPN ni conocer un endpoint eleva permisos. G4/G8 son los contratos de rol y alta, no un campo `role` confiable enviado por cliente.

Las mutaciones humanas usan prepare/commit/receipt, challenge60s, hash de estado/cuerpo y SK_H. Staging pagina **eventos y objetos**, validado entero antes de un commit. Operaciones de mantenimiento administrativo son fijas/locales y no dan acceso humano a secretos. Agentes carecen de exportación, administración y API de firma genérica.

## 8. Autenticación y máquina de estados

### 8.1 Flujo feliz

1. El agente registrado descubre metadatos y elige una credencial explícita.
2. El motor verifica identidad, suspensión global, habilitación actual y compatibilidad de destino/método.
3. Se crea el intento, fijando la revisión seleccionada para trazabilidad.
4. Antes de cada uso sensible se vuelve a comprobar que el acceso no ha sido revocado o deshabilitado localmente.
5. La integración confiable utiliza la credencial sin entregarla al agente.
6. El motor devuelve el resultado permitido por la integración y registra el evento sin secretos.
7. Lo que el agente haga dentro del servicio queda fuera del motor. No se introduce un proxy permanente de autorización de acciones.

### 8.2 Estados seleccionados

| Estado | Transiciones válidas | Comportamiento |
|---|---|---|
| `CREATED` | `RUNNING`, `FAILED`, `CANCELLED`, `EXPIRED` | Todavía no se ha utilizado el secreto. |
| `RUNNING` | `SUCCEEDED`, `WAITING_FOR_HUMAN`, `FAILED`, `CANCELLED`, `EXPIRED`, `INDETERMINATE` | Solo un ejecutor activo por intento. |
| `WAITING_FOR_HUMAN` | `RUNNING`, `CANCELLED`, `EXPIRED`, `FAILED` | No probar otra credencial, otro factor ni bucles de autenticación. |
| `SUCCEEDED` | Terminal | No gestionar luego el ciclo de vida de la sesión externa. |
| `FAILED` | Terminal | Explicar la categoría de fallo sin secretos. |
| `CANCELLED` | Terminal | No reiniciar por sincronización ni reconexión del cliente. |
| `EXPIRED` | Terminal | Un desafío vencido no se resucita como si siguiera válido. |
| `INDETERMINATE` | Conciliación verificable a estado terminal | El proveedor pudo completar la operación; no repetir a ciegas. |

### 8.3 Intervención humana

- Ante una exigencia humana real, se pausa inmediatamente **ese intento** y se presenta en la TUI con contexto mínimo no sensible.
- El humano completa la verificación mediante el mecanismo del proveedor/integración. Mostrar un pendiente no implica implementar un navegador completo en la TUI.
- El motor comprueba evidencia de resolución; no acepta únicamente la afirmación del agente «ya está resuelto».
- Reanuda automáticamente solo si conserva validez, destino/cuenta correctos y autorización vigente.
- Si hubo reinicio, se restaura el estado pendiente sin suponer que el desafío externo persiste. Una comprobación fallida termina o mantiene espera según la evidencia disponible, sin login repetitivo.
- Cancelar/revocar durante espera evita la reanudación. Si una autenticación ya completó, la revocación no promete deshacer sus efectos ni cerrar su sesión.

### 8.4 Integraciones, sin expansión de responsabilidad

El alcance debe cubrir familias web, sistema y servidores, además de los tipos acordados. No se declara compatibilidad universal con todos los productos de esas familias. La nota G3 fija la matriz concreta de métodos, destinos, runtimes y pruebas; su cierre documental no certifica compatibilidad.

| Familia | Responsabilidad del adaptador | Prueba crítica antes de anunciar soporte |
|---|---|---|
| Login web con contraseña/TOTP | Autenticar usando datos habilitados y gestionar la pausa de ese intento. | Que herramientas del agente no recuperen contraseña/código durante su uso; no basta ocultar la respuesta del CLI. |
| Passkeys | Utilizar claves mediante un autenticador compatible y respetar presencia/verificación exigida. | Integración real del autenticador/proveedor, no solo almacenamiento ni autenticador virtual de pruebas. |
| SSH | Usar claves o método soportado para autenticación sin exportar clave privada/contraseña. | Separación de custodia y límites reales de firma/conexión; no convertir una API de firma sin restricciones en soporte seguro por afirmación. |
| Tokens/API keys | Utilizar la credencial guardada para el destino configurado. | No inyectar el secreto en un entorno, archivo o header observable por herramientas controladas por el agente. |
| Credenciales de sistema | Integración con mecanismo nativo compatible, dentro del entorno autorizado. | No conceder administración del propio custodio al agente ni resolver esa contradicción mediante un bypass. |

La validación de destino evita entregar una credencial a un sitio arbitrario: pertenece a la protección de la bóveda, no a un sistema de permisos de negocio. Cada adaptador debe definir origen/host/identidad del servicio y tratamiento de redirecciones.

Si una integración solo funciona entregando el secreto a procesos del agente, **no cumple R09**. Debe marcarse no soportada hasta tener un mecanismo compatible, no degradarse silenciosamente. Eso constituye una limitación de compatibilidad a resolver/documentar, no autorización para eliminar familias del alcance.

### 8.5 Catálogo seleccionado y evidencia de éxito

| Perfil concreto | Ruta | Resultado permitido y condición |
|---|---|---|
| Keycloak26.7.3 password/TOTP | Browser Chromium privado, code+PKCE y callback validado; no ROPC ni DOM bajo agente. | Tokens OIDC nuevos después de validar respuesta/cuenta; nunca password/TOTP/DOM. |
| Keycloak Standard Token Exchange v2 | Adaptador confiable con bearer almacenado y contexto de exchange autorizado. | Token emitido distinto del secreto original; no exchange genérico para cualquier API key. |
| Passkeys propias | Proveedor MV3 + Native Messaging Rust + clave custodial; alta humana y UP/UV reales en TUI. | Login Keycloak verificado produce OIDC; assertion sola no equivale a login. Pausa por exigencia humana no se elude por autonomía. |
| SSH/servidores | Cliente confiable russh0.63.3 y firma custodial/password en integración. | `ssh_authenticated_connection` ligado al consumidor tras AuthResult Success; el consumidor conserva la conexión y la aplicación sus acciones. |
| Cuentas nativas | Cliente anterior con OpenSSH/Linux, Apple Remote Login o Windows OpenSSH existentes. | Misma conexión autenticada; no UAC/sudo/loginwindow genéricos ni configuración automática de servicios. |
| GitHub REST2026-03-10 PAT | `github-rest-bearer/1`, petición tipada `github-assigned-issues/1`, GET/issues con parámetros cerrados. | `authenticated_http_response` tipada, no bearer/headers/errores reflejados ni proxy HTTP arbitrario. |

No copiar aquí cada campo de context/result: los schemas propietarios G3/G4 son normativos. P1–P5 validan rutas y ataques; capacidades solo anuncia lo realmente implementado y comprobado en ese entorno. La selección documental del catálogo no anuncia soporte operativo ni promete todos los proveedores de cada familia.

## 9. Custodia, modelo de amenazas y reinicios

### 9.1 Activos y adversarios

Activos: secretos activos e históricos, claves maestras/delegadas/de recuperación, exportaciones, adjuntos, metadatos no habilitados y autoridad para registrar agentes/dispositivos.

Amenazas a cubrir en el entorno soportado: agente manipulado por contenido externo; procesos no registrados; agente que intenta invocar operaciones humanas; lectura de archivos/memoria accesible indebidamente; entradas de importación maliciosas; corrupción, repetición o reordenamiento de sincronización; pérdida de dispositivo; fallos/crashes durante escritura.

Límites del modelo: no prometer protección frente a administrador/kernel comprometido del custodio, terminal humano comprometido, propietario que revela voluntariamente un secreto o proveedor legítimo malicioso al que se entregó una contraseña. El sistema custodio y la integración que usa el secreto son parte de la base de confianza.

La exclusión de sesiones externas no elimina la obligación de impedir extracción del secreto original durante la autenticación. Tampoco implica que almacenar una API key deje de protegerla porque sea un token.

### 9.2 Suite y custodia seleccionadas

- Cifrado autenticado para contenido, revisiones, adjuntos y backups; verificar integridad antes de presentar o activar datos.
- Claves envueltas con vías separadas de acceso humano, delegado y recuperación; nunca copiar la contraseña maestra al contexto del agente.
- Limitar criptográfica y operacionalmente la delegación al conjunto habilitado; una clave exportable que descifre toda la bóveda dentro del entorno del agente viola R09.
- Derivación/protección de claves y aleatoriedad mediante bibliotecas revisadas; ninguna criptografía casera.
- G2 fija XChaCha20-Poly1305, Argon2id, Ed25519, sealed boxes, CBOR determinista y secretstream, nonces, propósitos y envolturas; G7 fija tratamiento de memoria. Su revisión/validación es trabajo de ejecución, no elección de primitivas pendiente.
- Evitar secretos en argv, variables del agente, historial del shell, core dumps, telemetría y archivos temporales. La mitigación concreta por OS es parte de G1/G2.
- Los backups y datos históricos también contienen secretos antiguos. Borrar un elemento no permite prometer borrado físico de copias ya exportadas o dispositivos offline.

### 9.3 Tres estados independientes

1. **Interfaz humana bloqueada/desbloqueada:** decide acceso humano a operaciones sensibles.
2. **Delegación habilitada/suspendida:** decide si agentes autorizados pueden iniciar nuevos usos.
3. **Custodia disponible/no disponible:** expresa si el motor puede utilizar la clave necesaria en ese entorno.

Bloquear la TUI no significa que toda clave quede inaccesible al motor: la delegación persistente requiere una vía de uso independiente. No anunciarlo como «bóveda totalmente inaccesible» mientras agentes pueden seguir autenticándose.

Tras reinicio, la autorización y suspensión deben persistir. El soporte de ejecución autónoma se valida con el sistema operativo y almacenamiento necesarios disponibles; la bóveda no elimina un desbloqueo de disco exigido antes de que arranque el propio sistema. Las condiciones de instalación deben documentarse explícitamente, sin fingir autonomía ante un entorno que impide arrancar al custodio.

### 9.4 Adaptadores nativos requeridos

Linux, macOS y Windows necesitan contratos equivalentes de identidad separada, claves, IPC autenticado, permisos, inicio/paro, instalación y actualización. Secret Service/Keychain/DPAPI no son garantías intercambiables ni sustituyen pruebas de aislamiento. Los perfiles concretos están seleccionados en G1/G2/G7/G8 y resumidos en §5.3.

## 10. Almacenamiento, sincronización y LWW

### 10.1 Local-first

- Las operaciones locales no requieren una cuenta ni respuesta del servidor de sincronización.
- Escritura de contenido/revisión/evento debe ser atómica y recuperable tras crash; ningún fallo deja un elemento parcialmente activo.
- El servidor almacena/transfiere ciphertext, no recibe secretos, contraseña maestra o capacidad de recuperación.
- Emparejar un dispositivo requiere una autorización humana verificable y provisión segura de claves. No basta iniciar sesión en el servidor para descifrar la bóveda.
- Publicar/descargar es idempotente; verificar formato, integridad y autorización antes de integrar cambios.
- Estados visibles: no configurado, al día, cambios pendientes, offline y error. No convertir la caída del servidor en bloqueo del uso local.

### 10.2 Semántica seleccionada de last-write-wins

- Unidad de resolución: revisión completa de un elemento, no mezcla arbitraria de campos secretos de distintas versiones.
- Orden total seleccionado: timestamp UTC de modificación, seguido de ID de dispositivo y ID de revisión como desempates deterministas. Todos los clientes aplican exactamente la misma comparación.
- Usar precisión/unidad y representación canónicas fijadas en el formato. Guardar origen y timestamp originales de importación como metadata, no hacer que un CSV antiguo sobrescriba silenciosamente un elemento existente.
- Gana la revisión de orden mayor; las demás pasan a historial. Restaurar una anterior crea una nueva revisión con nuevo timestamp.
- Conservar operaciones de eliminación como revisiones/tombstones mientras sean necesarias para convergencia. G5 fija purga manual, headers antirreplay retenidos y checkpoints que no olvidan autoridad para evitar resurrecciones conocidas.
- **Decisión funcional confirmada:** borrar prevalece frente a editar concurrentemente: el elemento permanece en papelera, conserva allí la edición ganadora por LWW y requiere restauración humana explícita para volver a activo. [ADR 0002](../../docs/adr/0002-borrado-frente-a-edicion-concurrente.md). La realización de retención y carreras de restauración/purga está fijada en G5, sin atribuir esa ingeniería al ADR funcional.
- Un reloj adelantado puede hacer ganar una edición antigua en tiempo real. Esta limitación es aceptada al elegir LWW por timestamp; no llamarlo orden causal perfecto ni cambiar a resolución manual.
- No pausar autenticaciones solo por un conflicto de contenido. Un intento ya creado no cambia silenciosamente de credencial/cuenta por la llegada de una revisión nueva; las comprobaciones de habilitación siguen vigentes.

### 10.3 Autorizaciones y revocaciones

La elección LWW se hizo para conflictos de credenciales. **No usar timestamps de contenido para permitir que una revisión vieja reactive un agente revocado.** El contrato G5 distingue eventos de seguridad de revisiones de contenido:

- Revocación/suspensión conocidas localmente se aplican antes del siguiente uso sensible.
- Un reenvío antiguo no revierte una revocación conocida. Si el humano vuelve a autorizar, debe ser una acción nueva verificable, no restauración accidental del historial.
- Equipo offline utiliza la última autorización conocida; revocación en otro equipo no es instantánea.
- Al recibirla, impedir nuevos usos; no afirmar que se cerraron sesiones externas existentes ni se recuperaron datos previamente usados.
- DAG firmado, reductor, cortes y checkpoints están definidos en G5; su convergencia aún debe probarse. No inventar una política por proyecto para resolver este problema.

## 11. TUI, importación, exportación y recuperación

### 11.1 Organización de la TUI

Secciones funcionales: elementos, búsqueda/organización, generador, historial/papelera, agentes/acceso común, autenticaciones pendientes, auditoría, backups/recuperación, importación/exportación y dispositivos/sincronización.

Toda función debe poder operarse por teclado. Revelar/copiar son acciones explícitas, no efectos laterales de seleccionar una fila. Las vistas y errores no deben llevar secretos a logs. El uso explícito del portapapeles por humano está permitido; sus límites frente a historial y aplicaciones externas deben comunicarse, sin prometer borrado universal.

### 11.2 Importación

1. El humano selecciona un archivo exportado por el producto de origen; no se extraen automáticamente bases privadas del navegador/Llavero.
2. Validar formato, tamaños y estructura sin ejecutar contenido. En .1pux, tratar rutas/adjuntos como datos no confiables.
3. Mostrar resumen de tipos/cantidades, mapeo y advertencias sin revelar valores sensibles por defecto.
4. Distinguir duplicados de elementos nuevos. No sobrescribir automáticamente por coincidencia débil de título/URL; presentar acciones humanas antes de confirmar importación.
5. Confirmar y escribir de forma transaccional. No habilitar automáticamente para agentes lo recién importado.
6. Informar qué se importó, rechazó o preservó como campo no reconocido; ningún descarte silencioso.
7. Advertir que el archivo fuente puede estar sin cifrar. No borrarlo sin autorización ni afirmar borrado físico garantizado.

No prometer migración de datos que el origen no exporta. Chrome/Apple CSV y 1Password desktop tienen límites documentados. Las passkeys necesitan una vía de migración compatible o recreación por los mecanismos del proveedor; almacenar passkeys no vuelve exportables las de otros gestores.

### 11.3 Exportación y backup

- Nativo cifrado y versionado: todos los tipos de elementos, adjuntos y datos de historial/organización definidos por el contrato de backup, con integridad comprobable.
- Exportación humana sin cifrar: alcance y riesgo explícitos, confirmación, permisos adecuados y sin registrar contenido.
- Un archivo de backup portable no exporta automáticamente identidades/keys delegadas reutilizables ligadas a un OS. Debe preservar datos de la bóveda sin clonar autoridad de agentes/dispositivos de forma silenciosa.
- [G6](../../docs/research/credential-migration.md) fija PMB1: todos los tipos/historial/adjuntos, auditoría local, settings y autoridad como historia; excluye privadas nativas, grants activos e intentos. Restauración nueva crea raíces/identidades nuevas; en destino existente importa contenido sin sustituir autoridad vigente.

### 11.4 Recuperación

- Requiere copia cifrada utilizable y clave externa válida, o la vía humana habitual todavía disponible.
- Validar clave, formato e integridad antes de reemplazar cualquier bóveda.
- Restaurar primero en un destino seguro y presentar resultado; no sobrescribir datos válidos por un intento fallido.
- Registrar nuevamente capacidades/identidades necesarias en un equipo nuevo; recuperación de datos no equivale a autorizar cualquier proceso.
- Sin clave/vía válida no existe bypass del servidor. No prometer recuperación universal.

## 12. Verificación por interfaces públicas

Actualmente no hay seams de código existentes. Las primeras pruebas deberán operar por interfaces externas reales: CLI/MCP contra motor real, TUI en terminal, almacenamiento real temporal y servidor de sincronización local. Dobles de proveedores solo en la frontera externa para fallos reproducibles; evitar mocks de cada módulo interno.

| ID | Escenario observable de aceptación | Requisitos |
|---|---|---|
| V01 | Crear/usar bóveda sin servidor ni cuenta; cerrar TUI y confirmar que motor no depende de ella. | R01, R15 |
| V02 | Ida/vuelta de todos los tipos, Unicode, adjuntos y metadatos, incluyendo historial/restauración. | R03–R05, R19 |
| V03 | Agente no registrado, registrado y revocado producen permisos distintos ante el mismo endpoint. | R06–R09 |
| V04 | Dos agentes registrados ven el mismo conjunto común; ninguno ve secretos ni metadata de elementos no habilitados. | R07–R09 |
| V05 | Agente intenta operaciones humanas directas, manipular flags y falsificar nombre de identidad: denegación verificable. | R06, R09, R10 |
| V06 | Credencial por ID y destino válido funciona en integración soportada; destino/cuenta incorrectos no reciben el secreto. | R08, R09 |
| V07 | Canarios secretos no aparecen en stdout/stderr/logs/errores/argv/env/temporales bajo control del agente. | R09 |
| V08 | Procesos del agente no leen archivos/memoria del custodio ni sustituyen su configuración/binario/servicio. | R09, R10 |
| V09 | TOTP y passkeys se prueban mediante integraciones reales compatibles; virtuales sirven solo como fixtures. | R03, R09, R13 |
| V10 | Desafío humano pausa solo un intento; otro sigue; no hay fallback ni retry continuo; resolución real reanuda. | R13 |
| V11 | Revocar, cancelar o vencer mientras espera impide reanudar; restart no resucita desafíos inválidos. | R06, R13 |
| V12 | Bloqueo TUI no detiene agentes; suspensión global sí impide nuevos usos y persiste tras reinicio. | R11, R12 |
| V13 | Reinicio nativo Linux/macOS/Windows bajo condiciones declaradas conserva autorización sin dar contraseña maestra al agente. | R02, R10, R11 |
| V14 | Caída de red mantiene operación local; revocación remota solo surte efecto al recibirse. | R15, R16 |
| V15 | Dos/tres dispositivos con cambios concurrentes, empates, reloj adelantado y entrega reordenada convergen por LWW. | R17 |
| V16 | Versiones perdedoras siguen recuperables; restauración crea una versión nueva; no pausa manual por conflicto. | R05, R17 |
| V17 | Replay de eventos no revive autorización revocada ni resucita accidentalmente eliminaciones ya conocidas. | R06, R16, R17 |
| V18 | Servidor y captura de su almacenamiento/tráfico no contienen secretos o claves de descifrado; modificación se rechaza. | R09, R15 |
| V19 | Importadores con fixtures oficiales/sintéticos, duplicados, columnas desconocidas, ZIP malicioso y datos truncados informan sin pérdidas silenciosas. | R19 |
| V20 | Exportación plaintext exige confirmación humana; identidad agente no puede exportar ni copiar adjuntos. | R04, R09 |
| V21 | Backup/restauración completa; clave errónea/ciphertext alterado no sobrescribe bóveda válida; equipo nuevo no hereda autoridad sin autorización. | R18, R19 |
| V22 | Cancelación, crash durante commit y pérdida de respuesta no generan doble uso ciego ni escrituras parciales. | R09, R13, R15 |
| V23 | Auditoría permite rastrear agente/credencial/resultado sin valores secretos; errores y crash reports se examinan con canarios. | R05, R09 |
| V24 | TUI completa usable por teclado en terminales soportados de tres OS, sin Omarchy/Electron. | R01, R02, R05, R21 |
| V25 | CLI y MCP presentan estados equivalentes, validan entradas/versiones y no bloquean indefinidamente por un pendiente. | R01, R13 |
| V26 | Distribución incluye licencia y obligaciones revisadas; no se introduce restricción no comercial ni SaaS oficial. | R15, R20 |
| V27 | Resultado exitoso no instala un gestor de sesiones ni aplica políticas de acciones externas. | R14 |

Las pruebas con canarios son evidencia necesaria, no prueba matemática de ausencia de toda filtración. La revisión de amenazas/criptografía y las pruebas nativas son puertas separadas.

### 12.1 Seams de prueba y artefactos verificables

**Inspección del repositorio:** 21 archivos Markdown, sin Cargo.toml, código de producto, base de datos, tests ni runtime configurado del proyecto. No hay seams implementados que reutilizar. Se seleccionan los de mayor nivel que los contratos ya exponen, no interfaces internas nuevas para mocks.

| Seam público seleccionado | Sistema real bajo prueba | Dobles permitidos y observación |
|---|---|---|
| CLI y MCP → custodio | Procesos reales, canal/identidad, almacenamiento temporal real, mismas operaciones. | Ningún motor/almacén/autoridad simulado; proveedor externo controlado para fallos. Comparar estados/schemas y rechazo por identidad. |
| TUI en terminal | Proceso real sobre pseudoterminal y sesiones nativas humanas. | Inputs sintéticos; verificar teclado, pantalla, errores y separación de bloqueo/suspensión. Clipboard requiere API/display nativo, no solo un mock que devuelve success. |
| Integración → proveedor | Keycloak/browser, passkey propia, cliente/servidor SSH y adaptador bearer. | Servidor de prueba para redirects/errores/reflexión; la conformidad de un doble no sustituye pruebas contra proveedor real autorizado. No credenciales reales en fixtures/repo. |
| Custodios → sync | Dos/tres procesos/almacenes y servidor local reales. | Red controlada para partición/reordenamiento/duplicación/omisión. Observar mismo estado lógico, autoridad y ausencia de secretos en servidor. |
| Importación/exportación/restore | Archivos sintéticos reales vía interfaz humana, staging y disco temporal. | Sin mocks de parser/DB/criptografía; comparar inventario y campos lógicos de todos los tipos, no ciphertext aleatorizado. |
| Instalador/servicio/actualizador | Entornos nativos desechables en los seis targets. | Repositorio de actualización firmado de prueba y fallos de disco/energía simulados en laboratorio; comprobar ACL, datos, autoridad y recovery. No tocar máquina de producción para validar. |

Complementos mínimos de menor nivel, por riesgo y no por cada clase interna: vectores de primitivas/formato G2, parsers de límites/entradas adversarias y reductor G5 con permutaciones reproducibles. Probarlos no sustituye los seams anteriores; no fijar una arquitectura de mocks ni exigir un porcentaje de cobertura inventado.

Cada resultado de prueba conserva: requisito/historia/Vxx o Pxx, versión/build y OS/CPU, fixture sintético, pasos/expectativa, observado y aprobado/fallido/no ejecutado. Logs/artefactos se revisan por canarios y no contienen secretos reales. Una prueba del flujo feliz no acredita extracción, recuperación o interoperabilidad en otro target.

### 12.2 Trazabilidad completa de historias

| Historias | Requisitos | Contratos / observación de aceptación |
|---|---|---|
| 1–4 | R01,R03–R05,R15,R18 | G1/G2/G6; V01,V02,V21,V24: crear, abrir, gestionar tipos y recuperar. |
| 5–11 | R03–R05,R17 | G2/G5/G7; V02,V07,V16,V20,V24: generador/organización/reveal/copy/historia/papelera. Generador respeta configuración elegida y fallo RNG, sin guardar resultado en diagnósticos. |
| 12–15 | R04,R18,R19 | G6/G7; V19–V21: cuatro orígenes, pérdidas/duplicados, plaintext confirmado y backup íntegro. |
| 16–22 | R03,R06–R10 | G1/G3/G4; V03–V09,V27: identidades/conjunto común/destino/métodos y rechazo sin fallback. |
| 23–27 | R08,R13 | G3/G4; V10,V11,V22: pausa individual, evidencia humana, cancelación, vencimiento/fallo. |
| 28–30 | R10–R12 | G1/G2/G4; V12,V13: bloqueo independiente, suspensión y reinicio sin contraseña maestra para agente. |
| 31 | R05,R09 | G7; V23: actor/credencial/resultado trazables, sin payload secreto. |
| 32–37 | R05,R06,R15–R17 | G5; V14–V18: emparejamiento/offline/retiros/LWW/historia con dispositivos reales. |
| 38–39 | R18,R19 | G2/G6; V21: clave externa sin equipo original y corrupción sin sobreescritura. |
| 40 | R01,R02,R21 | G1/G7/G8; V24: TUI completa por teclado, sin Omarchy/Electron. |
| 41–42 | R01,R20 | G4/G8; V25,V26: interfaces consistentes, licencia/fuente/avisos. |
| 43–45 | R04,R05,R09,R12 | G2/G7; V07,V12,V20,V24: clave errónea no muta, idle/reveal/copy y límites de limpieza. |
| 46–47 | R07,R19 | G6; V04,V19: campos preservados/reportados y cero habilitación automática al importar. |
| 48–50 | R03,R08,R09,R13,R14 | G3; V06,V09,V27/P1–P5: passkey propia, SSH utilizable confirmado, respuesta PAT tipada sin secreto. |
| 51–53 | R06,R08,R13 | G4/G5; V05,V10,V11,V22: ownership de intentos, respuesta perdida y revocación durante espera. |
| 54–55 | R05,R17 | ADR0002/G5; V15–V17: borrar vence edición, restauración explícita, retención/purga manual. |
| 56–57 | R06,R18,R19 | G2/G5/G6; V17,V21: restore sin autoridad antigua, cambio de maestra/recuperación preserva vías verificables y límites de backups viejos. |
| 58–59 | R05,R09,R10 | G1/G7; V07,V08,V23: purga audit declarada e indisponibilidad segura sin eliminar evidencia de autoridad. |
| 60–62 | R02,R11,R18,R20 | G8; V13,V21,V26: firmas, actualización/rollback y uninstall sin pérdida ni revocaciones revertidas. |
| 63–64 | R06,R09,R10,R18 | G2/G4/G7; V05,V08,V21,V25: versión/input rechazados, recuperación limpia tras compromiso sin garantías sobre copias ajenas. |

### 12.3 Criterio de finalización del producto, no de esta síntesis

- Todos los recorridos y requisitos tienen implementación y evidencia por seam/target aplicable; ningún campo/tipo se pierde para que pase un test.
- V01–V27 y P1–P5 cuentan con resultado y artefactos, incluyendo fallos/carreras/recuperación y pruebas de no entrega del secreto dentro del modelo soportado.
- Composición criptográfica y aislamiento sometidos a revisión independiente; fallos críticos corregidos antes de anunciar soporte. No declarar seguridad por usar Rust/libsodium o por una revisión documental.
- Instalación/distribución tienen grafo fijado, fuentes/avisos/SBOM y verificaciones de firma; no inventar compatibilidad de dependencias no construidas.
- Los límites aprobados de offline, sesiones externas, recuperación y copias expuestas siguen comunicados. Pasar las pruebas no amplía el modelo de amenazas.

Estas son condiciones de aceptación futura para tickets/ejecución, **no decisiones de producto reabiertas** ni permiso para implementar durante `to-spec`.

## 13. Fuera de alcance

- Electron, aplicación gráfica pesada, web UI o móvil como sustituto necesario de la TUI.
- Plugin Omarchy dentro de este repositorio/entrega actual.
- SaaS oficial operado por el proyecto, facturación o plataforma empresarial de permisos.
- Políticas por proyecto o por agente sobre subconjuntos diferentes; todos los autorizados comparten lo habilitado.
- Control de acciones dentro de servicios, gestión/aislamiento permanente de sesiones posteriores o logout remoto universal.
- Entrega de secretos de bóveda a agentes como fallback de compatibilidad, ni APIs humanas disfrazadas de herramientas MCP.
- Rotación automática de contraseñas en servicios externos; no confundir con mantenimiento criptográfico de la propia bóveda.
- Saltarse requisitos de presencia/verificación humana o prometer autenticación universal.
- Recuperación por el operador sin claves del propietario; revocación instantánea de dispositivos desconectados.
- Importadores Bitwarden/KeePass no acordados, migración universal de passkeys o extracción silenciosa de bases privadas.
- Prohibición de cobro/uso comercial. AGPL no obliga automáticamente a abrir programas independientes solo por invocar CLI/MCP.
- Garantías frente a administrador/kernel comprometido del custodio o datos que el humano exportó voluntariamente.

## 14. Distribución y publicación

- AGPL-3.0 es la base funcional aprobada; [G8](../../docs/design/distribution.md) selecciona `AGPL-3.0-only`, avisos/fuente correspondiente y tratamiento de dependencias. Titularidad real y grafo/SBOM se cotejan antes de publicar; no inventar autores ni añadir cláusula no comercial. Esta fase no crea `LICENSE`.
- Entregar contratos de instalación nativos para motor y clientes; solo los privilegios requeridos para crear la separación de custodia, no ejecutar la TUI/agente permanentemente como administrador.
- G8 fija paquetes nativos, Chromium/extensión compatibles, TUF con umbrales de firma, mantenimiento local y rollback que no retrocede autoridad. Son contratos, no instaladores ni claves de publicación ya existentes.
- Seguimiento local configurado en [docs/agents/issue-tracker.md](../../docs/agents/issue-tracker.md). Esta especificación conserva su ubicación canónica; no hay publicación remota ni tickets de implementación creados por el setup.
- No crear tickets ni marcar `ready-for-agent` por el mero hecho de que el alcance funcional esté confirmado.

## 15. Estado consolidado: acuerdos, cierres de diseño y validación

Esta sección es el punto único de seguimiento del estado global. Las notas enlazadas conservan su razonamiento y estado histórico; «Gx abierta» en ellas no significa que todos sus asuntos sigan sin decidir. No crear otra lista paralela ni convertir esta consolidación en tickets.

### 15.1 Acuerdos cerrados — no volver a entrevistar

El contrato R01–R21 permanece confirmado. En particular:

- Motor independiente, CLI/MCP y TUI completa; Linux/macOS/Windows; Omarchy después y en otro repositorio (R01–R02, R21).
- Capacidades humanas completas, tipos de elementos y orígenes de importación acordados (R03–R05, R19).
- Alta humana y revocación individual, conjunto común, selección por ID y agentes sin acceso a secretos ni administración del custodio (R06–R10).
- Delegación persistente, bloqueo humano separado, pausa de solo la autenticación que exige intervención y reanudación verificable (R11–R13).
- Bóveda, no administración de acciones/sesiones externas; [ADR 0001 aceptado](../../docs/adr/0001-limite-de-responsabilidad-de-la-boveda.md) (R14).
- Uso local, sincronización opcional E2EE autohospedada, autoridad offline conocida, LWW por timestamp con historial y recuperación mediante clave externa/backup (R15–R18).
- Borrado frente a edición concurrente: papelera conserva la edición ganadora; volver a activo requiere restauración humana explícita; [ADR 0002 aceptado](../../docs/adr/0002-borrado-frente-a-edicion-concurrente.md).
- AGPL-3.0 como base y uso comercial permitido bajo sus obligaciones; no restricción no comercial ni SaaS oficial (R15, R20).

Faltar pruebas no reabre estos acuerdos. La aprobación de un caso funcional tampoco ratifica automáticamente toda recomendación técnica que lo acompañaba.

### 15.2 Inventario acotado de cierre técnico

**Estado actual:** elecciones G1–G8 completas documentalmente, incluidos reductor y transporte de sync, schemas de datos/backup, comandos humanos, controles operativos y distribución. La revisión cruzada corrigió referencias criptográficas circulares, claves que habrían exigido TUI desbloqueada y paginación de importaciones. Son selecciones de ingeniería al completar el encargo, no aprobaciones individuales de parámetros ni pruebas ejecutadas.

La columna «cierre de diseño restante» solo incluye decisiones no resueltas: no volver a comparar stack/TLS/KDF sin evidencia que refute la elección. El asistente debe resolver ingeniería con elección concreta y justificación, no devolver al usuario preguntas sobre algoritmos o parámetros sin análisis. Solo elevar cambios de alcance, compromisos materiales de uso/retención/licencia o autorizaciones necesarias. Las pruebas de la última columna se planifican ahora y se ejecutan cuando exista autorización y un artefacto comprobable.

| Bloque | Decisión/base disponible | Cierre de diseño restante | Evidencia posterior necesaria |
|---|---|---|---|
| G1 — Plataforma/stack | **Selección documental cerrada:** Rust 1.98.1/Ratatui 0.30.2/Crossterm 0.29, rusqlite, libsodium FFI y rustls; [versiones y perfiles Linux/macOS/Windows](../../docs/design/isolation.md). Custodio dedicado, peer nativo bilateral, pkg/LaunchDaemon CLI-first macOS y bootstrap disponible tras desbloqueo de volumen cifrado. | Ninguna elección pendiente de lenguaje, init/IPC o ubicación de clave en este perfil. G7 detalla controles, G8 distribución y auditoría del grafo; no afirmar soporte certificado ni excluir portabilidad Linux no-systemd. | Pruebas nativas concretas de [G1](../../docs/research/g1-stack-and-custody.md): reboot sin TUI, impersonación, permisos, TUI y persistencia; V01, V08, V13, V24. Build/lockfile no ejecutados. |
| G2 — Criptografía/formato | **Cierre documental:** [suite y composición v1 §9](../../docs/design/key-hierarchy.md#9-composición-completa-con-g5g6g7), schemas G6, manifiesto de revisión, PMB1/PMF1, claves por propósito, control G5, auditoría y estado de intento autónomo. | Ninguna elección restante de suite, contenedor, pertenencia o orden de construcción. Commitment de grant evita ciclo con evento; K_ATT no exige K_H en custodia autónoma. | Vectores, parser adversario, mezcla de sobres/propósitos, truncado/rollback, KDF, recuperación y revisión criptográfica independiente; V07,V18,V21. No ejecutados. |
| G3 — Integraciones | **Cierre documental:** [resolución B1–B4](../../docs/research/g3-authentication-integrations.md#resolución-de-b1b4--cierre-documental-de-g3). Keycloak26.7.3 OIDC/password/TOTP/exchange; cliente confiable russh0.63.3 propietario del transporte; proveedor de passkeys Chromium MV3 + Native Messaging + custodio; GitHub REST PAT por petición; cuentas nativas por OpenSSH/Apple Remote Login/Windows OpenSSH. | Ninguna elección pendiente de realización para estos perfiles. El motor no administra sesiones, la TUI sigue siendo completa y el agente no recibe secretos almacenados. B4 corrige un requisito local universal añadido por research, no elimina funciones aprobadas. Empaquetado de adaptadores/extensión en G8 y controles en G7. | **P1–P5:** browser/OIDC/WindowsARM64, exchange, cliente SSH/sistemas, passkeys propias con UP/UV y bearer opaco sin reflexión. V06–V11,V27. No ejecutadas; cero perfiles certificados. |
| G4 — API/identidades | **Cierre documental:** [wire y comandos §9](../../docs/design/agent-identity.md#9-cierre-de-comandos-humanos-y-autoridad-distribuida): CLI/MCP, TLS/RPK, cinco tools, bootstrap, plazos, idempotencia, transacción humana y roles separados. Contratos G3 y eventos G5 definidos. | Ninguna elección restante de identidad, transporte o schema administrativo/distribuido. Importaciones paginan eventos y objetos antes de commit único; no nuevos permisos de agente. | Handshake/RPK, roles, replay, revocación activa, crash/pérdida de respuesta, CLI/MCP y transacciones grandes; V03–V05,V10–V12,V22,V25. |
| G5 — Sync/retención | **Cierre documental:** [contrato §9](../../docs/design/synchronization.md#9-contrato-g5-seleccionado--cierre-documental): DAG firmado, reductor, cortes de emisor, generations, LWW, purga causal, checkpoint cache y servidor mínimo autohospedado. | Ninguna elección restante. Retención manual sin caducidad automática; headers antirreplay conservados, crecimiento explícito sin quorum ni obligación de reconectar. No modifica LWW ni borrado frente a edición aprobados. | Permutaciones, revocación cruzada/forks, cortes, partitions, checkpoints, purga, presión de disco y omisión/replay; V14–V18. Convergencia no ejecutada ni teorema afirmado. |
| G6 — Migración/backup | **Cierre documental:** [contrato nativo/importadores](../../docs/research/credential-migration.md): campos/tipos, 1PUX3, Chrome, Apple mapeable, CSV; duplicados/pérdidas, límites, PMB1 e inventario completo. | Ninguna elección restante de mapeo, cobertura o restauración. Orígenes sin campos no se inventan; autoridad de backup es histórica; restore nuevo crea linaje, existente conserva autoridad actual. | Fixtures sintéticos por origen, ZIP/CSV adversarios, todos los tipos/campos/adjuntos/historial y auditoría, truncado/crash/restore sin keyring; V02,V19–V21. |
| G7 — Seguridad/operación | **Cierre documental:** [controles y operación](../../docs/design/security-operations.md): matriz amenaza/control/evidencia/responsable, memoria/dumps, TUI/clipboard, auditoría cifrada y retención, disco/staging y compromiso. | Ninguna elección restante de control/fallo/respuesta. Límites de heaps ajenos, rollback integral y borrado físico documentados; sin promesas de protección fuera del modelo. | Extracción/crash/canarios nativos, clipboard races, fsync/disco lleno, log/purga/recovery y revisión de seguridad; V05,V07–V08,V13,V20–V23. |
| G8 — Distribución/licencia | **Cierre documental:** [entrega y licencia](../../docs/design/distribution.md): AGPL-3.0-only, inventario directo de licencias, paquetes seis targets, Chromium propio/MV3, TUF, claves, mantenimiento, rollback y uninstall. | Ninguna elección restante de variante SPDX, empaquetado o confianza. Autoría/certificados/keys reales y grafo efectivo se verifican al preparar release, no se presumen existentes. | Build/lockfile/SBOM y fuentes correspondientes, firma/notarización, install/upgrade/rollback/uninstall nativos, browser/extension y auditoría de obligaciones; V13,V26, P1/P4. |

### 15.3 Qué bloquea diseño y qué no

**Bloqueos de diseño de este inventario: ninguno pendiente.** G1–G8 tienen contratos y alternativas seleccionadas; no convertir las pruebas de la última columna en decisiones nuevas ni iniciar otra investigación general. Un hallazgo concreto que refute un contrato se corrige en ese contrato y se registra aquí, sin reabrir acuerdos funcionales automáticamente.

**Comprobación previa de viabilidad:** si una elección depende de un hecho no demostrado —por ejemplo, si un flujo web permite entregar el resultado sin exponer el secreto, o si la custodia nativa puede arrancar con las claves disponibles— formular una prueba acotada con criterio de éxito/refutación y pedir autorización cuando sea necesaria. No declarar resuelta esa elección por preferencia. Esta comprobación puede preceder al cierre del diseño afectado.

**Validación de implementación:** los vectores ejecutados, roundtrips, pruebas end-to-end, crashes e instaladores requieren artefactos. Son entregables de ejecución/validación, no decisiones funcionales pendientes. No exigir el producto terminado y probado antes de poder planificar su implementación.

Por tanto, preparación significa: diseño relevante cerrado, viabilidad crítica respaldada, pruebas pendientes definidas como criterios de aceptación y autorización separada para ejecutar. Las garantías de seguridad/compatibilidad solo se anuncian cuando pase su evidencia, aunque la decisión de diseño ya esté tomada.

### 15.4 Preparación y siguiente fase

1. **Cierre documental completado:** G1–G8 y sus dependencias cruzadas; decisiones y límites en los documentos enlazados.
2. **Siguiente fase posible:** descomponer estos contratos en tickets locales y criterios de aceptación, únicamente cuando el usuario autorice esa fase. No necesita otra entrevista o ronda genérica de research.
3. Planificar primero las comprobaciones críticas de composición/aislamiento y P1–P5 junto a sus artefactos mínimos; una prueba puede refutar una realización, pero la ausencia actual de código no es una pregunta de diseño pendiente.
4. Implementar, probar o publicar requiere autorización posterior; no confundir contrato listo para planificación con producto certificado, release publicable o permiso de ejecución.

**Cierre documental:** cada elección pendiente tiene una solución concreta, compatibilidad razonada, autoridad de decisión registrada y prueba/criterio de aceptación asociado; ninguna ambigüedad esencial se disfraza de «se resolverá implementando». El documento puede quedar listo para planificar mientras su validación de producto aún no existe. La aprobación para crear tickets, prototipos o código sigue siendo independiente.

**Estado de esta iteración:** todos los cierres de diseño G1–G8 del inventario fueron completados, sin recortar R01–R21 ni historias; validación crítica, pruebas de producto y puertas de publicación no ejecutadas. La síntesis `to-spec` publica `ready-for-agent` como preparación documental; no crea tickets ni autoriza implementación. No quedan decisiones que devolver al usuario sobre los cuatro contratos solicitados; los límites técnicos documentados son parte de sus criterios verificables.

### 15.5 Publicación de la síntesis v1.0

`to-spec`, 2026-09-12: publicada en este mismo archivo del tracker local con etiqueta **ready-for-agent**, sin servicio externo ni nuevos tickets. Se conservaron R01–R21, historias1–42 y V01–V27; historias43–64 hacen explícitos recorridos/fallos ya acordados. Se incorporaron contratos propietarios, fronteras, persistencia, mapeo CLI/MCP, catálogo concreto y trazabilidad de pruebas; se retiraron textos preliminares que aún presentaban elecciones cerradas como pendientes.

La etiqueta describe preparación de esta especificación para descomposición y ejecución **cuando sea autorizada**; no es certificación ni cambia el alcance de permisos actual. No se configura un catálogo global de triage ni se cambia el ciclo open/claimed/resolved del tracker por etiquetar esta especificación.

## 16. Evidencia y referencias

### Investigación del repositorio

- [G3: perfiles concretos y resolución B1–B4](../../docs/research/g3-authentication-integrations.md): cierre documental de perfiles; P1–P5 pendientes, cero integraciones certificadas.

- [Contrato de sincronización](../../docs/design/synchronization.md): contenido LWW y autoridad sin depender de relojes; borrado frente a edición concurrente aprobado en ADR 0002, retención/cortes/checkpoints definidos, validación pendiente.
- [Identidad y wire v1 seleccionados](../../docs/design/agent-identity.md): alta humana, TLS/RPK, CLI/MCP, autorización y revocación; contratos G3/G5 y transacciones definidos, pruebas pendientes.
- [Jerarquía y contenedor criptográfico v1 seleccionado](../../docs/design/key-hierarchy.md): vías humana/delegada/recuperación, suite y contenedor; manifiesto G6/composición definidos, revisión independiente y validación pendientes.
- [Aislamiento, stack y perfiles seleccionados](../../docs/design/isolation.md): selección documental G1; controles G7 definidos y evidencia nativa pendiente.
- [Seguridad y operación G7](../../docs/design/security-operations.md): controles, auditoría, fallos e incidentes.
- [Distribución y licencia G8](../../docs/design/distribution.md): paquetes, TUF, fuentes/licencias, actualizaciones y desinstalación.
- [Bases técnicas G1–G3](../../docs/research/technical-foundations.md): comparación histórica; las selecciones posteriores y esta síntesis prevalecen, sin modificar el contrato funcional.
- [Viabilidad multiplataforma](../../docs/research/cross-platform-feasibility.md).
- [Migración de credenciales](../../docs/research/credential-migration.md).
- [Autenticación sin intervención](../../docs/research/unattended-authentication.md): evidencia de TOTP/WebAuthn; la recomendación histórica de fallback fue rechazada.
- [Omarchy](../../docs/research/omarchy-integration.md): evidencia de plugins sin sandbox; integración diferida por decisión posterior.

### Fuentes primarias

- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238.txt).
- [W3C WebAuthn: assertions](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion) y [automatización de pruebas](https://www.w3.org/TR/webauthn-3/#sctn-automation).
- [Linux Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html), [Apple Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web), [Windows DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
- [MCP transports, referencia consultada](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports); versión seleccionada del adaptador stdio; implementación no ejecutada.
- [Ratatui: compatibilidad de backends](https://ratatui.rs/concepts/backends/comparison/).
- [1Password exportación](https://support.1password.com/export/) y [1PUX](https://support.1password.com/1pux-format/).
- [Chrome exportación](https://support.google.com/chrome/answer/13068232?hl=en), [Apple Contraseñas exportación](https://support.apple.com/guide/passwords/export-passwords-mchl35b12625/mac).
- [GNU AGPL](https://www.gnu.org/licenses/why-affero-gpl.html), [separación entre programas](https://www.gnu.org/licenses/gpl-faq.en.html#MereAggregation), [definición Open Source](https://opensource.org/osd).

No se ejecutaron pruebas de producto, no se implementaron importadores/autenticadores y no se modificó configuración del sistema para redactar esta especificación.
