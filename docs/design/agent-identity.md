# Registro de agentes y contrato de comunicación v1

Fecha: 2026-09-12. Estado: **selección de ingeniería para la especificación**, no aprobación explícita del usuario de primitivas ni compatibilidad certificada. G4 cerrado documentalmente: núcleo, integraciones G3 y comandos/autoridad distribuida G5 definidos en §9. Sin implementación ni pruebas de protocolo.

Autoridad: [contrato R06–R14 y API lógica](../../.scratch/passwordmanager/spec.md), [aislamiento](isolation.md), [jerarquía de claves](key-hierarchy.md) y [glosario](../../CONTEXT.md). No se crean permisos por proyecto, subconjuntos por agente ni gestión de sesiones externas.

## 1. Recomendación y alternativas

**Elección de esta iteración:** una identidad criptográfica por agente registrado, autorizada por el humano y vinculada al entorno previsto; autenticación mutua con el custodio y autorización vigente por operación. La conexión identifica al agente, no decide por sí sola qué puede hacer.

| Alternativa | Ventaja | Defecto | Propuesta |
|---|---|---|---|
| Nombre, PID, UID o ubicación del socket | Integración local simple. | No representa necesariamente a cada agente revocable ni prueba autoridad humana. | Usar identidad nativa como protección adicional, no como registro completo. |
| Token bearer compartido por todos | Configuración breve. | No separa identidades ni revocación; quien lo copia hereda la misma autoridad. | Descartar. |
| Clave individual y registro firmado por autoridad humana | Permite prueba de posesión y revocación individual sin entregar secretos del proveedor. | Exige provisión inicial, protección de la clave y verificación de ambos extremos. | Seleccionada; pruebas pendientes. |

Son alternativas evaluadas; se selecciona clave individual/registro firmado, no comparativas ejecutadas. El agente registrado representa una **instalación/identidad operativa**, no necesariamente cada conversación o ejecución del modelo. Reiniciar una tarea no obliga a registrarla nuevamente. Dos procesos que comparten su clave son indistinguibles bajo esta identidad; la separación entre agentes depende también del [perfil de aislamiento](isolation.md).

## 2. Separar cuatro autoridades

| Identidad | Prueba/raíz de confianza propuesta | Autoridad |
|---|---|---|
| Humano | Canal humano protegido y operación autorizada por `SK_H` tras desbloquear. | Administrar bóveda, registrar/revocar agentes y cambiar conjunto común. |
| Dispositivo custodio | Clave de autenticación de transporte incorporada al registro confiable por el humano. | Acreditar que el cliente está hablando con el custodio esperado. No convierte al custodio en propietario. |
| Agente | Posesión de clave privada cuya pública figura en una concesión humana vigente. | Consultar metadatos habilitados y solicitar autenticaciones compatibles. |
| Proveedor externo | Verificación de destino definida por la integración. | Recibir únicamente la credencial destinada a ese proveedor, no autoridad sobre la bóveda. |

La clave de autenticación del custodio es **distinta** de `SK_D`, que abre sobres de contenido delegado. Las claves de agente, transporte y autoridad no se reutilizan para cifrar elementos. Ampliación de propósitos de la [jerarquía propuesta](key-hierarchy.md), no algoritmos elegidos.

### Registro lógico

Una concesión contiene: ID opaco de agente, clave pública y generación, bóveda, vínculo con dispositivo/entorno autorizado, nombre visible, referencia a aprobación humana y estado. El nombre es solo presentación. El vínculo evita usar el alta de una instalación para matricular automáticamente otra; no limita qué credenciales ve cada agente.

No incluir listas de credenciales por agente. Todos los activos acceden al conjunto común conocido localmente. El registro de dispositivos custodios, sus públicas y la raíz de autoridad se provisiona por canal humano confiable; una raíz enviada por un cliente no se vuelve confiable porque valide su propia firma. Orden/propagación del registro quedan en G5.

## 3. Alta inicial, sin una puerta pública de administración

**Flujo recomendado: intercambio de solicitud pública y aprobación humana explícita.** No abrir por defecto un endpoint de autoinscripción ni aceptar una URL de enrolamiento arbitraria sugerida por el agente.

1. El adaptador del agente genera su clave de identidad en el entorno aislado. Exporta una solicitud **pública**, sin secretos de bóveda ni clave privada.
2. El humano obtiene esa solicitud por el mecanismo confiable de su entorno. Desde TUI/CLI humana desbloqueada verifica la huella de la pública y la procedencia prevista. Comparar dos textos suministrados por el mismo agente no verifica un segundo entorno.
3. La interfaz muestra el agente, entorno/dispositivo y alcance: utilizar el conjunto común sin revelar secretos ni administrar. Etiquetas y campos importados se tratan como datos, no comandos ni instrucciones.
4. La aprobación firma el contenido exacto, incluido un identificador de solicitud de un solo uso, caducidad y destinatario. Cambiar pública, bóveda o vínculo invalida la aprobación. El registro queda pendiente de prueba de posesión.
5. El agente recibe la concesión pública y la identidad confiable del custodio mediante el intercambio aprobado. No confiar automáticamente en la primera clave que responda por red.
6. La primera conexión prueba posesión de la clave aprobada. El custodio valida concesión, caducidad y estado; consume la solicitud y activa el registro de forma atómica. Repetir la confirmación devuelve el mismo resultado, no crea otra identidad. Si antes fue revocada, no la reactiva.

El artefacto público aprobado no es un bearer: sin la privada correspondiente no autentica al agente. Una clave robada sí permite actuar como ese agente hasta que se aplique su revocación; no hay identificación mágica del modelo original.

El formato y la caducidad del alta se fijan en §7. La caducidad del **alta pendiente** no se convierte en obligación de aprobación humana periódica del agente activo.

## 4. Canal autenticado y continuidad desatendida

**Perfil seleccionado:** TLS 1.3 mutuamente autenticado con **raw public keys (RPK, RFC 7250)** Ed25519 y pinning de SPKI en ambos extremos; `rustls 0.23.44`, proveedor `aws-lc-rs` explícito. ALPN `pm-agent/1`. Solo TLS 1.3, grupo X25519, suites TLS_AES_256_GCM_SHA384 / TLS_CHACHA20_POLY1305_SHA256 / TLS_AES_128_GCM_SHA256. Sin 0-RTT, PSK, tickets ni resumption; cada conexión prueba posesión de nuevo. [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250.html), [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3), [proveedores rustls](https://docs.rs/rustls/0.23.44/rustls/crypto/).

**Trade-off decidido:** RPK evita certificados X.509 sin valor de autoridad y sus renovaciones/relojes en un protocolo privado con altas humanas. La alternativa X.509 con renovación de la misma clave queda descartada para este canal, no para HTTPS de proveedores. No se instala CA global ni se confía en CA pública/CN/TOFU. La identidad activa persiste hasta revocación explícita; no existe vencimiento de certificado que obligue intervención periódica.

Rustls expone `requires_raw_public_keys()` para verificadores y `verify_tls13_signature_with_raw_key()` para la firma del handshake. El verificador propio **solo** vincula SPKI esperado/rol/registro; la comprobación de firma se delega al helper y algoritmos del proveedor, sin devolver éxito incondicional. Exigir RPK en ambos extremos y rechazo de certificados, claves desconocidas, algoritmo distinto, TLS anterior o ALPN distinto. [API del verificador](https://docs.rs/rustls/0.23.44/rustls/client/danger/trait.ServerCertVerifier.html), [helper](https://docs.rs/rustls/0.23.44/rustls/crypto/fn.verify_tls13_signature_with_raw_key.html). Firma y negociación documentadas no equivalen a interoperabilidad ejecutada.

- La privada TLS es independiente de SK_D y SK_H. El alta fija bytes SPKI y su hash SHA-256, no un nombre. La clave del servidor se obtiene del instalador/registro humano confiable, no de su primer saludo.
- Canal delegado local sobre Unix socket/pipe protegido **más** TLS y comprobación nativa; TCP entre entornos solo por binding habilitado explícitamente al registrar. Ninguna API humana en TCP. [Perfiles elegidos](isolation.md).
- Canal humano local con ALPN `pm-human/1`: servidor RPK fijado por instalación, identidad de cliente nativa obligatoria y comandos administrativos firmados por SK_H. No exige al humano una identidad de agente ni deja que el cliente seleccione su rol. Inicializar bóveda es una excepción local de una sola vez bajo identidad humana admitida por instalación; fija PK_H de forma atómica sin confiar en un registro traído por un agente.
- Sustituir identidad requiere operación humana que revoca la generación anterior, instala nueva pública y solicita prueba de posesión. Los intentos anteriores no se transfieren al nuevo agente: el humano puede consultarlos/cancelarlos; no reintentar login tras sustitución. Rotar servidor requiere nueva pública autenticada por autoridad humana y aceptación del registro; la firma de la vieja clave TLS por sí sola no basta.

La clave privada se protege en el entorno de cada agente, sin compartirla entre registros. No debe pasar como argumento, variable con su valor, log ni respuesta de herramienta; el cliente selecciona una referencia a su almacenamiento. No es una contraseña externa custodiada por la bóveda, pero su robo compromete esa identidad.

### MCP no sustituye ese canal

El cliente MCP lanza el adaptador `stdio`; ese adaptador usa su identidad para conectar al custodio. No carga claves de contenido ni ejecuta la autoridad humana. Las salidas y errores continúan sin secretos. La revisión MCP seleccionada es **2025-11-25**, transporte stdio. [Transportes MCP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

No usar ID de sesión MCP, ID de intento ni clave de idempotencia como credencial de acceso. Las recomendaciones MCP prohíben utilizar sesiones como autenticación. [MCP security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices). No se propone aquí un servidor MCP HTTP remoto adicional; si se adopta, requiere un perfil propio conforme a su autorización y transportes, no asumir que el canal interno lo cubre automáticamente.

## 5. Autorización por operación

El módulo de autorización recibe identidad **verificada del canal**, operación e inputs validados; nunca confía en un `agent_id`/rol del cuerpo para determinar al solicitante.

| Operación lógica | Verificación requerida |
|---|---|
| `GetCapabilities` | Agente activo; no revelar configuración humana ni declarar integraciones sin evidencia. |
| `DiscoverCredentials` | Agente activo; solo metadatos del conjunto común. Suspender usos no revela otros elementos ni otorga administración. |
| `StartAuthentication` | Agente activo, custodia disponible, no suspensión, credencial habilitada, ID/destino/método válidos e idempotencia. |
| `GetAuthentication` / `CancelAuthentication` | Agente activo propietario del intento; conocer el ID no basta. Compartir credenciales no comparte resultados de intentos. |
| Operaciones humanas | Solo canal y contexto humanos válidos. Nunca elevar un canal delegado por tener la TUI abierta. |

**Suspensión:** bloquea nuevos usos sensibles, no la consulta/cancelación de los intentos propios por un agente todavía registrado. **Revocación:** retira toda operación delegada de esa identidad; el humano conserva administración de sus pendientes y auditoría. Esta propuesta concreta [R06/R12 y API §7](../../.scratch/passwordmanager/spec.md).

La ejecución humana autoriza comandos administrativos concretos, ligados a bóveda, operación, contenido, estado esperado y una solicitud local de un solo uso. El motor verifica autoridad y no acepta un replay de un comando antiguo. La ejecución humana bloqueada no puede emitir nuevas autorizaciones; comandos ya confirmados pueden completar su transacción atómica, no convierten el bloqueo en revocación retroactiva. Comando humano local: CBOR `{v:1,vault,challenge,expected_state,operation,body_hash,expires_at}` firmado bajo dominio `pm/human-command/v1`. Challenge aleatorio de 32 bytes emitido por canal humano, vida 60 s; ligado a conexión/UID o SID, operación y hash del cuerpo. Consumo persistido atómico con transacción, nunca reutilizable. Antes de desbloquear, el peer humano solo puede leer sobres cifrados necesarios, no obtener secretos; las mutaciones exigen SK_H. §9 y G5 concretan referencias de estado y contenido de eventos; no crear un bearer humano reutilizable disponible al agente.

### Intentos e idempotencia

- Vincular el intento a bóveda, custodio ejecutor, agente/generación, credencial/revisión y contexto de destino. No se migra automáticamente a otro ejecutor tras un fallo.
- Alcance de idempotencia: bóveda + custodio + identidad/generación + clave del cliente. Misma clave y mismos inputs normalizados devuelve el intento existente; inputs distintos se rechazan. Generar otra clave no hace seguro repetir un login indeterminado.
- Tras reconectar, autenticar de nuevo y comprobar autoridad antes de consultar o repetir. Resultados conservados siguen bajo las mismas comprobaciones; la idempotencia no salta una revocación.
- §7 fija admisión temporal y retención: una clave olvidada que ya venció nunca se admite como una solicitud nueva.
- No aceptar `resume` del agente como prueba de resolución humana. La integración verifica resolución y autorización actual. No repetir ciegamente ante desconexión o reinicio.

Son restricciones del [modelo de intentos existente](../../.scratch/passwordmanager/spec.md), no nuevas herramientas de negocio.

## 6. Revocación, carreras y errores

Estados seleccionados de registro: pendiente, activo, revocado o alta vencida. La revocación de una generación es terminal; reautorizar requiere una acción humana nueva, no restaurar un backup ni reenviar el alta original. Una sustitución define expresamente qué ocurre con pendientes y auditoría de la generación anterior.

Aplicar revocación/suspensión/deshabilitación y la autorización del próximo uso en un orden serializado localmente. Invalidar conexiones/cachés y volver a comprobar al ejecutar, no únicamente al conectar. La integración no recibe un permiso ilimitado para seguir utilizando el secreto después de esa comprobación: cada nuevo uso sensible entra por el motor.

La garantía empieza en el punto de aceptación del uso: si la retirada se confirma antes, el uso no se autoriza; si el secreto ya fue utilizado/transmitido, no se puede retirarlo del proveedor. Minimizar la ventana y documentar su punto exacto por integración; no prometer cancelación externa atómica. Una revocación remota desconocida offline conserva el límite aprobado de última autoridad conocida. [R13–R16](../../.scratch/passwordmanager/spec.md).

Antes de verificar identidad, fallo genérico sin enumerar agentes/bóvedas. Para identidad probada pero revocada puede devolverse `AGENT_REVOKED` sin datos de credenciales. Un intento ajeno y uno inexistente deben ser indistinguibles para el solicitante. Errores de versión, identidad o integridad no permiten fallback a acceso anónimo, bearer compartido o exportación de secreto. §7 fija los errores del núcleo y su envoltura pública.

## 7. Wire/CLI/MCP v1

**Decisión de ingeniería:** un núcleo RPC pequeño compartido por CLI/MCP, no dos APIs de negocio ni un endpoint genérico de lectura de secretos. Alternativas descartadas: duplicar lógica dentro de herramientas MCP y exponer toda la API humana con flags de rol. Lo siguiente fija núcleo y límites; los [contratos G3](../research/g3-authentication-integrations.md#resolución-de-b1b4--cierre-documental-de-g3) fijan contextos/resultados Keycloak, SSH/sistemas, passkeys y bearer por petición, sin `payload` arbitrario sin validar.

### Framing y tipos

- Motor: JSON-RPC 2.0, UTF-8, un frame de `u32` big-endian + documento JSON por mensaje TLS. Máximo 1 MiB/frame, profundidad 16, sin batch ni notificaciones para operaciones de dominio. IDs de request: strings 1–64 ASCII; params siempre objeto. Rechazar claves duplicadas, desconocidas, no-finitos y trailing bytes. El framing es **propio**, no confundir con stdio MCP. [JSON-RPC](https://www.jsonrpc.org/specification).
- Primer request `pm.v1.hello` con `{protocol:1,vault_id}`; respuesta `{protocol:1,custodian_id,agent_id,generation,server_time}`. IDs/gen del cliente no otorgan identidad: se obtienen del canal. En alta pendiente, hello activa atómicamente solo la concesión pública previamente instalada; no hay método remoto para crear concesiones. Versión desconocida cierra la conexión tras `UNSUPPORTED_VERSION`.
- UUID lógico = 16 bytes representados en **32 hex minúsculas**; generación uint64 y timestamp int64 microsegundos como strings decimales canónicas en JSON, nunca float. No usar JSON serializado directamente como material firmado: convertir al esquema CBOR de [formato v1](key-hierarchy.md).
- Timeout de handshake/hello: 10 s cada uno; frame incompleto: 10 s; conexión ociosa: 5 min. Cerrar conexión no cancela un intento aceptado. `Start` confirma persistencia antes de ejecución externa; no mantiene RPC bloqueado hasta login. Máximo 16 requests pendientes/conexión, 4 conexiones/agente, 16 intentos no terminales/agente y 128/custodio; cola llena rechaza, no elimina pendientes ajenos. Son límites de protección, no permisos sobre acciones externas. Datos de resultado de integración hasta 64 KiB; capacidad/página hasta 512 KiB. Datos mayores requieren un mecanismo tipado G3, no frames sin límite ni truncado silencioso.

### Operaciones y salidas

| Método RPC | Campos de params | Resultado |
|---|---|---|
| `pm.v1.capabilities` | `{}` | `{protocol, integrations:[{id,version,methods,availability,input_schema,result_schema}],limits}`; solo integraciones verificadas, schema cerrado/versionado, sin config privada. |
| `pm.v1.credentials.discover` | `filter?` con `text?` (0–256 bytes), `type?`; `limit?` (1–100, default 50); `cursor?` (hasta 512 bytes). | `{credentials:[{id,title,type,destination,account,integrations}],next_cursor}`; cada campo textual hasta 4096 bytes; valores mayores se omiten con indicador, no se truncan destinos para autenticar. Página limitada además a 512 KiB, deteniéndose antes del siguiente elemento; cursor autenticado, ligado al agente/filtro y 5 min de validez; selección siempre por ID. |
| `pm.v1.authentication.start` | `credential_id,integration_id,integration_version,method,destination,context,idempotency_key`. | Snapshot de intento. `context` ≤64 KiB y **solo esquema cerrado de integración anunciada**; sin ruta de archivo ejecutable/comando/headers arbitrarios por defecto. Destino debe coincidir con contexto autenticado, no una URL libre que permita reflejar secretos. |
| `pm.v1.authentication.get` | `attempt_id` | Snapshot del intento propio. |
| `pm.v1.authentication.cancel` | `attempt_id` | Snapshot tras cancelación local; estado ya terminal no cambia, ni produce logout externo. |

Snapshot: `{attempt_id,credential_id,revision_id,integration_id,integration_version,state,created_at,expires_at,reason,result}`. `reason` es código público fijo o null, no mensaje libre del proveedor. `result` es null o un objeto validado por `result_schema` anunciado. No se permite reflection crudo de respuesta, DOM, stdout ni headers del proveedor. `WAITING_FOR_HUMAN` devuelve contexto mínimo y referencia local de pendiente, no un factor/URL secreta hacia el agente. `SUCCEEDED` exige evidencia definida por integración; firma SSH sola no acredita login. Resultados de sesión externa solo cuando G3 demuestra transferencia sin devolver secreto original; no gestionar su vida posterior.

CLI delegado: nombre de trabajo `pm` (no reserva marca), subcomandos `capabilities`, `credentials list`, `auth start`, `auth status`, `auth cancel`, `mcp`. `--json` emite un único resultado JSON con el esquema anterior; diagnóstico de códigos sin secretos en stderr; exit 0 = RPC aceptado/estado consultado, 2 = argumentos, 3 = autoridad, 4 = transporte/custodia, 5 = fallo de dominio. Exit 0 en `Start` **no significa login completado**. Inputs de contexto por stdin/documento referenciado, nunca secretos como argumentos. TUI por `pm tui` exclusivamente en entorno humano; ejecutar ese subcomando en agente no autoriza acceso.

MCP stdio 2025-11-25 mantiene sus reglas de framing y IDs, **no** hereda el prefijo binario/ID string-only del RPC privado: `initialize`, negociación de versión/capabilities y ciclo de vida estándar; publicar cinco tools `get_capabilities`, `discover_credentials`, `start_authentication`, `get_authentication`, `cancel_authentication`, mapeadas uno a uno. `inputSchema`/`outputSchema` cerrados y resultado estructurado consistente con CLI (y el mismo JSON en TextContent por compatibilidad); errores de tool con `isError`, errores de protocolo como JSON-RPC. Nada de logs en stdout. No publicar resources/prompts de bóveda ni herramientas administrativas. [Transportes](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

### Contraste con integraciones concretas

| Caso documentado | Consecuencia para este contrato, no integración certificada |
|---|---|
| OpenSSH `ssh-agent` + `session-bind` | Retornar firma no acredita aceptación por servidor. `StartAuthentication` no publica éxito por `SSH_AGENT_SIGN_RESPONSE`; G3 necesita cliente/contexto confiable con evidencia de login. [Protocolo OpenSSH](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.agent), [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html). |
| Campo password HTML en navegador controlado por CDP del agente | No pasar identidad/password al DOM agente. Un endpoint/handshake bien cifrado no arregla ese canal de salida; G3 debe resolver contexto confiable y transferencia limpia o declarar ese flujo incompatible. [HTML password](https://html.spec.whatwg.org/multipage/input.html#password-state-(type=password)), [CDP Runtime.evaluate](https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-evaluate). |
| WebAuthn con presencia/verificación requerida | Pausar ese intento, no fabricar UP/UV ni aceptar `resume=true` como evidencia humana. [WebAuthn](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion). |
| Windows `LogonUserW` | Plaintext se usa solo dentro de integración confiable; no devolverlo a la herramienta. Un token/handle local exige handoff nativo tipado G3, no convertir un número de handle en resultado portable ni afirmar login remoto. [API Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw). |

Estos casos justifican esquema cerrado, evidencia de resultado y límites por integración. **Actualización G3:** [resolución B1–B4](../research/g3-authentication-integrations.md#resolución-de-b1b4--cierre-documental-de-g3) cierra documentalmente los perfiles; `LogonUser`/Authorization Services genéricos quedan como alternativas no seleccionadas, no requisitos locales pendientes.

Resultados cerrados: `oidc_tokens` para Keycloak/password/TOTP/passkey y exchange según cada perfil; `ssh_authenticated_connection` con `consumer_ref` ligado al cliente confiable dueño del transporte para SSH/cuentas nativas; `authenticated_http_response` tipado para GitHub PAT por petición. Los campos y límites son los de la nota G3, bajo el límite de 64 KiB del wire; no hay resultado genérico para devolver contenido sin validar. El motor no incorpora operaciones de canales SSH ni administración de sesiones. La extensión comunica internamente con el custodio: no se añaden herramientas MCP para firmar bytes o crear passkeys desde agente. `GetCapabilities` no anuncia un perfil operativo solo porque su diseño esté cerrado; exige implementación y evidencia del entorno. P1–P5 siguen sin ejecutar.

### Alta, plazos y no repetición

Solicitud pública: CBOR `{v:1,request_id,agent_spki,agent_label,environment_label}`; labels ≤256 bytes, nunca autoridad. Aprobación firmada por SK_H con dominio `pm/enroll/v1`: añade vault, custodian, subject_id, generación, hash SPKI de servidor, emisión/vencimiento y request_id. **Caduca en 24 horas antes de activación**; el custodio conserva el registro consumido mientras exista esa generación. Clave/entorno se verifican por canal confiable según §3. No renovar alta activa por reloj.

Intentos: ventana máxima 24 h desde aceptación; timeout de ejecución externa inicial 120 s salvo plazo más corto del proveedor. Si surge desafío humano, se pausa inmediatamente y su validez termina en el menor entre expiración del proveedor y ventana del intento; no consumir tiempo de espera como permiso de retries. Al vencer ejecución sin evidencia: `INDETERMINATE`, no `FAILED` artificial. Consulta/reconciliación puede confirmar efecto ya ocurrido, pero no emitir nueva autenticación. La pérdida de material externo irrecuperable tras reboot se informa indeterminada, no se vuelve a ingresar la contraseña.

Clave idempotente: `{issued_at,nonce}` con timestamp UTC y 16 bytes aleatorios. Alcance vault/custodian/agent/generación. Solo claves nuevas emitidas entre `now-600 s` y `now+120 s`; primero buscar coincidencia persistida y comparar el hash de params tipados (excluido request_id RPC). Misma clave/inputs: mismo intento, sujeto a autorización actual; distintos: `IDEMPOTENCY_CONFLICT`. Commit del índice y del intento antes del uso del secreto.

Retener snapshot y resultado cifrado mientras intento siga abierto y 24 h tras terminar; después conservar únicamente índice mínimo/hash de inputs/ID y estado terminal hasta 7 días tras terminar; consulta de resultado retirado devuelve `RESULT_EXPIRED`, nunca una ejecución nueva. Pasado ese plazo puede eliminarse índice: su clave ya está fuera de admisión. No es política de historial/auditoría de bóveda, que se resuelve en G5/G7. Reloj local que retrocede respecto al máximo persistido: denegar **nuevas admisiones** con `CLOCK_UNTRUSTED` hasta corregirse; no ampliar altas/plazos y no alterar LWW. Tras rollback integral del host persiste el límite G5: sin evidencia externa no se prueba actualidad. Los plazos son defaults de ingeniería documentados, revisables antes de publicar, no aprobación atribuida al usuario.

### Errores y revocación

Conservar categorías §7.3 de spec; añadir `INVALID_ARGUMENT`, `UNSUPPORTED_VERSION`, `NOT_FOUND`, `IDEMPOTENCY_CONFLICT`, `IDEMPOTENCY_EXPIRED`, `RESULT_EXPIRED`, `RATE_LIMITED`, `CLOCK_UNTRUSTED`, `INTERNAL_ERROR`. Envelope JSON-RPC: error estándar de parse/protocolo según JSON-RPC; dominio `code:-32000`, `message` fijo igual a categoría, `data:{category,retryable,retry_after_ms?}`. Nunca payload upstream/stacktrace. `retryable` solo permite repetir **el mismo request con su idempotencia**, no otro login tras resultado indeterminado.

Un ID de intento inexistente o ajeno produce el mismo `NOT_FOUND`. Clave revocada puede rechazarse en handshake con error de transporte genérico; `AGENT_REVOKED` solo después de identificarla sin revelar datos. Al aplicar revocación invalidar conexiones y no reanudar pendientes; la custodia conserva reconciliación humana del resultado, no transfiere automáticamente ownership. Errores de importación pertenecen al canal humano, no son nuevas herramientas de agente.

## 8. Evidencia pendiente


La [propuesta de sincronización](synchronization.md) desarrolla precedencia de retiradas, generaciones y límites offline. Su §9 fija formato/reductor; faltan pruebas, no sustituye verificación por operación.

1. Sustituir pública, bóveda o custodio en el alta; robar/repetir solicitud aprobada sin privada: no activar identidad ajena. Probar aprobación expirada y pérdida de respuesta tras activación.
2. Presentar X.509 donde se exige RPK, firma/transcript inválidos o clave de otro agente: rechazo. Probar ausencia de resumption, continuidad de identidad sin certificados y rotación no aprobada.
3. Invocar API humana desde canal delegado con TUI bloqueada y desbloqueada; falsificar rol/ID, compartir IDs de intentos y claves de idempotencia: denegación sin fugas.
4. Revocar con conexión abierta, solicitud en cola y desafío humano pendiente; no nuevos usos ni reanudaciones inválidas. Probar orden de carreras real en cada integración.
5. Reboot con humano bloqueado: agente autorizado reconecta sin contraseña maestra, conserva identidad y sigue sujeto a suspensión. Perder privada no ofrece bypass.
6. Probar robo de claves entre agentes dentro del perfil de aislamiento, parser/inputs hostiles, reloj erróneo, DoS acotado y ausencia de privados/secretos en todos los diagnósticos.
7. Demostrar consistencia CLI/MCP y probar desconexión/idempotencia sin login duplicado ciego; conservar la separación entre firma SSH y login realmente confirmado.

**Núcleo de G4 seleccionado:** wire/CLI/MCP, errores, bootstrap, RPK, sustitución, plazos e idempotencia. Eventos/comandos distribuidos se completan en §9 y G5; los contratos G3 están definidos; no son razón para reabrir TLS o herramientas lógicas. Pruebas anteriores no ejecutadas. No se implementa, crean tickets ni declara preparación para producción.

## 9. Cierre de comandos humanos y autoridad distribuida

**Selección de ingeniería G4 completa documentalmente.** El wire y las cinco operaciones delegadas permanecen iguales. [G5 §9](synchronization.md#9-contrato-g5-seleccionado--cierre-documental) define los eventos/cortes/raíces, [G6](../research/credential-migration.md) los objetos importables y [G7](security-operations.md) los controles; no son nuevas herramientas de agentes.

### Transacción humana local

- `expected_state=SHA256(CBOR(['pm/state-view/v1',vault,authority_epoch,sorted_valid_heads]))`, donde heads son digests G5 de la vista sobre la que el humano confirma. Identifica conocimiento local, no actualidad global. Cualquier cambio de esa vista antes del commit devuelve `STATE_CHANGED`; regenerar preview/challenge y confirmar sobre estado nuevo, nunca sobrescribir con autorización vieja.
- `body_hash=SHA256(CBOR(body))`; `body={transaction_id,events_manifest_digest,event_count,object_manifest_digest,local_effect}`. El manifiesto de eventos pagina la lista ordenada de sobres S de G5 (incluidas firmas), con partes ≤256KiB, hashes y event_count exacto; cero eventos usa digest null. Verificar todo el staging antes del único commit, sin enviar todos los eventos inline; `object_manifest_digest` referencia staging cifrado de las partes/revisiones o null si no hay contenido. Transaction_id ID16 aleatorio; mismo ID/cuerpo aceptado devuelve recibo existente y no repite efecto. Body ≤256 KiB; manifiestos paginados de eventos y objetos G5/G6 vinculan lotes grandes sin ensanchar el RPC ni activar fragments. Challenge local60s y su firma siguen §5.
- Método humano `pm.v1.human.prepare{operation,body_hash,expected_state}`: devuelve challenge/expiry después de verificar peer humano. `pm.v1.human.commit{command,signature,body}` valida conexión, challenge, raíz fijada, hashes, estado y firmas; confirma un único commit durable de eventos/partes/consumo de challenge/outbox/auditoría. `pm.v1.human.receipt{transaction_id}` consulta recibo en canal humano; no vuelve a ejecutar. Preparar no habilita nada ni emite SK_H. Se puede preparar desde contexto humano válido, pero commit exige firma después de desbloqueo.
- Operación enum `item_write,availability_change,identity_change,item_lifecycle,import_commit,restore_commit,root_transition,audit_purge`; tipos de eventos permitidos por cada operación se corresponden a G5 (no operación string arbitraria). Reveal/copy/export/backup siguen autoridad humana y controles G6/G7, sin transformarlos en mutaciones de autoridad distribuida. Prohibir body con eventos de otra clase: item_write/item-revision; availability_change/enable,disable,suspend,resume; identity_change/device-grant,agent-grant,agent-revoke,device-retire; item_lifecycle/trash,restore,purge-item,purge-revisions; import/restore_commit/item-revision y disable/trash expresamente previsualizados; root_transition/root-transition. Audit_purge usa events_manifest_digest null/event_count=0, object_manifest_digest null y local_effect `{kind:audit_purge,device,audit_generation,through_seq,expected_audit_head}`; verificar cabeza actual y G7 antes del commit. Para las demás operaciones local_effect=null; no un comando libre ni purga implícita por retención.
- El motor no firma actos humanos por tener SK_SD ni acepta una firma de dispositivo como firma SK_H. SK_SD autentica procedencia/sync/audit; la raíz humana firmó contenido y autoridad previamente. Reducir retiradas y reservar el uso sensible comparten orden transaccional local; una conexión abierta no queda autorizada para siempre.
- Recibos humanos mínimos `{transaction_id,body_hash,committed_heads,committed_at,outcome}` se conservan junto con headers de eventos; sin secretos ni cuerpo completo en auditoría. Repetir commit con challenge consumido no autoriza un nuevo acto: identidad humana + mismo transaction_id/hash devuelve recibo. Distintos devuelve `TRANSACTION_CONFLICT`. Un recibo de importación no equivale a éxito de autenticación externa.

Canal sync usa ALPN `pm-sync/1`, solo rol de transporte de dispositivo explícitamente registrado; métodos cerrados de G5, ningún agente puede invocarlos mediante ALPN/rol aportado en JSON. Canal de consumidores confiables usa ALPN `pm-integration/1`, peer/pin técnico y asociación de intento G3, no firma general ni operaciones humanas. Donde interfaz nativa de consumidor SSH usa pipe/socket, la identidad de aplicación consumidora se vincula a la identidad agente que inició el intento; conocer consumer_ref no la sustituye.

Antes del desbloqueo humano se permite leer solo bootstrap/sobres cifrados y estado público mínimo necesario. No publicar un `get_secret` remoto ni elevar rol al agente. El motor humano comparte código de dominio con TUI/CLI; no se crea segunda implementación de política.

**Estado:** formato de comando, estado esperado, transacción, roles y eventos concretados. Dependencias G2/G3/G5/G6 resueltas documentalmente. Permanecen los tests de §8 y V03–V05/V10–V12/V22/V25; no hay implementación ni permiso para ejecutarla por completar este contrato.
