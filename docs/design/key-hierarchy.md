# Jerarquía de claves y formato criptográfico v1

Fecha: 2026-09-12. Estado: **selección de ingeniería para la especificación**, por continuación de diseño solicitada; no aprobación explícita del usuario de algoritmos ni formato certificado. G2 cerrado documentalmente con composición, schemas G6 y autoridad G5 en §9. Sin implementación, vectores ejecutados ni revisión criptográfica independiente.

Autoridad: [contrato funcional](../../.scratch/passwordmanager/spec.md), [glosario](../../CONTEXT.md) y [aislamiento seleccionado](isolation.md). Esta nota concreta responsabilidades y transiciones; no convierte una composición de primitivas en un protocolo ya validado.

## 1. Recomendación y alternativas

**Elección de esta iteración:** una raíz humana para acceso completo; claves independientes para contenido humano y material autenticable; sobres de delegación dirigidos a cada dispositivo custodio; y una vía externa de recuperación. Ninguna clave de contenido llega al agente.

| Alternativa | Ventaja | Problema | Selección |
|---|---|---|---|
| Una clave raíz permanente en el custodio delegado | Menos sobres y sincronización sencilla. | El proceso desatendido puede abrir toda la bóveda, aunque solo necesite lo habilitado. | Descartar. |
| Una clave compartida para todo el conjunto delegado | Modelo simple. | Altas/bajas y material histórico quedan demasiado acoplados a una sola clave. | No preferida. |
| Claves por revisión y sobres por dispositivo | Separa contenido humano, delegación y recuperación; limita el material provisionado. | Más metadata, transacciones y reglas de actualización. No revoca copias antiguas mágicamente. | Seleccionada; composición por revisar. |

Es una elección de ingeniería sobre el patrón documentado de [cifrado por envolturas](https://docs.cloud.google.com/kms/docs/envelope-encryption), no uso de un servicio cloud. Las diferencias son consecuencias de las alternativas, no resultados de un benchmark.

## 2. Inventario de claves

Los símbolos identifican propósitos; §7 fija tamaños y primitivas. Se generan claves aleatorias independientes; nunca reutilizar una clave de cifrado como clave de firma.

| Símbolo | Función | Dónde puede estar en claro |
|---|---|---|
| `K_P` | Derivada de la contraseña maestra; abre el sobre de la raíz humana. | Ejecución humana confiable durante desbloqueo; descartar al completar. |
| `K_H` | Raíz humana aleatoria; abre las claves de todo el contenido y la autoridad humana. | Ejecución humana desbloqueada, no custodia delegada desatendida. |
| `K_R` | Clave aleatoria externa de recuperación; abre un segundo sobre de `K_H`. | Creación/recuperación explícita en entorno humano; fuera del equipo en reposo. |
| `K_C[r]` | Cifra contenido humano de una revisión: notas, campos privados y referencias protegidas. | Ejecución humana mientras se utiliza esa revisión. |
| `K_A[r]` | Cifra exclusivamente material autenticable de una revisión y su contexto necesario. | Ejecución humana o módulo custodio/adaptador confiable durante uso autorizado. |
| `K_F[f]` | Cifra un archivo o flujo de backup, separado de credenciales. | Operación humana correspondiente; no se delega al agente. |
| `SK_D / PK_D` | Par de claves de envoltura del dispositivo custodio: recibe sobres de `K_A[r]`. | Privada protegida en custodia nativa; pública distribuible mediante registro autenticado. |
| `SK_H / PK_H` | Autoridad humana para acreditar cambios de disponibilidad y provisión de claves. | Privada protegida bajo `K_H`, solo disponible en ejecución humana desbloqueada. |
| Identidad de agente | Acredita al cliente ante el motor, separada de las anteriores. | Entorno de ese agente, conforme al diseño G4. No descifra la bóveda. |

La cadena de confianza de sincronización, emparejamiento y rotación de `PK_H` está definida en G4/G5 y §9. No aceptar una clave pública nueva porque venga incluida junto con su propia firma.

```text
contraseña -- KDF --> K_P -- abre sobre --> K_H
clave externa K_R -------- abre sobre ----> K_H
                                             |
                          +------------------+-------------------+
                          |                  |                   |
                       K_C[r]             K_A[r]              K_F[f]
                       humano          autenticación       archivos/backup
                                             |
                    sobre adicional para PK_D, solo si está habilitada
                                             |
                                 SK_D en custodio aislado
                                             |
                                adaptador utiliza el secreto
                                             |
                          agente recibe solo resultado permitido
```

Las flechas significan apertura de sobres, no entrega al agente ni derivación de todas las claves desde su identidad.

## 3. Separación humana y delegada en el motor

**Realización seleccionada:** ejecutar las operaciones que manejan `K_H` en un contexto humano temporal aislado del agente y distinto del proceso delegado persistente. Ambos usan el mismo módulo de dominio del motor; la TUI no implementa otra política criptográfica. El almacenamiento puede seguir teniendo un único escritor custodio, que recibe transacciones cifradas y autorizadas sin necesitar `K_H`.

Así, bloquear implica cerrar acceso humano y limpiar/terminar ese contexto y sus claves transitorias. El proceso delegado conserva `SK_D` o una vía nativa para utilizarla. No afirmar borrado perfecto: copias de memoria, dumps, swap, buffers y errores necesitan tratamiento verificable. [Límites y API de memoria de libsodium](https://doc.libsodium.org/memory_management).

Una revisión lógica vincula sus partes mediante IDs y referencias de integridad autenticados: el motor no mezcla una contraseña de una revisión con el destino de otra. `K_A[r]` no abre `K_C[r]`, adjuntos ni otras revisiones. Su contenido comprende solo lo imprescindible para autenticar; los metadatos que ve el agente siguen limitados al conjunto común. Esto concreta [R07–R09 y revisión completa LWW](../../.scratch/passwordmanager/spec.md), no crea un segundo elemento funcional.

## 4. Habilitación y actualización sin desbloquear otros equipos

1. El humano desbloqueado elige una credencial y confirma su incorporación al conjunto común.
2. La ejecución humana prepara sobres de `K_A[r]` para los dispositivos custodios autorizados que conoce, utilizando sus **claves públicas autenticadas**. No necesita sus claves privadas.
3. La concesión vincula bóveda, elemento, revisión, destinatario, generación de autorización, contexto de uso y sobre cifrado. Se acredita con autoridad humana. Codificación y firma se fijan en §7; la precedencia distribuida de autoridad permanece en G5.
4. El custodio verifica autoridad, destinatario, integridad y estado vigente antes de activar el sobre. Poder descifrar no equivale a tener permiso de usar.
5. Al editar una credencial habilitada, la ejecución humana crea claves nuevas para la nueva revisión y sus sobres delegados en la misma transacción lógica. Un custodio que recibe todo puede aplicar el cambio con su TUI bloqueada. Un receptor con datos incompletos no publica una revisión parcialmente utilizable ni recurre a otra contraseña.

El cifrado asimétrico permite esta provisión con claves públicas, pero una sealed box por sí sola **no identifica al remitente**. La autenticidad humana y la vinculación al estado no son opcionales. §7 fija la composición que debe someterse a revisión independiente; no se presenta como protocolo criptográfico auditado. [Libsodium sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).

Los sobres por dispositivo son copias técnicas del **mismo conjunto común**, no permisos distintos por agente o proyecto. Dispositivos desconectados aplican el último estado conocido. Un dispositivo nuevo requiere emparejamiento humano y provisión de lo habilitado; el servidor no le genera acceso.

Un intento ya iniciado puede retener su revisión mientras sea válido, según la especificación; eso no concede al agente navegación libre del historial. Terminar, cancelar o invalidar el intento libera su material. Los plazos del núcleo se fijan en [identidad §7](agent-identity.md); G3 fija persistencia del desafío por integración.

## 5. Transiciones que debe cubrir el diseño

| Acción | Efecto propuesto sobre claves y autoridad |
|---|---|
| Crear/importar elemento | Generar claves y sobres humanos; no crear delegación automáticamente. |
| Bloquear la TUI | Retirar acceso a `K_H`, `SK_H` y claves humanas transitorias. Mantener la vía delegada y autorización previamente habilitada. |
| Suspender agentes | Persistir estado de suspensión y denegar nuevos usos; conservar sobres para poder reanudar sin reintroducir todas las credenciales. Limpiar claves de trabajo que ya no sean necesarias. |
| Deshabilitar credencial | Registrar retirada autorizada, impedir nuevos usos y reanudaciones inválidas; eliminar sobres activos/cachés delegados de esa credencial localmente. Conservar historial humano cifrado. |
| Revocar agente | Invalidar su identidad; no rotar todas las claves de contenido ni afectar a otros agentes. No tenía claves de contenido. |
| Cambiar contraseña maestra | Nueva derivación y sobre de `K_H`, confirmación/transacción recuperable. No exige recifrar cada elemento si no existe sospecha de compromiso. |
| Reiniciar | La custodia nativa recupera uso de `SK_D` y estado autorizado sin contraseña maestra. Si esa vía no está disponible, informar indisponibilidad; no abrir la vía humana automáticamente. |
| Rotar clave de dispositivo | Preparar nueva clave y sobres para el mismo conjunto, validar transición y retirar la anterior. No requerir ni entregar `K_H` al proceso delegado. |
| Retirar dispositivo | Dejar de enviarle nuevas concesiones/sobres y aplicar retirada al conocerla. No borrar a distancia secretos o claves que ya pudo conservar. |
| Restaurar revisión anterior | Crear revisión nueva con claves nuevas; actualizar delegación si sigue habilitada, sin reactivar identidades revocadas. |
| Eliminar/purgar | Retirar disponibilidad y aplicar retención; no prometer eliminación física de backups, snapshots o equipos desconectados. |

Estas son transiciones seleccionadas para realizar [R04–R18](../../.scratch/passwordmanager/spec.md), no código ni una modificación de sus garantías offline.

### Límite importante: retirar permiso no borra el pasado

La separación criptográfica excluye contenido **nunca delegado**. Un custodio que conserva su clave privada y un sobre antiguo puede técnicamente abrir el material que recibió antes. El producto impide el uso mediante su estado vigente y elimina copias activas cuando corresponde; no puede hacer desaparecer snapshots o secretos ya conocidos.

Por ello, «solo abre lo habilitado» significa material provisionado más control vigente dentro del custodio confiable, no revocación retroactiva demostrada por criptografía. Reenviar una concesión antigua no debe reactivarla: se necesita estado antirreplay autenticado. Restaurar simultáneamente datos y toda memoria local de revocaciones no permite detectar por sí solo que existe una versión posterior; G5/G7 debe fijar qué evidencia adicional hay y qué límite se comunica. [AEAD no define antirreplay, RFC 5116 §1.2](https://www.rfc-editor.org/rfc/rfc5116.html#section-1.2).

Cambiar contraseña o reenvolver claves tampoco invalida un backup anterior. Si se compromete `K_H` o una clave de datos, la respuesta requiere claves nuevas y recifrado del contenido afectado para proteger copias futuras, además de revisar autoridad. Eso no cambia contraseñas externas ni recupera la confidencialidad de datos ya copiados. [Base de envolturas](https://docs.cloud.google.com/kms/docs/envelope-encryption), [límites del contrato](../../.scratch/passwordmanager/spec.md).

## 6. Recuperación y backups

**Propuesta:** backup lógico completo producido por una operación humana autenticada: incluye contenido, organización, historial, adjuntos y un manifiesto protegido que los vincula. Usa una clave de backup independiente, accesible mediante `K_H`; incluye los sobres de `K_H` para vía humana y `K_R`. No incluye en claro `K_R` ni claves privadas nativas de dispositivo o de agentes.

Recuperación: introducir `K_R` en entorno humano confiable, abrir `K_H`, validar manifiesto y contenido completo en destino separado y solo entonces confirmar restauración. Recuperar datos no concede automáticamente autoridad operativa a clientes del equipo nuevo. Si se conserva autoridad humana histórica cifrada, su activación exige un flujo explícito de recuperación y reconciliación; no restaurar agentes como activos por copiar su metadata.

**Ciclo de `K_R`:** crear y verificar su copia externa inicialmente; descartar su valor local tras la operación. Backups posteriores pueden reutilizar el sobre existente de `K_H` sin conocer `K_R`. Si cambia `K_H`, exigir al humano la clave de recuperación existente para generar el nuevo sobre o generar/verificar una nueva clave de recuperación. No anunciar un backup recuperable con una vía que no se ha actualizado. Conservar claramente qué generación de clave abre cada backup.

Un backup antiguo válido no prueba que sea el más reciente ni acredita revocaciones posteriores. La reconciliación con dispositivos existentes sigue G5/G6. La recuperación debe funcionar sin el keyring del equipo perdido; si no quedan claves/vías válidas y copia utilizable, no hay bypass. [Contrato de backup y recuperación, §11](../../.scratch/passwordmanager/spec.md).

## 7. Formato v1 seleccionado

**Decisión de ingeniería, no resultado de pruebas.** Se elige una sola suite, no negociación de algoritmos controlada por el archivo. Se descartan AES-GCM como segunda suite inicial (duplicaría caminos de nonce) y una raíz permanente en el custodio (ampliaría lo descifrable). La interoperabilidad se define por bytes y vectores públicos, no por compartir SQLite ni ABI Rust.

### 7.1 Biblioteca y primitivas

- **libsodium 1.0.22**, distribución oficial verificada; binding **libsodium-sys-stable 1.24.0**, encapsulado en un módulo de seguridad con interfaz tipada. No exponer FFI, buffers ni primitivas crudas al dominio/TUI. La revisión de `unsafe`, limpieza y tamaños del módulo es un requisito de seguridad, no seguridad automática por escribir Rust. [Release](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE), [binding y configuración](https://docs.rs/crate/libsodium-sys-stable/1.24.0).
- **Argon2id v1.3** (`crypto_pwhash_argon2id`, algoritmo explícito), salida 32 bytes, salt aleatorio 16 bytes, `p=1`. Perfil de creación: memoria 256 MiB, tres pasadas; no autotuning silencioso. El formato acepta memoria 64–1024 MiB, múltiplo de MiB, y 3–10 pasadas; crear por debajo del perfil requiere confirmación humana informada. Rechazar antes de reservar memoria lo que exceda límites. Una derivación humana a la vez; error de recursos no reduce parámetros. Medir latencia de este perfil en los seis targets, no afirmar que tarda un segundo. Contraseña: bytes UTF-8 exactos, sin trim/normalización, 1–1024 bytes. No guardar verificador además del sobre. El `p=1` está comprobado en [código 1.0.22](https://raw.githubusercontent.com/jedisct1/libsodium/1.0.22/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c); no es el perfil `p=4` de [RFC 9106 §4](https://www.rfc-editor.org/rfc/rfc9106.html#section-4).
- **XChaCha20-Poly1305-IETF** para contenido y sobres simétricos: clave 32 bytes, nonce aleatorio 24 bytes, tag 16 bytes. `K_H`, `K_R`, `K_C`, `K_A`, `K_F` son aleatorias e independientes de 32 bytes. Nonce nuevo para cada escritura, incluso reenvoltura; un intento fallido no reutiliza nonce/ciphertext alterado. [Primitiva](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).
- Ed25519: pública 32 bytes, firma 64 bytes; custodiar seed privado de 32 bytes y expandir solo al usar. X25519 de dispositivo: privada/pública de 32 bytes. Estas claves son independientes de las simétricas; [API de firmas](https://doc.libsodium.org/public-key_cryptography/public-key_signatures) y [API de box](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption).
- **crypto_box_seal** para sobres a `PK_D` (X25519/XSalsa20-Poly1305 de libsodium); **Ed25519 detached** con `SK_H` para concesiones y objetos de autoridad humana. No convertir la clave de firma en clave X25519 ni reutilizar claves TLS. Firmar bytes completos con prefijo de dominio, no inventar `Ed25519(SHA256(payload))`. [Sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes), [firmas](https://doc.libsodium.org/public-key_cryptography/public-key_signatures).
- **secretstream_xchacha20poly1305** para archivos/backup: clave independiente, chunks plaintext de hasta 1 MiB, framing `u32` big-endian de longitud cifrada; último chunk con `TAG_FINAL`, incluso archivo vacío. Rechazar EOF prematuro, bytes posteriores al final y longitudes excesivas antes de asignar. No exponer archivo parcialmente validado como restaurado; no prometer acceso aleatorio. [Secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream).

### 7.2 Codificación y vinculación

Reglas normativas de v1 (notación descriptiva, **no implementación**):

1. Objetos autenticados: **CBOR determinista core RFC 8949 §4.2.1**, enteros en codificación mínima y longitudes definidas. Maps con claves textuales ASCII del esquema; prohibir claves duplicadas/desconocidas, floats, tags, valores `undefined`, trailing bytes y profundidad >16. Texto UTF-8 válido, sin normalizar secretos. ID de bóveda/objeto/revisión/dispositivo: 16 bytes aleatorios; generación: uint64; timestamp UTC: int64 microsegundos. Comparar IDs binarios, no representación textual. [Reglas de codificación](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1).
2. Cabecera `H = {v:1, suite:1, vault, object, revision, purpose, key_generation}`. `purpose` distingue `human-content`, `auth-payload`, `control`, `key-wrap`, `root-password`, `root-recovery` y `file`. Un sobre añade `recipient`, `wrapped_purpose` y referencia al objeto objetivo; raíz-password añade algoritmo/salt/memoria/pasadas/lanes. Encabezado completo en AAD: bytes CBOR de `['pm/aead/v1', H]`. Envelope: `{header:H, nonce, ciphertext}`; ciphertext incluye tag. Campos privados (título, cuenta, destino, campos libres) dentro del plaintext, no AAD.
3. Sobre simétrico: plaintext CBOR `{key, target_header}` bajo `K_H`, `K_P` o `K_R` según propósito. Comparar `target_header` con el objeto pretendido después de descifrar. La envoltura no permite intercambiar claves entre bóvedas/propósitos. Manifest de revisión humano cifrado vincula partes `K_C/K_A` mediante sus IDs y hashes SHA-256 de bytes cifrados completos; no publicar revisiones parciales.
4. Sobre delegado: sealed box de CBOR `{key:K_A, target_header, recipient, authorization_generation}`. Concesión humana `G = {v:1, vault, item, revision, recipient, authorization_generation, target_header, payload_sha256, sealed_box, authority_event}`. Firma Ed25519 de CBOR `['pm/grant/v1', G]`. Verificar firma con `PK_H` ya confiable y autoridad vigente **antes** de usar el sobre; comprobar todos los vínculos tras abrirlo. Nunca aceptar una clave humana incluida en el propio mensaje como raíz. La firma autentica emisor y sobre; la sealed box solo aporta confidencialidad.
5. Un paquete operativo completo (payload autenticable, concesión, metadatos mínimos necesarios) viaja dentro de un sobre de control cifrado; el servidor de sync solo necesita IDs opacos, tamaños y ciphertext. Evitar que la firma o `G` externa revele contexto de credenciales al servidor. SHA-256 identifica bytes, no sustituye firma/AEAD.
6. Mensaje de autoridad humana: firma Ed25519 sobre CBOR `['pm/human-event/v1', evento]`. El evento incluye vault, ID, sujeto, generación, operación y referencias de antecedentes. G5 fija el reductor y esquema completo de eventos; poder verificar la firma no autoriza cualquier transición.
7. Límite de objeto no-stream cifrado: 16 MiB; cabecera: 4 KiB. Archivos mayores usan streaming, no se truncan ni se convierten en campos gigantes. Error de versión/suite: rechazo explícito, sin fallback. El sobre de raíz valida límites KDF antes de intentar autenticar su cabecera; solo se confía en ella después de AEAD válido.

La composición de los puntos 3–6 es **diseño del producto que requiere revisión**, no un estándar de libsodium. La codificación de tipos y backup se concreta en G6; §9 completa la composición sin presentarla como validación.

### Archivo stream v1

Cabecera de archivo: magic ASCII `PMF1`, longitud `u32` big-endian (máximo 4 KiB), CBOR `{header:H,stream_header}` donde `stream_header` son los 24 bytes emitidos por secretstream. Sigue secuencia de chunks enmarcados de §7.1; cada chunk usa AAD CBOR `['pm/file/v1', H, stream_header, index]`, index uint64 desde cero. Un archivo vacío tiene un chunk vacío FINAL; para archivos no vacíos FINAL va en el último chunk. No permitir TAG_PUSH/TAG_REKEY como final. Máximo cifrado/chunk 1 MiB + 17 bytes. Nombre, MIME y tamaño lógico esperado se guardan en manifiesto cifrado y se contrastan al completar. El manifiesto de backup G6 agrega membresía exacta de todos los objetos; este framing no prueba por sí mismo backup completo. [Formato de stream y overhead](https://doc.libsodium.org/secret-key_cryptography/secretstream).

### 7.3 Control, rotaciones y recuperación

**Control:** `K_O[e]`, 32 bytes nuevos por paquete operativo/evento, separado de contenido y firmas. Se envuelve bajo `K_H` para lectura humana y en sealed boxes a los custodios autorizados. El paquete interior contiene firma y contexto verificable. El custodio bloqueado puede abrir control pero no `K_C` ni `K_H`; conocer `K_O` no habilita firmar altas. Una retirada no necesita rotar una clave global de control: próximos paquetes llevan nuevas claves y excluyen al retirado. Un dispositivo recién emparejado recibe checkpoint/sobres provisionados por el humano; ningún servidor le entrega privadas. G5 fija precedencia y antirollback, no la suite.

**Rotación:** cambiar contraseña produce salt/K_P/nonce nuevos y reenvuelve `K_H`; cambiar K_R crea y verifica nueva copia externa y sobre; cambiar SK_D exige nueva pública autenticada y provisión humana de sobres activos antes de activar el reemplazo. El custodio viejo no traduce sobres por iniciativa propia. Compromiso de K_H exige nueva raíz, autoridad humana y claves de datos futuras, recifrado y revisión de emparejamientos; no basta reenvolver la raíz comprometida. Mantener generaciones separadas y commit atómico recuperable; no borrar la única vía válida antes de verificar reemplazo. Backups antiguos siguen dependiendo de sus claves históricas.

**Recuperación externa:** representación transportable de K_R: 64 dígitos hexadecimales agrupados para el humano, más checksum de los primeros 8 dígitos de SHA-256 de CBOR `['pm/recovery/v1', vault, generation, K_R]`. La copia incluye vault/generación y versión. El checksum detecta errores, no autentica al usuario ni aumenta entropía. Confirmar reintroducción antes de completar alta; nunca registrar su valor. Se mantiene §6: backup completo y recuperación no reactivan agentes.

**Aleatoriedad:** inicialización RNG obligatoria; fallo bloquea creación/uso que la necesite. Restauración *detectada* de un snapshot invalida contexto de generación y requiere entropía nueva antes de escribir. No prometer detectar clones invisibles ni solucionar repetición de RNG solo con IDs aleatorios. [Advertencia oficial](https://doc.libsodium.org/generating_random_data).

## 8. Evidencia posterior de G2

El cifrado operativo de control ya se fija en §7.3; el reductor y checkpoint autenticado se completan en [sincronización](synchronization.md).

El [contrato de identidad](agent-identity.md) separa además las claves de autenticación del transporte de las claves de envoltura `SK_D`; ninguna autentica automáticamente al humano.

Pruebas futuras, no ejecutadas:

1. Con TUI bloqueada, el custodio usa una credencial habilitada pero no abre contenido nunca delegado, campos humanos ni adjuntos; agentes nunca reciben claves o secretos.
2. Dos dispositivos: editar/habilitar desde A; B bloqueado recibe revisión y sobre válidos sin contraseña humana. Probar pérdida, reordenamiento y recepción parcial sin activar mezclas.
3. Alterar destinatario, bóveda, revisión, generación, firma, nonce o ciphertext: rechazo. Una sealed box válida de remitente no autorizado no habilita nada.
4. Deshabilitar/revocar y reenviar sobres antiguos: no reactivación conocida. Distinguir este caso de rollback completo del equipo y de información remota aún desconocida.
5. Cambiar contraseña, `K_R`, `K_H` y clave de dispositivo con crash en cada transición; conservar una vía verificable o informar fallo, sin pérdida silenciosa.
6. Restaurar todos los tipos con `K_R` en equipo sin keyring original; rechazar clave errónea, manifiesto incompleto, sustitución, truncado y backup corrupto sin sobrescribir la bóveda válida.
7. Ejecutar vectores oficiales y casos adversarios de formato; medir KDF, limpiar memoria, revisar dumps/swap, snapshots y reutilización de nonces en plataformas nativas.
8. Revisar composición y autoridad con especialistas; una biblioteca revisada no acredita nuestro formato ni su integración.

Resultado: suite, binding, contenedor v1, KDF, sobres y control seleccionados. Los antiguos pendientes de manifiesto/compatibilidad G6 y composición se resuelven en §9; las ocho pruebas anteriores son validación futura, no ocho decisiones reabiertas. Sin implementación ni garantías nuevas sobre sesiones externas.

## 9. Composición completa con G5/G6/G7

**Cierre documental de G2, 2026-09-12.** Las decisiones de esta sección completan los pendientes anteriores, sin sustituir pruebas de primitives, revisión criptográfica independiente ni evidencia de aislamiento.

### Schemas y pertenencia

- Plaintext de revisión, unión de componentes `auth` y datos humanos: [G6 §2](../research/credential-migration.md#2-modelo-lógico-común-y-límites-seleccionados). Se cifra el array `auth` completo bajo K_A[r], incluso password+TOTP de una misma revisión; no sobres/claves independientes que permitan mezclar revisiones. `auth=[]` de nota/archivo no es delegable. Campos privados/proveniencia no se copian a descubrimiento delegado.
- Manifiesto de revisión `M={v:1,vault,item,revision,issuer_device,modified_at,kind,human_part,auth_part,attachments}`; parte `{object_id,ciphertext_sha256,ciphertext_length,key_envelope_digest}`. `auth_part=null` para elemento no autenticable; adjuntos `{file_id,descriptor_digest,key_envelope_digest}`. M cifrado bajo K_C de la revisión (su sobre humano va fuera de M) y referenciado por hash cifrado desde el evento `item-revision` G5. `human_part.key_envelope_digest` refiere a un sobre K_C externo ligado al target_header del objeto human_part. M usa otro sobre externo de la **misma** K_C ligado al target_header de M; ambos sobres llevan nonce y cabecera propios, nunca se reutiliza un target_header para dos objetos; no hay hash autorreferente. La firma de evento vincula el ciphertext del manifiesto y su contexto.
- Vista operativa firmada de la revisión: G de §7.2 conserva `target_header/payload_sha256` y la referencia al evento habilitante; material autenticable contiene la cuenta/destino necesarios. No requiere descifrar M humano para comprobar payload/target/credencial. Disponibilidad se decide mediante G5, no por poseer un sobre. Actualizar los dos lados es una transacción/manifiesto de publicación coherente, nunca sustitución parcial.
- Archivos grandes mantienen PMF1/TAG_FINAL. Descriptor de transporte firmado indirectamente por M contiene longitud total de ciphertext, SHA-256 completo y páginas ordenadas de hashes de bloques; los bloques son transporte, no segmentos criptográficos que puedan reordenarse. G5 fija los límites y el receptor confirma secuencia completa antes de ofrecer el archivo.
- Backup **PMB1**: [G6 §5](../research/credential-migration.md#5-backup-completo-pmb1), sobres humanos/de recuperación, PMF1, inventario y vínculo outer_sha256. Datos de todas las revisiones se recifran dentro del stream de backup; no exige copiar claves privadas nativas ni SK_H histórica. Restaurar crea autoridad nueva o importa solo datos bajo autoridad vigente. Las afirmaciones condicionales anteriores sobre restaurar SK_H histórica no son la ruta seleccionada.

### Control y firma sin ciclos

`authority_event` de G es `event_digest` de G5 (32 bytes). Para construir enable: preparar sealed box y todos los campos G salvo authority_event; computar `commitment=SHA256(CBOR(G sin authority_event))`; incluir commitments en body de enable; construir/firmar E; completar G con digest(E) y firmar `['pm/grant/v1',G]`. Receptor verifica firma de E y G bajo raíz ya confiable, commitment, referencia y reductor G5 antes de abrir; después verifica contexto interior de sealed box. No incluir hash de G completo en E: produciría un ciclo imposible de construir.

Agregar inventario de claves: **SK_SD/PK_SD** Ed25519 de procedencia de dispositivo (seed32/pública32), independiente de TLS/SK_D/SK_H; alta humana la fija, cuenta custodial protege seed. Firma eventos técnicos/auditoría, no concesiones humanas. **K_AUD[d]** de 32 bytes para auditoría local según [G7](security-operations.md), independiente de K_A de credenciales; sobre bajo K_H y sealed box a PK_D, bound a vault/device/generation/purpose `audit-record`/`audit-manifest`. Añadir `audit-record` y `audit-manifest` al enum de propósitos de H: AEAD y wrapped_purpose deben coincidir; no reinterpretar un sobre de credencial como clave de auditoría. Rotación de K_AUD conserva claves históricas bajo KH mientras sus segmentos existan; no da notas al custodio. La envoltura de KAUD tiene wrapped_purpose `audit-record` y se permite usar esa misma clave exclusivamente en los dos schemas audit-record/audit-manifest de esa generación, nunca en auth-payload.

Resultados/estado de intentos G4 usan **K_ATT[a]** aleatoria32 por intento, únicamente sealed box al PK_D del dispositivo ejecutor, autenticada por Sig_D con dominio pm/attempt-key/v1 y bound a vault/attempt/generation; no sobre KH que exigiría desbloqueo humano durante operación autónoma. Consulta humana autorizada se realiza a través del custodio, no abriendo K_ATT directamente; purpose `attempt-state` en H y en los sobres. Incluye snapshot/resultado permitido cifrado, no password original ni seed TOTP retenidos durante desafíos. Tras 24h terminal eliminar resultado/K_ATT y sobres; índice mínimo de idempotencia sigue 7d con protección de control K_O y sin contenido del resultado. No exportar K_ATT al agente; el motor devuelve únicamente el schema público G3 al propietario autenticado. Backup G6 excluye estos intentos/capacidades y sus claves. Añadir `attempt-state` al enum de propósitos, sin cambiar algoritmos.

Registro de raíz confiable `{vault,epoch,PK_H}` se fija fuera de banda humana; transición planificada doble firma y corte G5; compromiso exige linaje nuevo G7. `key_generation` de sobre identifica generación de esa clave, **no** por sí sola epoch de autoridad ni generación de agente. Referencias de evento/grant contienen la época y generación pertinentes, y se comprueban contra el registro; no aceptar `max(generation)` como confianza.

### Revisión de composición realizada sobre el diseño

| Ataque/error revisado | Invariante del contrato | Evidencia posterior |
|---|---|---|
| Sustituir nonce/header/destino/payload/recipient | AAD tipada y comparación de target interior; evento y grant firman referencias. | Alterar cada campo, rechazo antes de autenticación externa. |
| Sealed box válida de atacante | No acredita emisor; firma SK_H y autoridad G5 obligatorias. | Paquetes válidamente cifrados pero no autorizados rechazados. |
| Metadata o payload de otra revisión | Manifest/event/grant y partes vinculan IDs y hashes, publicación completa. | Reordenar/mezclar partes, nunca activar combinación. |
| Círculo evento↔grant | Commitment sin authority_event primero; firma final después. | Vector de construcción/revalidación reproducible. |
| Clave usada para otro propósito | Tipos AAD, prefijos de firmas y claves independientes; no conversión de TLS a envoltura. | Tests de sustitución entre root/control/auth/audit/file. |
| Replay/backup antiguo/rollback | G5 conserva headers/retiradas; restore G6 no activa autoridad importada. No prueba actualidad de snapshot integral aislado. | Retiradas, cortes y restore adversarios V17/V21. |
| Compromiso de raíz | Linaje nuevo, recifrado y emparejamiento limpio; no solo reenvoltura. | Procedimiento G7 en entorno sintético. |

Resultado de esta revisión documental: dependencias, orden de construcción y separación de claves concretados. **No es auditoría criptográfica externa ni evidencia runtime.** Los tests de §8 siguen como criterios de implementación, no condiciones circulares que obliguen a construir antes de poder planificar.
