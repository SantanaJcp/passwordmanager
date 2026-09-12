# G2 — Criptografía y custodia de claves

Fecha de consulta: 2026-09-12. **Estado: investigación documental; G2 abierta.**

Selección posterior: [formato v1 y suite](../design/key-hierarchy.md). Las alternativas de esta investigación se conservan como antecedentes; suite/binding/KDF ya tienen selección de ingeniería, no seguridad validada. Backup/revisión de composición y pruebas siguen pendientes.

Desarrollo posterior: [jerarquía de claves propuesta](../design/key-hierarchy.md), con distinción explícita entre contenido nunca delegado, retirada de permiso y copias históricas que no pueden invalidarse retroactivamente.

## Pregunta y conclusión

¿Qué fundamentos permiten cifrar la bóveda, recuperarla y mantener autenticación delegada tras reinicios sin entregar secretos al agente? El límite es el contrato R07–R12 y R15–R18 de la [especificación](../../.scratch/passwordmanager/spec.md), no la gestión de sesiones externas.

**Recomendación, no decisión:** evaluar Argon2id para desbloqueo humano, AEAD de biblioteca mantenida, cifrado por envolturas y custodia delegada separada del acceso humano completo. Las primitivas disponibles no validan su composición ni el aislamiento. No se han ejecutado vectores, benchmarks o pruebas nativas, ni elegido dependencia/binding; la especificación todavía no fija stack ni versión.

## Hechos verificados

| Área | Evidencia y consecuencia |
|---|---|
| Derivación humana | RFC 9106 documenta Argon2 v1.3 y recomienda Argon2id. Sus perfiles incluyen `m=2 GiB,t=1,p=4` y, con menos memoria, `m=64 MiB,t=3,p=4`; no son mediciones de este producto. Incluye vectores. [RFC 9106, §§4–5](https://www.rfc-editor.org/rfc/rfc9106.html#section-4). |
| API y formato | `crypto_pwhash()` deriva claves; `crypto_pwhash_str()` produce un verificador de contraseña, no una clave secreta para almacenar junto al ciphertext. La reproducción exige conservar algoritmo, salt y parámetros; `ALG_DEFAULT` puede cambiar. El fallo de derivación devuelve `-1`, habitualmente por falta de memoria. [libsodium pwhash](https://doc.libsodium.org/password_hashing/default_phf). |
| Diferencia relevante | En el código **1.0.20 inspeccionado**, `crypto_pwhash_argon2id()` pasa `p=1` a Argon2 y convierte memoria de bytes a KiB. No anunciar el perfil RFC `p=4` usando esa API sin comprobar implementación. Esta referencia fija evidencia, no selecciona ni declara última versión de la dependencia. [Fuente versionada, llamada a `argon2id_hash_raw`](https://github.com/jedisct1/libsodium/blob/1.0.20/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c#L125-L162). |
| Registros y claves envueltas | XChaCha20-Poly1305 autentica ciphertext y datos asociados; estos últimos **no se cifran**. Su nonce de 192 bits permite generación aleatoria, pero nunca debe repetirse con la misma clave. El descifrado rechaza autenticación inválida con `-1`. Libsodium lo recomienda cuando no se requiere interoperabilidad con otras bibliotecas. [Documentación de la construcción](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction). |
| Archivos grandes | `secretstream` proporciona secuencias autenticadas, nonces gestionados y rekeying. El consumidor debe comprobar errores y `TAG_FINAL`: EOF no sustituye un final autenticado. Su estructura ordenada no equivale a un formato de acceso aleatorio. [API y ejemplo de archivos](https://doc.libsodium.org/secret-key_cryptography/secretstream). |
| Envolturas | Una DEK cifra datos; una KEK protege esa DEK. Separarlas permite granularidad por objeto y diferentes vías de protección. Se toma el patrón, **no se propone Cloud KMS ni dependencia cloud**. [Descripción primaria de envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption). |
| Integridad ≠ autoridad | AEAD no define antirreplay ni decisiones de acceso. Una sealed box oculta el contenido al no destinatario, pero **no autentica quién lo envió**. Por tanto, cifrar eventos de habilitación no basta para acreditar autoridad humana. [RFC 5116 §1.2](https://www.rfc-editor.org/rfc/rfc5116.html#section-1.2), [libsodium sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes). |
| Memoria y aleatoriedad | `sodium_mlock()` puede fallar; borrado explícito y protección frente a swap/dumps necesitan tratamiento propio. Libsodium advierte que restaurar un snapshot de VM puede repetir salidas aleatorias. Un RNG criptográfico no resuelve por sí solo clonación/restauración del estado. [Memoria](https://doc.libsodium.org/memory_management), [generación aleatoria](https://doc.libsodium.org/generating_random_data). |

## Dirección de diseño propuesta, pendiente de revisión

Los nombres siguientes son responsabilidades lógicas, no un protocolo criptográfico nuevo ni un formato aprobado. Aplican el patrón de [envolturas](https://docs.cloud.google.com/kms/docs/envelope-encryption) al [contrato del repositorio](../../.scratch/passwordmanager/spec.md).

1. **Vía humana:** contraseña → KDF → envoltura de una clave aleatoria de acceso humano. Esta permite abrir claves de contenido; no usar la contraseña directamente para cifrar cada elemento. Cambiarla puede reenvolver claves sin recifrar todo, pero no invalida copias históricas obtenidas con una vía anterior. Es una inferencia del patrón de envolturas, no revocación retroactiva.
2. **Contenido:** evaluar DEKs independientes por elemento/revisión y por archivo. Separar material autenticable de notas, campos libres, adjuntos e historial humano antes de conceder acceso delegado; habilitar una credencial no debe implicar delegar todos sus campos. El diseño debe resolver cómo se mantienen consistentes esas partes y sus revisiones, sin inventar conjuntos por agente.
3. **Vía delegada:** cada dispositivo custodio conserva una vía local protegida que abre únicamente material del **conjunto común habilitado**, nunca la raíz humana completa. Las identidades de agentes solo autorizan operaciones: no reciben DEKs, KEKs ni la clave de dispositivo. Emparejamiento, actualizaciones del conjunto y su prueba de autoridad deben definirse con G4/G5.
4. **Recuperación:** evaluar una clave aleatoria independiente, conservada fuera del equipo, que proteja una vía de recuperación en el backup cifrado. La restauración debe funcionar sin keychain del equipo perdido y no registrar agentes por copiar un backup. Rotar esta vía exige definir compatibilidad de backups antiguos; ni una nueva contraseña ni una nueva clave hacen desaparecer copias previas. [Contrato R18 y modelo RecoveryEnvelope](../../.scratch/passwordmanager/spec.md).
5. **Formato:** fijar suites/versiones explícitas, codificación canónica, límites de tamaños y parámetros KDF antes de asignar recursos. Autenticar vínculo bóveda/objeto/revisión/propósito de clave y encabezados pertinentes; no poner información confidencial en AAD. Rechazar formatos desconocidos sin degradación silenciosa. Son controles propuestos ante los parámetros costosos y la semántica de AAD documentados en [pwhash](https://doc.libsodium.org/password_hashing/default_phf) y [RFC 5116 §3.3](https://www.rfc-editor.org/rfc/rfc5116.html#section-3.3).

### Dos límites que no puede resolver una suite

**Bloquear la TUI no equivale a dejar el custodio sin capacidad de descifrado.** Si debe autenticar autónomamente tras reinicios, conserva o recupera material suficiente para ese uso. Es una consecuencia de R11/R12, no un fallo criptográfico; la protección frente al agente depende de la frontera G1/G7. Suspender agentes retira nuevos usos, no garantiza eliminar instantáneamente toda copia de memoria o backup. [Contrato y custodia propuesta](../../.scratch/passwordmanager/spec.md).

**Keyring no es prueba universal de aislamiento.** DPAPI normalmente vincula descifrado al usuario/equipo; `LOCAL_MACHINE` permite descifrar a cualquier usuario con el blob. Secret Service describe un servicio en la sesión de login y operaciones que devuelven secretos. Apple advierte que macOS no aplica directamente las mismas clases Data Protection que otros dispositivos. La identidad, permisos y disponibilidad del custodio tras reboot requieren diseño nativo, no seleccionar un wrapper genérico. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [Freedesktop](https://specifications.freedesktop.org/secret-service/latest/description.html), [Apple](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web).

## E2EE, revocación y recuperación

- **Contrato:** el servidor solo intercambia datos cifrados; offline se usa la última autorización conocida. Una revocación remota surte efecto al recibirse, no antes. [R15–R18](../../.scratch/passwordmanager/spec.md).
- **Inferencia:** cifrado autenticado no impide que el servidor omita o reproduzca una revisión válida. LWW de contenido no debe convertirse en autorización para resucitar agentes; autenticidad de eventos, autoridad para emitirlos y defensa frente a rollback quedan en G4/G5. [Límite antirreplay de AEAD](https://www.rfc-editor.org/rfc/rfc5116.html#section-1.2).
- **Propuesta:** el backup debe autenticar manifiesto, pertenencia de objetos y finalización, y restaurarse de forma transaccional tras validar integridad. Secretstream protege la secuencia de un archivo, no garantiza por sí solo que un backup incluya todos los elementos esperados ni que sea el más reciente. [API](https://doc.libsodium.org/secret-key_cryptography/secretstream), [requisitos de restauración](../../.scratch/passwordmanager/spec.md).

## Qué falta para cerrar G2

1. Fijar biblioteca y binding mantenidos, versiones exactas, formatos y perfiles KDF; medir Linux/macOS/Windows y verificar interoperabilidad de parámetros, sin confundir API de alto nivel con perfil RFC.
2. Revisar jerarquía y todas las transiciones: desbloqueo, reboot, habilitar/deshabilitar, edición mientras TUI bloqueada, recuperación, cambio de contraseña, pérdida/retirada de dispositivo y claves comprometidas.
3. Ejecutar vectores y casos adversarios: bytes/header/AAD alterados, sustitución entre bóvedas, truncado/reordenamiento, KDF abusivo, fallos de memoria, crash durante escritura, snapshots/clones y nonce reutilizado. Son pruebas pendientes, no realizadas.
4. Demostrar que el custodio delegado no puede abrir contenido nunca delegado y que retiradas conocidas impiden nuevos usos de material antes habilitado, sin prometer invalidar copias antiguas. Probar que un agente no extrae secretos ni invoca administración humana y verificar disponibilidad nativa tras reboot con la vía humana bloqueada.
5. Revisar E2EE, rollback y backups antiguos con G5/G7. Una auditoría de la biblioteca no sería una auditoría del formato, del binding ni del producto.

**Resultado:** hay fundamentos para proponer un diseño revisable, no evidencia suficiente para cerrar G2 ni autorizar implementación.
