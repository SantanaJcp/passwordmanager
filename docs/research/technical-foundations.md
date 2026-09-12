# Bases técnicas — síntesis de investigación G1–G3

Fecha de consulta: 2026-09-12. Estado: investigación documental; recomendaciones no adoptadas.

Estado actualizado: contratos G1–G8 completos documentalmente; ver [spec §15](../../.scratch/passwordmanager/spec.md#15-estado-consolidado-acuerdos-cierres-de-diseño-y-validación). La comparación original es histórica: stack/perfiles y núcleos de claves/wire ya se seleccionaron en [aislamiento](../design/isolation.md), [claves](../design/key-hierarchy.md) e [identidad](../design/agent-identity.md); G3 tiene [resolución documental B1–B4](g3-authentication-integrations.md#resolución-de-b1b4--cierre-documental-de-g3). Las incertidumbres y estados abiertos de la comparación original de abajo son históricos; P1–P5 siguen sin ejecutar. No se ejecutó validación.

## Pregunta y alcance

¿Qué combinación de custodia, criptografía e integraciones permite que agentes aislados utilicen credenciales sin recibirlas, con motor independiente y TUI completa en Linux, macOS y Windows?

Hipótesis a contrastar: un servicio custodio separado, claves delegadas limitadas al conjunto común e integraciones de autenticación confiables pueden satisfacer el contrato. Esto **no equivale** a que cualquier herramienta del agente pueda utilizar cualquier contraseña de forma invisible.

Autoridad: [contrato funcional, R01–R21](../../.scratch/passwordmanager/spec.md#2-contrato-de-producto-aprobado), [glosario](../../CONTEXT.md) y [ADR 0001](../adr/0001-limite-de-responsabilidad-de-la-boveda.md). No se reabre el alcance, recortan funciones ni incorpora gestión de sesiones externas. Omarchy permanece fuera de esta entrega y repositorio.

## Lectura por decisión

| Investigación | Pregunta que resuelve documentalmente | Lo que no certifica |
|---|---|---|
| [G1 — Stack y custodia](g1-stack-and-custody.md) | Candidatos de lenguaje/TUI/almacenamiento y separación nativa por OS. | Aislamiento real, versiones mínimas, instalador y reinicio desatendido en las tres plataformas. |
| [G2 — Criptografía](g2-vault-cryptography.md) | Primitivas candidatas y separación humano/delegación/recuperación. | Protocolo compuesto seguro, formato final, parámetros medidos o revisión independiente. |
| [G3 — Integraciones](g3-authentication-integrations.md) | Límites de web/TOTP/passkeys/SSH/API/sistema sin exportar secretos. | Compatibilidad de un proveedor o cliente que no se haya probado. |

## Dirección recomendada tras la revisión

**Candidatos, no arquitectura aprobada:**

- **Motor y TUI:** priorizar Rust + Ratatui/Crossterm; Go + Bubble Tea continúa viable. SQLite puede guardar contenido previamente cifrado, pero no aporta cifrado por elegirlo. La preferencia favorece control explícito de recursos, no una superioridad de seguridad demostrada. [Comparación y fuentes G1](g1-stack-and-custody.md).
- **Claves:** evaluar Argon2id, AEAD y envolturas separadas para humano, delegación y recuperación. Delegar material autenticable, no notas/adjuntos/historial completos. La composición y los parámetros aún necesitan revisión: por ejemplo, la API Argon2id de libsodium 1.0.20 inspeccionada usa `p=1`, no el `p=4` de los perfiles RFC examinados. [Evidencia G2](g2-vault-cryptography.md).
- **Autenticación:** SSH ofrece una interfaz de firma sin exportar la clave, pero firmar no demuestra que el login fue aceptado. Web/TOTP requieren un contexto confiable; autofill bajo control irrestricto del agente no cumple la garantía. Un bearer almacenado necesita aplicación confiable en cada solicitud que lo exija, salvo intercambio compatible por una credencial distinta. [Matriz y fuentes G3](g3-authentication-integrations.md).

**Incertidumbres prioritarias:** instalación CLI-first e identidad IPC en macOS; una ruta concreta para autenticación de sistema macOS; entrega del resultado web sin residuos del secreto; y semántica de resultados SSH/bearer en `StartAuthentication`. Son asuntos para concretar en G1/G3/G4, no motivos para excluir macOS, eliminar familias o introducir un gestor de sesiones. [G1](g1-stack-and-custody.md), [G3](g3-authentication-integrations.md), [interfaz propuesta §7](../../.scratch/passwordmanager/spec.md).

## Hallazgo transversal: MCP no es la frontera de custodia

**Hechos verificados.** En el transporte MCP `stdio`, el cliente arranca el servidor como subproceso y puede capturar sus diagnósticos. En Streamable HTTP, la especificación exige validación de `Origin` y recomienda autenticación y escucha local para servidores locales. Son contratos de transporte, no una garantía de separación de secretos. Referencia examinada: versión **2025-11-25**, no versión adoptada por el proyecto. [MCP: transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

Las recomendaciones oficiales advierten sobre servidores locales con privilegios del cliente y establecen que un identificador de sesión MCP no debe servir como autenticación. También distinguen los tokens destinados al propio servidor MCP de los destinados a servicios externos. [MCP: security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).

**Inferencia y propuesta.** El adaptador MCP ejecutado por el agente debe ser un cliente sin secretos del servicio custodio, no el proceso que descifra la bóveda. Separar autoridad humana, identidad del agente y credencial del proveedor. Que el agente pueda usar una credencial del conjunto común no le da acceso a las operaciones humanas. Esta propuesta concreta los invariantes de [la especificación, §§5–7](../../.scratch/passwordmanager/spec.md), sin escoger todavía transporte nativo ni protocolo de identidad.

La autenticación y continuidad del canal interno con la bóveda sí pertenecen al producto; no deben confundirse con administrar la sesión externa posterior, excluida por [ADR 0001](../adr/0001-limite-de-responsabilidad-de-la-boveda.md).

## Orden recomendado para resolver incertidumbre

Esto es un orden de **validación**, no una entrega MVP ni una autorización de ejecución:

1. Precisar la frontera nativa entre propietario, custodio y agente para cada OS. Elegir candidatos de stack a partir de esa frontera, no confundir una TUI portable con una bóveda aislada.
2. Revisar la jerarquía de claves y el flujo completo de una credencial habilitada: creación, uso, bloqueo humano, suspensión, revocación, reinicio y recuperación.
3. Especificar un recorrido verificable por cada familia de autenticación aprobada, con componente confiable, datos que entran/salen y condiciones humanas. No anunciar familias completas a partir de un único proveedor.
4. Con autorización posterior, ejecutar pruebas negativas nativas y de integración. Registrar también resultados que refuten la hipótesis; no sustituir R09 por una promesa de no mostrar el secreto en el chat.

Estos pasos derivan de [G1–G3 y escenarios V03–V13, V20–V25](../../.scratch/passwordmanager/spec.md), no añaden funcionalidades.

## Registro mínimo de evidencia futura

Por cada combinación que se pretenda soportar, conservar:

- OS, arquitectura, versiones de cliente/proveedor/bibliotecas y configuración efectiva de identidades y permisos.
- Método, destino, credencial sintética y límite exacto de la integración; qué puede observar o modificar el agente.
- Recorrido del secreto y resultado permitido; controles sobre destino y tratamiento de errores/redirecciones.
- Pruebas de extracción por archivos, memoria, terminal, logs y herramientas del agente; intentos de invocar autoridad humana.
- Resultados de reinicio, pausa humana, cancelación y revocación, distinguiendo estado local de información remota aún no sincronizada.
- Evidencia reproducible, limitaciones y revisión. Una prueba positiva de login no basta para afirmar ausencia de extracción.

Es una propuesta de registro para hacer verificables [V03–V13 y V23](../../.scratch/passwordmanager/spec.md), no pruebas ya realizadas ni tickets creados.

## Estado de las puertas y limitaciones

- **G1, G2 y G3 siguen abiertas:** esta investigación entrega evidencia documental y candidatos; no cumple sus criterios completos de cierre.
- **G4–G8 siguen abiertas y no se investigan exhaustivamente aquí.** Identidades/API, sincronización, migración, operación y distribución pueden invalidar una combinación aparentemente viable de G1–G3.
- No hay manifiestos de dependencias ni versiones de producto con las que contrastar firmas runtime. No se incluyen ejemplos de código presentados como validados.
- No se ejecutaron prototipos, pruebas de autenticación, benchmarks criptográficos ni pruebas nativas de aislamiento. No se instalaron dependencias ni modificó configuración del sistema.
- No se crea ADR aceptado, licencia definitiva, ticket de implementación ni declaración `ready-for-agent` a partir de estas recomendaciones.

Los criterios vigentes permanecen en [la especificación, §15](../../.scratch/passwordmanager/spec.md).
