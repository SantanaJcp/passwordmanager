# Sincronización, revocaciones y retención — contrato v1

Fecha: 2026-09-12. Estado: **G5 cerrado documentalmente; selección de ingeniería en §9**. §§1–8 preservan la propuesta histórica, no su estado pendiente. Sin simulación ni prueba de convergencia ejecutada.

Autoridad: [R15–R18 y §10 de la especificación](../../.scratch/passwordmanager/spec.md), [glosario](../../CONTEXT.md), [identidades](agent-identity.md) y [claves](key-hierarchy.md). Se conserva uso local/offline, servidor opcional autohospedado, E2EE, conjunto común y LWW de contenido por timestamp.

## 1. Recomendación y alternativas

**Recomendación:** intercambiar objetos inmutables cifrados y operaciones autorizadas. Separar la selección del contenido visible de la autoridad para utilizarlo. Los dispositivos calculan el resultado; el servidor no decide permisos ni resuelve conflictos.

| Alternativa | Ventaja | Problema | Propuesta |
|---|---|---|---|
| Servidor ordena todas las operaciones | Orden central sencillo. | El uso offline no puede depender de esa respuesta; añade confianza al servidor. | Descartar como autoridad. |
| Un solo registro LWW para contenido y permisos | Un único comparador. | Un timestamp adelantado puede hacer ganar un permiso antiguo frente a una revocación. | Descartar para autoridad. |
| Contenido LWW y eventos de autoridad con relaciones explícitas de precedencia | Conserva la elección funcional sin basar revocación en relojes. | Más estado y reglas de retención; necesita pruebas exhaustivas. | Preferida para revisión. |

No se propone sincronizar el archivo SQLite abierto: su WAL participa del estado persistente. Se intercambian revisiones lógicas y se aplican transacciones locales. [SQLite WAL](https://sqlite.org/wal.html).

## 2. Objetos y responsabilidades

| Objeto lógico | Contenido mínimo propuesto |
|---|---|
| Revisión | Bóveda, elemento, ID de revisión, dispositivo autor, timestamp, referencias de partes cifradas y prueba de autorización/integridad. |
| Evento de autoridad | ID único, objeto/generación afectada, acción, emisor autorizado, referencias a antecedentes y prueba humana correspondiente. |
| Sobre delegado | Destinatario, revisión, generación de habilitación y clave de material autenticable cifrada para el custodio. |
| Manifiesto de transferencia | Referencias verificables de los objetos que forman una revisión/operación completa; no una lista arbitraria aceptada por confianza en el servidor. |
| Cursor | Ayuda del servidor para descargar cambios; no prueba de completitud ni de antigüedad. |
| Acuse | Evidencia de recepción/aplicación de un dispositivo, separada del simple almacenamiento en servidor. |

IDs, relaciones, timestamps y destinatarios deben quedar autenticados. El contenido humano permanece cifrado para su vía humana; el custodio bloqueado necesita leer únicamente control y material delegado correspondientes.

**Necesidad adicional de G2:** un cifrado de control, separado de las claves de contenido humano, para que dispositivos custodios lean eventos de autoridad con TUI bloqueada sin exponer esos eventos al servidor. Propuesta: clave operativa de control distribuida a custodios mediante sobres autenticados; no cifra notas ni concede autoridad de firma. Su generación/rotación al retirar dispositivos se integra con la jerarquía; no reutilizar la raíz humana. El servidor aún puede observar tamaños, frecuencia, identificadores de transporte y conexiones: E2EE no significa anonimato.

Las operaciones humanas deben verificarse bajo autoridad previamente confiable; un acuse firmado por un dispositivo no lo autoriza a registrar agentes. Cifrar no resuelve antirreplay ni control de acceso por sí solo. [RFC 5116 §1.2](https://www.rfc-editor.org/rfc/rfc5116.html#section-1.2).

## 3. Contenido: LWW exacto y sin mezclar campos

Propuesta de orden total entre revisiones válidas del mismo elemento:

1. Timestamp UTC de modificación; candidato de representación: entero de microsegundos desde Unix epoch, sin float ni comparación de strings locales.
2. ID de dispositivo, en representación binaria canónica.
3. ID de revisión, también canónico.

Gana el máximo de la tupla. Empates de timestamp se resuelven igual en todos los dispositivos; el orden de llegada no participa. Mismo ID con contenido distinto es fallo de integridad, no un empate LWW.

Conservar las revisiones perdedoras en historial hasta una purga explícita. Seleccionar la revisión completa: no combinar contraseña de A, destino de B y metadatos de C. Restaurar contenido crea una revisión nueva y nuevas claves, conforme a [la jerarquía](key-hierarchy.md).

**Relojes:** una escritura con reloj adelantado puede ganar aunque ocurriera antes. No corregir silenciosamente timestamps recibidos, cambiar a reloj del servidor ni convertir el conflicto en aprobación manual. Avisar al humano de anomalías detectables sin pausar autenticaciones por el conflicto. Incluso una restauración con reloj atrasado puede perder: su resultado debe mostrarse honestamente. No fingir que ocurrió más tarde ni prometer que toda restauración será visible sin resolver ese desfase. Rango, overflow y límites se fijan en §9.1.

## 4. Autoridad: retirar gana frente a una habilitación concurrente

**Propuesta de semántica, no protocolo probado:** los eventos de autoridad forman un historial con referencias autenticadas a antecedentes. «Posterior» aquí significa que un evento incluye al otro entre sus antecedentes verificables, no que su timestamp sea mayor. Eventos sin esa relación son concurrentes.

### Suspensión global y disponibilidad común

Para cada control (delegación global o habilitación de una credencial):

- Una habilitación/reanudación solo es efectiva si es posterior a **todas las retiradas relevantes conocidas** de ese control. Si hay una retirada concurrente o posterior, prevalece la retirada.
- Reanudar después de conocer varias retiradas requiere una nueva acción humana que las tenga como antecedentes. No basta reenviar una habilitación anterior con un timestamp mayor.
- Al recibir una retirada antes desconocida, recalcular el resultado. Puede invalidar una habilitación que otro equipo creía vigente offline: es la consecuencia prevista del conocimiento parcial.
- La operación inicial toma un estado base explícito: agente no registrado y credencial no habilitada no adquieren acceso por ausencia de eventos.

Ejemplo lógico: A suspende mientras B, desconectado de A, reanuda. Al intercambiar ambos eventos, queda suspendido. Una reanudación humana posterior que conoce ambas ramas puede volver a habilitar. La resolución es automática y no cambia el LWW de contraseñas.

### Identidades y generaciones

Revocar una generación de agente/dispositivo es terminal para esa generación. Reautorizar requiere una concesión humana nueva, vinculada a los antecedentes de retirada; el alta original y sus certificados no se reactivan. La nueva concesión no hereda pendientes ni autoridad de un backup automáticamente. [Identidad propuesta](agent-identity.md).

Las retiradas deben referir al sujeto estable además de a su generación, para que una concesión concurrente creada sin conocer la retirada no la esquive mediante un número nuevo. Sucesión de generaciones, pruebas de antecedencia y rotación de raíz de autoridad requieren especificación formal antes de cerrar G5.

**Datos incompletos:** no activar una concesión cuyos antecedentes no puedan verificarse. Una retirada con autoridad independientemente verificable puede denegar provisionalmente el sujeto afectado mientras llegan antecedentes; nunca usar la incompletitud para ampliar permisos. Limitar memoria/parser y aislar entradas inválidas sin bloquear toda la bóveda. El detalle de validación depende del formato firmado G2/G4.

## 5. Papelera y eliminación: decisión funcional y propuestas técnicas

**Decisión confirmada posteriormente por el usuario:** borrar prevalece frente a una edición concurrente, conservando en papelera el contenido ganador por LWW; volver a activo requiere restauración humana explícita. Registrada en [ADR 0002](../adr/0002-borrado-frente-a-edicion-concurrente.md). La investigación inicial no había cerrado este caso; ya no requiere ratificación.

**Reglas funcionales aceptadas y realización técnica propuesta:**

- Editar modifica contenido por LWW; no cambia por sí solo papelera a activo.
- Enviar a papelera deja un marcador de eliminación. Una edición concurrente puede ganar como contenido y queda recuperable allí, pero no devuelve el elemento a la lista activa.
- Restaurar desde papelera es una acción humana explícita que reconoce las eliminaciones conocidas. Una eliminación concurrente prevalece hasta una restauración posterior que la reconozca, usando la misma relación de antecedentes.
- Eliminar/deshabilitar invalida uso delegado. Restaurar contenido o salir de papelera no reconstituye por sí solo los sobres/autorizaciones retirados; la TUI debe explicar y permitir habilitación explícita.
- La eliminación definitiva retira contenido y claves gestionadas según el alcance confirmado y deja un marcador compacto del ID purgado. Reimportar deliberadamente una copia crea un elemento nuevo, no elimina ese marcador.

**Trade-off aceptado:** evitar resurrección automática por edición mediante un ciclo de vida separado del LWW de contenido. Las reglas de antecedentes para restauración concurrente con otra eliminación, habilitación delegada posterior y purga son propuestas técnicas: la aprobación no ratifica automáticamente todos esos detalles ni la retención por defecto.

## 6. Flujo local y sincronización

1. Validar acción humana/delegada y estado local. Crear IDs, revisión y sobres necesarios; escribir de forma atómica el cambio y su registro de publicación pendiente.
2. El usuario puede seguir localmente sin respuesta del servidor. Publicar cifrados mediante operaciones idempotentes; una respuesta perdida se resuelve consultando/reintentando el mismo objeto, no generando otra revisión.
3. Descargar objetos a un área de recepción; verificar límites, integridad, autoridad, antecedentes y referencias antes de activar. Cursor/orden de descarga no acreditan autorización.
4. Aplicar autoridad válida conocida antes de nuevos usos sensibles. Una revisión ganadora incompleta no sustituye la activa a medias: mostrar sincronización pendiente; mantener último estado completo conocido hasta disponer del cambio aplicable, salvo retirada que obligue a denegar.
5. Activar transaccionalmente revisión, partes y sobres coherentes; recalcular disponibilidad. No volver a una credencial anterior como fallback de una integración fallida.
6. Persistir avance local y acuse sin secretos. Reiniciar reanuda transferencia, no una autenticación externa indeterminada. Los intentos mantienen su ejecutor y comprobaciones de [G4](agent-identity.md).

La convergencia propuesta es **condicional**: mismos objetos válidos completos y mismas reglas deben producir la misma revisión y autoridad. Si el servidor oculta una rama, dos equipos pueden discrepar; el cifrado no obliga al servidor a entregarla. Esta propiedad aún debe modelarse y probarse.

«Al día» solo significa sin pendientes respecto de la vista obtenida, no prueba de ausencia de operaciones en dispositivos desconectados ni de omisiones maliciosas. Mostrar última sincronización y estado por dispositivo cuando exista evidencia; no bloquear uso offline para obtener una certeza imposible.

## 7. Dispositivos retirados, restauración y retención

- **Retirar dispositivo:** no enviarle nuevos sobres después de conocer la retirada; rotar control conforme a G2 para proteger metadata futura. No recupera claves/cifrado que el equipo ya obtuvo ni evita envíos efectuados por otro equipo que aún ignora la retirada.
- **Emisor retirado que vuelve:** no usar su timestamp para aceptar automáticamente autoridad nueva. Propuesta: la retirada fija una frontera autenticada de operaciones de ese emisor que reconoce como anteriores; operaciones fuera de esa frontera quedan como candidatas de recuperación, no activas, aunque otro equipo las hubiera recibido antes. Todos recalculan con la misma frontera, sin decidir validez por orden de llegada. El humano puede inspeccionar/importar datos mediante una instalación válida y crear revisiones nuevas. Esto puede apartar cambios offline legítimos: no se eliminan silenciosamente. El formato y relación con autoridad se concretan en §9.1–9.2; la convergencia sigue sin probarse.
- **Compromiso de raíz humana:** retirar un dispositivo no neutraliza una `SK_H` copiada. Rotar raíz/cadena de confianza y recuperar un linaje confiable es un procedimiento distinto G2/G7; no prometer que una revocación de transporte lo resuelve.
- **Restaurar backup:** importar datos en destino seguro sin sustituir silenciosamente el estado de autoridad más reciente de una instalación existente. Un nuevo equipo requiere emparejamiento; un backup no declara agentes activos por sí solo.
- **Rollback completo:** si se restauran datos y toda evidencia local de que existieron retiradas posteriores, no hay detección local automática garantizada. Contrastar con un dispositivo/checkpoint confiable disponible puede revelar divergencia; un servidor que omite información no es prueba suficiente de actualidad. Mantener el límite offline, no inventar un quorum obligatorio.

**Retención recomendada:** historial y papelera sin caducidad automática por defecto, con purga humana explícita y aviso de alcance. Esta es política propuesta, no plazo previamente acordado. Conservar marcadores compactos de purga/revocación y referencias de seguridad mientras puedan reaparecer copias antiguas; no eliminarlos por un simple timeout.

No existe un periodo fijo de días tras el cual sea seguro olvidar a cualquier dispositivo si se permite offline sin límite. Compactar eventos requiere un checkpoint autenticado con estado equivalente y pruebas de que mensajes anteriores no pueden reactivar contenido/autoridad. Acuse del servidor no basta; faltan protocolo de checkpoint, tratamiento de dispositivos retirados y límites de crecimiento. Ante cuota agotada, informar y no borrar marcadores para «hacer espacio» silenciosamente.

Una purga puede eliminar datos gestionados localmente y solicitar eliminación al servidor, pero no demostrar borrado físico en snapshots o copias externas. La metadata antiresurrección debe ser mínima y no conservar valores secretos purgados. [Límites de recuperación y eliminación](../../.scratch/passwordmanager/spec.md).

## 8. Casos de aceptación propuestos

Todos son ejemplos sintéticos de resultado esperado, **no pruebas ejecutadas**.

| Caso | Resultado esperado |
|---|---|
| A escribe timestamp 100, B escribe 200; llegan en ambos órdenes y duplicadas. | Gana 200; 100 queda en historial. |
| Mismo timestamp, dispositivos/revisiones distintos. | Mismo desempate canónico en todos los equipos. |
| A tiene reloj adelantado. | Puede ganar una edición anterior en tiempo real; aviso, no cambio de comparador. |
| A revoca; B reenvía alta anterior con timestamp mayor. | No reactiva autoridad. |
| Suspensión y reanudación concurrentes; después reanudación que conoce ambas. | Primero suspendido; después habilitado si no existe otra retirada no reconocida. |
| Credencial deshabilitada y sobre de edición llega más tarde. | Sobre no devuelve habilitación; contenido conserva su LWW. |
| Editar/borrar concurrentemente. | Bajo política propuesta de §5, gana contenido por LWW pero permanece en papelera. |
| Purga y posterior reenvío de una revisión antigua. | ID purgado no reaparece; no retener su secreto en el marcador. |
| Revisión antes de sobre/adjunto o concesión sin antecedentes. | No activar estado parcial ni ampliar autoridad. |
| Revocación llega con conexión/intent pendiente. | Revalidación local impide nuevo uso; no promete logout externo. |
| Crash entre escritura, publicación, descarga y acuse. | Recuperación idempotente sin revisión duplicada ni pérdida de retirada conocida. |
| Servidor omite una rama, replay de snapshot, retiro de dispositivo. | No afirmar actualidad global; conservar estado conocido y límites documentados. |

Validación posterior: modelo/reductor con permutaciones de 2–3 dispositivos, concurrencia, duplicados, huecos, corrupción y crashes; revisión de firmas/antecedentes y no resurrección. Formato, checkpoint, retención y límites están seleccionados en §9; no requieren esas pruebas ejecutadas para definirlos.

**Estado histórico de §§1–8 sustituido por §9:** R17 permanece; el contrato posterior elige realización/servidor sin implementar ni autorizar desarrollo.

## 9. Contrato G5 seleccionado — cierre documental

**2026-09-12, selección de ingeniería al completar los contratos solicitados.** Esta sección concreta y sustituye los pendientes/propuestas de realización de §§1–8; conserva su razonamiento, R17 y ADR 0002. No declara demostrado un CRDT, seguridad criptográfica ni convergencia ejecutada. No requiere implementar un modelo para poder especificarlo.

### 9.1 Tipos y autenticación de eventos

Se adopta el CBOR determinista y las envolturas G2. Las reglas siguientes son **diseño propio**, no propiedades que una RFC o SQLite prueben por nosotros. CBOR fija bytes inequívocos y SQLite la transacción local, no autoridad distribuida. [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1), [atomicidad SQLite](https://sqlite.org/atomiccommit.html).

- `id`: 16 bytes aleatorios; `digest`: SHA-256 de bytes canónicos completos; `generation` y `seq`: uint64 desde 1, sin wrap; `modified_at`: int64 de microsegundos Unix en todo su rango. Rechazar overflow/conversión, no limitar por reloj actual una revisión recibida ni corregir su timestamp. Comparador de contenido: máximo `(modified_at, issuer_device_id, revision_id)` binario, sin mezcla de campos. Timestamp fuente importado se preserva aparte de timestamp de escritura de importación.
- Evento `E={v:1,vault,event_id,authority_epoch,issuer_device,issuer_generation,seq,prev,parents,kind,subject,subject_generation,body}`. `prev` es digest del anterior evento de ese emisor/generación o null en secuencia 1 y, si no es null, debe figurar en parents; `parents` contiene digests ordenados sin duplicados de las cabezas conocidas y de todos los antecedentes específicos de la operación. `subject` identifica el objeto estable, no su nombre. Un campo no aplicable es null, no ambiguamente ausente.
- `event_digest=SHA256(CBOR(E))`. Firma de dispositivo `Sig_D=Ed25519(SK_SD,CBOR(['pm/device-event/v1',E]))`. **SK_SD/PK_SD** es un par nuevo de firma de dispositivo, protegido nativamente como SK_D pero distinto de envoltura y TLS. El alta humana vincula sus públicas, generación, dispositivo y bóveda. La clave solo acredita procedencia; no concede administración humana. [Semántica de firma](https://doc.libsodium.org/public-key_cryptography/public-key_signatures).
- `human_sig=Ed25519(SK_H,CBOR(['pm/human-event/v1',E]))` obligatorio para mutación de contenido, altas, habilitación, retirada, restauración, purga y transición de raíz. Eventos técnicos `join`, `receipt`, `checkpoint-cache` solo llevan Sig_D y no modifican contenido ni autoridad. Sobre firmado `S={event:E,device_signature,human_signature}` (null para evento técnico); referencias de `prev/parents` son `event_digest`, no hashes del cifrado aleatorio. El paquete cifrado de control K_O por evento y sus sobres humanos/dispositivo son los de G2; no publicar metadata de autoridad al servidor.
- `body` es unión cerrada por `kind`, ver tabla siguiente. Límite 256 KiB por evento, 4096 parents, profundidad 16. Un emisor con más cabezas crea eventos `join` para reducirlas antes de una acción; un join solo declara causalidad, nunca es voto. Dos eventos distintos con mismo `(issuer,generation,seq)` son fork: conservar ambos, denegar concesiones positivas de esa rama hasta una sustitución humana con antecedentes de ambas; no elegir por timestamp. El contenido firmado humano no se pierde: permanece como recuperación inspeccionable.

| `kind` | Campos exactos de `body` además del sobre común |
|---|---|
| `item-revision` | `revision_id,modified_at,manifest_digest,previous_revisions[]`; referencias de partes y claves están en manifiesto G2/G6. No habilita por sí mismo. |
| `device-grant` / `agent-grant` | `request_id,public_identity,predecessor_grants[],expires_at`; device añade `wrap_public_key,event_public_key`; agent añade `environment_binding`. Sustitución reconoce todos los grants/retiradas conocidos. |
| `enable` / `resume` | `prior_positive_events[],withdrawals_seen[]`; enable añade `revision_id,grant_commitments[]`. Resume global no habilita una credencial individual. |
| `disable` / `suspend` / `agent-revoke` | `reason_code`; sujeto identifica credencial/global/agente, sin texto libre sensible. |
| `device-retire` | `reason_code,accepted_prefix:{generation,seq,tip_digest}` para cada generación conocida del sujeto; lista vacía conserva cero operaciones positivas del emisor. |
| `trash` / `restore` | `deletions_seen[]`; restore reconoce todas las eliminaciones conocidas y no habilita la credencial. |
| `purge-item` / `purge-revisions` | `item_id,revision_ids[],scope`; `scope=item` es terminal para ID, `scope=revisions` solo retira revisiones no activas. Validar contra la vista causal completa del propio evento que ninguna revisión objetivo sea ganadora LWW allí; no usar la revisión activa del receptor según llegada. Purga admitida es monotónica incluso frente a eventos concurrentes; excluir siempre esos IDs de candidatos visibles. |
| `join` / `receipt` | join `{}`; receipt `{received_heads[],applied_state_digest}`: diagnóstico verificable, no permiso ni prueba de actualidad global. |
| `checkpoint-cache` | `covered_heads[],state_digest,index_parts[]`; cache de estado, no autoridad nueva ni permiso para olvidar retiros. |
| `root-transition` | `next_epoch,next_public_key,accepted_heads[],new_key_proof`; firma humana de raíz antigua y prueba de raíz nueva según §9.4. |

Para evitar una referencia circular, `grant_commitments` es SHA-256 de CBOR del objeto G de G2 **sin** `authority_event`; se preparan sealed boxes y campos G primero, se firma el evento enable y después se completa `G.authority_event=event_digest` y su firma. Verificar ambos vínculos al recibir; no calcular el hash del grant completo dentro del evento que ese mismo grant referencia.

Arrays de IDs/digests van ordenados binariamente sin duplicados; razones son enums `owner_request`, `replacement`, `suspected_compromise`. No usar `reason` como política externa. Transacciones con muchas revisiones usan manifiesto paginado con partes autenticadas ≤256 KiB y commit de digest raíz; ningún fragmento activa una mitad de importación.

### 9.2 Reductor determinista y disponibilidad

Para un conjunto de paquetes recibidos, en este orden lógico (aplicación local en una transacción):

1. Comprobar límites, AEAD, dominio/bóveda/época, firmas bajo claves previamente confiables, hash y estructura de DAG. No activar eventos con parents desconocidos; indexar pendientes por digest. El emisor no prueba confianza enviando su propia pública. Ignorar duplicados idénticos; corrupción queda en cuarentena acotada. Una retirada firmada por raíz ya confiable puede establecer denegación provisional del sujeto aun con huecos; no puede conceder acceso provisional.
2. Conservar el conjunto monotónico de **retiradas humanas verificadas** (`suspend`, `disable`, `agent-revoke`, `device-retire`, `trash`, purgas). Una retirada posterior del emisor no borra esas denegaciones ya acreditadas bajo la raíz; de lo contrario revocaciones cruzadas podrían reactivarse mutuamente. Estas operaciones requieren firma SK_H: SK_SD robada sola no permite emitirlas. Un evento negativo con firma humana válida no es una nueva concesión del dispositivo retirado. Su posible abuso si SK_H fue comprometida se trata como compromiso de raíz, no se resuelve con cortes de dispositivo.
3. Calcular fronteras de emisor retirado: para cada generación, aceptar como operaciones **positivas** únicamente el prefijo hash-encadenado referido por todos los `accepted_prefix` de sus retiradas verificadas. Varias retiradas intersectan prefijos; si divergen, conservar solo ancestro común. No decidir por llegada ni reloj. Ramas fuera del corte conservan datos como candidatos humanos de recuperación, no conceden autoridad; importarlos de nuevo crea revisiones con emisor vigente. Un corte jamás elimina la evidencia de una retirada del paso 2. Revocaciones cruzadas dejan ambos emisores retirados; no invalidan entre sí la denegación.
4. Para un control C, `D(C)` es el conjunto de retiradas verificadas relevantes. Una positiva P habilita solo si **cada** d de D(C) es ancestro estricto de P, P pasa la frontera anterior y sus dependencias están completas. Inicialmente nada está habilitado; ausencia de retirada no sustituye concesión. `withdrawals_seen` debe corresponder a las retiradas conocidas en su cierre causal; no se confía en esa lista sin comprobar parents.
5. Revocar una generación es terminal. Alta nueva: generación `1+max(conocidas)` sin overflow y parents que incluyan grants/retiradas anteriores; con grants concurrentes incompatibles, ninguna clave se activa hasta alta sucesora que reconozca ambas. No se elige identidad ganadora por LWW. Generación nueva creada ignorando una retirada del sujeto estable no la esquiva. Activación sigue requiriendo prueba de posesión local G4.
6. Para elemento no purgado, seleccionar máximo LWW entre revisiones completas/admisibles. Historial conserva perdedoras salvo purga humana. `trash` prevalece hasta un `restore` humano posterior a **todas** las eliminaciones; nuevo trash concurrente gana otra vez. Purga-item es terminal, elimina uso aunque exista restore concurrente; recreación deliberada usa ID nuevo. Purga-revisions impide reimportar automáticamente esas revisiones por replay, no borra otras; la admisibilidad se verifica en su vista causal (§9.1), no por la revisión visible al recibirla.
7. Uso delegado requiere conjunción: agente vigente, dispositivo vigente, global reanudado, elemento activo/no purgado, enable vigente, revisión y sobre coherentes para custodio, perfil G3 disponible. Edición de habilitada trae provisión de nueva revisión, pero nunca revierte disable/trash. Si ganó revisión aún incompleta, mantener último estado completo **solo mientras ninguna retirada conocida lo deniegue**, informar sync pendiente. No fallback tras fallo externo ni selección de revision libre por agente.

Los pasos no consultan «quién llegó primero». Causalidad afecta autoridad/ciclo de vida; solo el contenido usa timestamp. Una firma/AEAD correcta no demuestra que el servidor haya mostrado todas las ramas. Con mismos eventos válidos completos y raíz confiable, estas reglas definen un mismo resultado; las pruebas de permutaciones deben comprobarlo, no se afirma teorema ni implementación validada.

### 9.3 Checkpoints, retención y límites

**Elección conservadora:** historial, papelera y auditoría sin caducidad automática; purga humana explícita con alcance y consecuencias visibles. No atribuir al usuario un plazo que no seleccionó. Política v1 `manual`: sin temporizador de caducidad; la TUI permite purgar elementos, revisiones históricas o auditoría con alcance explícito. No se declara un planificador de eliminación automática ni se decide borrar por presión de cuota. Historial de intentos/resultados efímeros mantiene los plazos distintos de G4.

Un checkpoint **no trunca la historia de autoridad**. Es cache firmada por dispositivo sobre `covered_heads`, estado reducido y páginas de índice. Se acepta solo tras comprobar esos eventos y recomputar su digest, o como punto provisionado por humano durante emparejamiento con su evidencia conservada; el servidor no lo convierte en raíz. Nuevos eventos no cubiertos se incorporan y recalculan normalmente. Checkpoints concurrentes no compiten como permisos: son caches de conjuntos distintos.

**Compactación elegida:** descartar índices derivados/caches antiguos y payloads secretos purgados; conservar permanentemente headers firmados de eventos, parents, hashes de revisión, generaciones y marcadores mínimos de purga/revocación. No conservar título, cuenta, destino, secreto ni contenido purgado en un marcador. Los headers referencian digests de manifiestos/partes, nunca su plaintext; retirar payload no impide verificar la firma del header. El historial no purgado conserva sus partes cifradas. Antecedentes no se borran por timeout ni acuse de servidor. Esta decisión resuelve checkpoint sin exigir quorum ni reconexión obligatoria a dispositivos offline: acepta crecimiento de metadata de seguridad a cambio de no olvidar autoridad.

Defaults operativos: máximo 256 MiB de recepción **no verificada** por custodio y 4096 eventos pendientes de antecedentes; llegada excesiva detiene esa descarga con `SYNC_BACKPRESSURE`, no borra estado válido. Aplicación por lotes ≤256 eventos, hash/verificación incremental y cola persistida cifrada. Metadata de seguridad crece en disco: aviso a 1 GiB y luego cada duplicación; no límite que borre datos. Con espacio insuficiente no aceptar nuevas escrituras/usos que requieran commit durable; lectura humana/exportación cifrada disponible si integridad lo permite. El humano libera espacio/purga contenido, no elimina marcadores antirreplay para forzar avance. No garantía de almacenamiento infinito.

Una reinstalación sin toda evidencia anterior no prueba ausencia de retiradas. Si no existe dispositivo confiable para reconciliar, recuperación crea un **linaje nuevo sin agentes activos** G6; no restaura la autoridad antigua como si fuera vigente. La purga no borra backups/snapshots externos ni claves que un custodio retirado ya copió.

### 9.4 Raíz de autoridad y composición G2/G4

Alta inicial fija `(vault,authority_epoch=1,PK_H)` por canal humano G4. `SK_SD` firma procedencia/recibos, nunca reemplaza SK_H. Todo control se cifra con K_O nuevo, sobres a dispositivos vigentes conocidos y sobre humano; recibir un evento no exige desbloquear TUI. Provisionar dispositivo nuevo es operación humana que reenvuelve control y material habilitado, no tarea del servidor ni del agente.

Rotación planificada de SK_H: `root-transition` firmado con SK_H antigua y prueba de posesión de nueva SK_H sobre CBOR `['pm/root-transition/v1',E sin body.new_key_proof]`; construir esa prueba primero y luego firmar E completo con la antigua, sin autorreferencia; next_epoch = actual+1. Aceptar transición únicamente desde raíz previamente fijada, causalmente completa y sin transición hermana incompatible. Sellar `accepted_heads`: positivos de la raíz anterior fuera de ese corte no activan autoridad; datos nuevos de esa rama quedan recuperación humana. Retiradas conocidas no se olvidan. Publicar nueva raíz y provisión sin destruir la única vía de backup verificable. Rotaciones concurrentes incompatibles bloquean nueva delegación hasta reconciliación humana por canal confiable, no eligen clave por número/timestamp.

Si SK_H/K_H pudo copiarse, **no confiar en una transición enviada por red bajo la clave comprometida**. Recuperación G7/G6 en entorno limpio crea nuevo vault/raíces/identidades, recifra datos revisados y vuelve a registrar dispositivos/agentes por canal humano. Conserva linaje anterior como datos de procedencia, nunca permiso. No promete revocar passwords externas ni neutralizar equipos offline de la bóveda vieja.

### 9.5 Transporte de sincronización autohospedado

Se selecciona **servicio mínimo propio Rust + SQLite** sobre el mismo stack ya escogido, sin SaaS ni cuenta pública. Almacena bloques opacos inmutables por SHA-256 de ciphertext y un índice por namespace aleatorio. No recibe K_H/K_O/K_A ni plaintext de manifiestos. No sincronizar SQLite/WAL de los custodios.

Canal de sync separado de agente/humano, TLS1.3/RPK fijado según G4. Operador local del servidor registra públicas de transporte de dispositivos y namespace mediante administración local; el humano empareja pin del servidor y namespace con el custodio. Esa ACL protege recursos/descarga, **no decide autoridad de bóveda**. Retirar un dispositivo deniega provisión cifrada futura aunque servidor desobedezca su ACL; no prueba borrado remoto. Pin o namespace no se entregan como secreto de autenticación externa al agente.

RPC sync v1 con framing privado G4 y métodos cerrados: `sync.put{namespace,hash,bytes}`, `sync.get{namespace,hash}`, `sync.publish{namespace,root_hash}`, `sync.list{namespace,cursor?,limit}` y `sync.delete{namespace,hashes}`. Bytes base64 en JSON, bloque ≤512 KiB y frame ≤1 MiB; hash SHA-256 de bytes decodificados verificado en ambos extremos, put repetido mismos bytes idempotente. Publish registra un root de paquete operativo G2 recuperable por dispositivo, ≤512 KiB; sus partes grandes se referencian por hash. Publish repetido mismo root es idempotente y no acredita integridad ni autoridad. List enumera solo roots publicados, no obliga a descifrar todos los bloques de archivos como control. List limit 1–256/default128, cursor opaco ≤512 bytes; no certeza de completitud ni orden autoritativo. Delete es solicitud física de housekeeping sobre bloques ya purgados, no evento lógico de borrado. Cliente solo solicita borrar bloques sin referencias locales no purgadas; omisiones/copias de otros dispositivos/servidor siguen límite conocido.

Objetos grandes se transportan en bloques ordenados: descriptor cifrado autenticado contiene longitud total, hash de ciphertext completo y páginas de `{index,block_hash,length}`; índices contiguos desde 0, sin duplicados/huecos. Descriptor grande se pagina en partes ≤256 KiB, digest raíz incluido en manifiesto firmado. Se verifica objeto completo antes de activarlo; para archivos G2 se verifican además secretstream y TAG_FINAL. Servidor solo enumera hashes: cliente ignora bloques huérfanos; no abre objetos solo porque se publicaron.

Timeout request 30 s; reintento de los mismos hashes con backoff 1,2,4,8,16,30 s máximo, suspendido al desconectar/saturar. No dispara autenticaciones externas. Escritura local y outbox atómicas; confirmación remota no reemplaza commit local. Sin servidor configurado estos componentes no se requieren para operar.

### 9.6 Criterios verificables y cierre

Además de V14–V18, los futuros tests deben cubrir: revocaciones cruzadas; intersección de cortes con fork; grant de generación nueva concurrente con retirada; root transitions hermanas; checkpoint recibido antes de parents; payload purgado con headers todavía verificables; mezcla de disable/trash/restore/purge; recepción saturada sin perder denegación; pérdida de respuesta put/delete; restitución de backup viejo sin autoridad activa. Oráculo: mismas entradas válidas → mismo digest de estado; ningún orden/duplicado produce privilegio extra; una rama desconocida no permite afirmar actualidad global.

**G5 cerrado documentalmente:** reductor, formatos, cortes, retención, checkpoint y transporte elegidos. No se ejecutaron modelo, fixtures, servidor ni pruebas; su ejecución/revisión independiente es validación posterior, no otra elección de diseño pendiente.
