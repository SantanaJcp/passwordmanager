# Aislamiento, stack y perfiles de despliegue seleccionados

Fecha: 2026-09-12. Estado: **selección de ingeniería para la especificación** tras continuación solicitada; no aprobación explícita del usuario de APIs ni seguridad validada. G1: decisiones de stack/perfiles cerradas documentalmente; controles detallados G7 y distribución G8 se completan por separado.

Autoridad: [contrato R06–R14](../../.scratch/passwordmanager/spec.md), [vocabulario](../../CONTEXT.md), [ADR de responsabilidad única](../adr/0001-limite-de-responsabilidad-de-la-boveda.md). §4 fija perfiles y §8 stack/versiones de referencia; claves y transporte se fijan en sus diseños enlazados. No instala nada.

## 1. Elección de ingeniería

Separar tres dominios de ejecución: **humano propietario**, **custodio** y **agente**. Instalar el motor custodio como proceso persistente con identidad nativa propia y privilegios mínimos. La TUI permanece en el entorno humano; CLI/MCP delegados permanecen en el entorno del agente y no descifran secretos.

El aislamiento tiene que proteger tanto al custodio como al entorno humano. Separar únicamente el daemon no sirve si el agente puede leer la contraseña introducida en la TUI, capturar su portapapeles o sustituir el cliente humano. Es una consecuencia de R09/R10; las capacidades de inspección entre procesos Linux dependen de UID, dumpability y configuración, no de que tengan nombres distintos. [Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html).

**Compromiso visible:** no prometer instalación segura como un simple servidor MCP ejecutado junto a un agente irrestricto bajo la cuenta habitual del propietario. Hace falta preparar una separación real. La bóveda instala su custodia y documenta requisitos de integración; no se convierte en un orquestador de agentes, contenedores o máquinas virtuales.

## 2. Alternativas consideradas

| Alternativa | Ventaja | Coste o defecto | Recomendación |
|---|---|---|---|
| Motor dentro del MCP, mismo entorno que el agente | Instalación simple. | El proceso que usa secretos queda dentro del entorno controlado por el agente. | Rechazar como perfil de garantía R09. |
| Custodio dedicado; humano y agentes con separación nativa efectiva en el mismo equipo | Sin exigir VM; integración local. | Requiere aislamiento de archivos, procesos, escritorio, IPC y administración; una cuenta distinta por sí sola no certifica todo eso. | Perfil local candidato, sujeto a pruebas por OS. |
| Custodio y humano en host confiable; agentes en VM o equipo separado | Hace explícita la separación operativa entre entornos. | Canal autenticado, recursos adicionales y cuidado con integraciones host/guest. No es prueba automática contra escape o mala configuración. | Perfil de referencia conservador para validar la arquitectura, sin imponer un hipervisor ni volverlo requisito funcional universal. |

Son evaluaciones de diseño apoyadas por [la investigación G1](../research/g1-stack-and-custody.md), no resultados comparativos medidos. No certificar contenedores genéricos ni cuentas separadas por etiqueta: cada perfil debe cumplir las mismas pruebas.

## 3. Responsabilidades y canales

```text
Entorno humano                         Entorno custodio
TUI / CLI humana -- canal humano --->  Motor + almacenamiento cifrado
                                             |
Entorno del agente                           +--> adaptador confiable
Agente -> CLI/MCP -- canal delegado --------> |    de autenticación -> destino
```

Las flechas representan contratos, no transportes elegidos. Un adaptador que vea un secreto pertenece al dominio confiable de custodia, aunque su implementación use otro proceso. El contexto de login web no puede quedar bajo instrumentación del agente mientras contenga el secreto. La entrega del resultado es trabajo pendiente de cada integración, no autorización para administrar su sesión posterior. [Matriz G3](../research/g3-authentication-integrations.md).

| Actor | Puede obtener | No debe obtener/controlar |
|---|---|---|
| Humano autenticado | Administración completa y revelado explícito mediante TUI/CLI humana. | Su autoridad no se transmite por compartir ejecutable o dispositivo con un agente. |
| Agente registrado | Metadatos habilitados, uso por ID, estado y resultado permitido de sus intentos. | Secretos, exportación, API humana, almacenamiento, configuración, binarios o administración del custodio. |
| Custodio en modo delegado | Material necesario para usar el conjunto común y verificar autorización. | No necesita la raíz humana completa durante operación desatendida. La [jerarquía elegida](key-hierarchy.md) concreta esa separación. |
| Servidor de sincronización | Sobres cifrados y metadata de transporte declarada. | Claves de descifrado o autoridad implícita para registrar agentes. |

Contrato de referencia: [§§5–9 de la especificación](../../.scratch/passwordmanager/spec.md). El módulo de custodia concentra autorización y uso de credenciales; los clientes no reproducen esa lógica. La separación de canales se verifica en el motor, no ocultando métodos en el listado MCP.

### Identidad: dos comprobaciones distintas

1. **Identidad del entorno/canal:** acreditar quién conecta y que conecta al custodio auténtico. Permisos nativos para canales locales; canal cifrado y autenticado mutuamente para cruzar entornos. No confiar en dirección IP, nombre del proceso ni un campo `agent_id` enviado por el cliente.
2. **Registro individual:** prueba de posesión de una identidad de agente aprobada por el humano, vinculada al dispositivo/entorno según el contrato que defina G4. Propuesta: claves de identidad distintas por agente, desafío y protección frente a replay mediante protocolos establecidos, no criptografía inventada.

El agente puede poseer material para acreditar **su propia identidad**; no es la contraseña maestra ni una credencial del proveedor. Compartir el conjunto de credenciales habilitadas no significa compartir identidad.

**Límite:** dos procesos con acceso a la misma clave de identidad pueden actuar como el mismo agente. Registrar dos nombres no los separa. Si se promete resistencia a suplantación entre agentes, sus claves necesitan dominios de acceso separados; una prueba de posesión no identifica por sí sola un modelo o una conversación. Este es un requisito de diseño pendiente de G4/G7, no una garantía de hardware asumida.

### Registro inicial propuesto

- La solicitud de alta no transporta secretos de la bóveda. El humano inicia o verifica el emparejamiento desde su canal confiable y comprueba el vínculo con el entorno previsto.
- La confirmación cubre una identidad y una solicitud concreta, con caducidad y protección frente a sustitución/replay. Un nombre amigable no es evidencia suficiente.
- El custodio registra la autorización; cada uso posterior vuelve a comprobar identidad, revocación, suspensión y habilitación actual.
- Rechazar peticiones humanas desde el canal delegado, aunque la TUI esté desbloqueada. No conceder permisos por un flag `--human` ni por poseer un ID de intento.

Este flujo concreta [R06–R08](../../.scratch/passwordmanager/spec.md); [identidad §7](agent-identity.md) fija wire y emparejamiento.

## 4. Perfiles nativos elegidos

Mismos tres dominios en todos los OS. El mínimo de versión es un **target de ingeniería**, no promesa de soportar sistemas sin parches ni prueba de los seis targets. Linux no-systemd no se declara imposible ni se elimina como portabilidad del motor/TUI; el perfil de servicio que se verifica primero es systemd, sin inventar un segundo init no validado.

| Plataforma/CPU | Instalación y custodia | Canal/clave tras reboot |
|---|---|---|
| Linux kernel ≥6.1, glibc ≥2.36, systemd ≥252; x86-64/AArch64 | Paquete nativo; servicio de sistema `User=passwordmanager`, cuenta sin login; binarios/config root-owned. | Dos sockets por ruta; `SO_PEERCRED` bilateral y TLS fijado; clave privada bootstrap `0400`, directorio custodio privado. |
| macOS ≥13; Intel/Apple silicon | `.pkg` firmado/notarizado, LaunchDaemon `UserName=_passwordmanager`, `ProgramArguments` absoluto; no SMAppService, bundle `.app` ni Electron. | Dos sockets Unix; `getpeereid` bilateral y TLS fijado; bootstrap `0400` de custodio, no Keychain dependiente de login. |
| Windows 11; x64/ARM64 MSVC | Servicio automático own-process en cuenta virtual `NT SERVICE\PasswordManager`; no LocalSystem interactivo. | Dos pipes locales con DACL explícita; SID cliente por identificación y servidor por SCM/PID **más** RPK fijada. Bootstrap DPAPI machine con DACL exclusiva custodio/SYSTEM; machine-scope sin ACL no aísla. |

Fundamento documental, APIs y pruebas nativas exactas en [G1: perfiles instalables](../research/g1-stack-and-custody.md#concreción-de-perfiles-instalables--continuación-de-ingeniería). En Windows no pedir `SeDebugPrivilege` a la TUI para inspeccionar tokens ajenos. La identidad nativa limita conexión y suplantación; no reemplaza registro ni firma humana. [Contrato TLS/RPK y canal humano](agent-identity.md).

**Compromiso de despliegue explícito:** volumen cifrado requerido en estos perfiles desatendidos para proteger la clave bootstrap frente a copia de disco. La bóveda no habilita ni administra FDE, TPM ni desbloqueo del SO por su cuenta. Tras desbloqueo del volumen, la clave delegada está disponible aunque la TUI esté bloqueada o no haya login humano. Unix protege la clave por cuenta/permisos/FDE, no por hardware sealing ni otra clave guardada al lado. Sin esta condición no se anuncia protección ante robo offline; no se instala/configura aquí y el efecto de exigir FDE debe mostrarse antes de instalación.

El instalador fija principal humano, identidades custodias y pública TLS en archivos de configuración no modificables por agente; el servicio nunca aprende la autoridad humana de un flag/campo enviado por el cliente. Privilegio administrador solo para instalación/control del servicio. Un host administrado por el agente queda fuera del perfil, no se arregla ocultando secretos en MCP.

Para VM/equipo separado, no exponer el canal humano por el canal delegado. Deshabilitar en el perfil soportado accesos al almacenamiento de la bóveda, escritorio, terminal, portapapeles humano y mecanismos de administración del host. Un directorio de proyecto compartido, si existe, no puede incluir esos recursos. Se elige TLS 1.3 RPK para transporte delegado; no se impone plataforma de virtualización ni se construye un orquestador de agentes.

## 5. Arranque, bloqueo y fallos

- **Instalación:** elevación explícita solo donde sea necesaria para crear identidad, permisos y arranque del custodio. No ejecutar permanentemente TUI o agentes como administrador del host custodio. No modificar esas configuraciones en esta etapa.
- **Reinicio:** iniciar custodia con estado persistente y comprobar integridad/autoridad antes de aceptar usos. Si faltan claves o garantías del perfil, devolver indisponibilidad de custodia, no entregar un secreto como alternativa. El desbloqueo de disco previo al arranque conserva el límite ya aprobado.
- **TUI bloqueada:** no habilita administración humana. La vía delegada puede continuar; no presentar esto como ausencia absoluta de capacidad de descifrado. Retención y limpieza de claves humanas requieren diseño G2, no se resuelven cerrando una ventana.
- **Suspensión/revocación:** denegar nuevos usos conocidos localmente y revalidar antes de utilizar el secreto o reanudar un desafío. No se puede retirar una credencial ya transmitida al proveedor ni deshacer una autenticación consumada. Documentar la carrera exacta en G4/G7, sin prometer logout.
- **Offline:** aplicar última autoridad conocida; una revocación remota desconocida no puede tener efecto inmediato. Cifrado del transporte no resuelve antigüedad del estado.
- **Desafío humano:** pausar solo ese intento; resolución por evidencia de la integración, no por un mensaje no verificado del agente. No fallback ni reintentos de login continuos.

Estas reglas conservan [R09–R18 y estados §§8–10](../../.scratch/passwordmanager/spec.md).

## 6. Evidencia que refutaría el diseño

Pruebas propuestas por interfaz pública, con datos sintéticos, para cada perfil/OS:

| Prueba negativa | Criterio requerido |
|---|---|
| Agente lee memoria/archivos de custodio, TUI, terminal o portapapeles humano. | Acceso denegado por el entorno soportado; no basta redacción de logs. |
| Agente sustituye binario, configuración, endpoint o mecanismo de arranque. | No puede modificar custodia ni engañar al cliente para que entregue autoridad humana. |
| Agente usa canal humano o falsifica identidad/ID de intento. | Rechazo también con TUI desbloqueada; sin filtrar información no habilitada. |
| Un agente roba identidad de otro desde recursos compartidos. | Negación dentro del perfil que promete separación entre agentes; no certificar un perfil con almacén común legible. |
| Reinicio con TUI bloqueada o suspensión persistente. | Delegación autorizada funciona cuando claves/OS están disponibles; suspensión no desaparece. |
| Revocación o cancelación durante desafío. | No reanuda un intento inválido ni cambia silenciosamente de método. |
| Adaptador refleja secreto por error, DOM, red o resultado. | Integración no se anuncia compatible mientras exista esa vía, aunque el daemon esté aislado. |
| Se pierde el aislamiento configurado. | Rechazo ante fallos detectables; no prometer detectar cualquier cambio externo o administrador comprometido. |

Además del resultado de login, conservar evidencia de permisos, procesos, canales y versiones realmente probados. Relación con [V03–V13, V20, V23 y V27](../../.scratch/passwordmanager/spec.md).

## 7. Resultado de esta etapa

La elección es **custodio dedicado + humano separado + agente aislado**, con perfiles nativos concretos y clave disponible después del desbloqueo del disco. [Identidad](agent-identity.md) y [claves](key-hierarchy.md) fijan su realización. G1 ya no conserva como decisiones abiertas el lenguaje, init macOS o mecanismo de peer; resta evidencia nativa, no otra encuesta de alternativas.

No se afirma aislamiento validado: comprobar lectura de memoria/TUI/archivos, peer impostor, reinicio y FDE en cada target. Los controles operativos exhaustivos y actualización segura se completan en G7/G8; el bloqueo técnico de flujo web pertenece a G3. No hay nuevo ADR aceptado, tickets ni autorización de implementación.

## 8. Stack seleccionado y alcance de las versiones

**Elección:** Rust para motor y clientes, sin runtime Electron. Go/Bubble Tea queda como alternativa evaluada descartada, no segunda implementación. Motivo: un motor de dominio compartido con control explícito de vida de claves y adaptadores nativos; no afirmar seguridad por lenguaje ni rendimiento medido.

| Responsabilidad | Baseline de ingeniería y fundamento |
|---|---|
| Lenguaje/toolchain | **Rust 1.98.1**, edición 2024; toolchain reproducible al implementar, no `stable` flotante. [Anuncio oficial](https://blog.rust-lang.org/2026/09/03/Rust-1.98.1/). |
| TUI | **Ratatui 0.30.2 + Crossterm 0.29.0**, backend único. Usar versión compatible/reexport para evitar estados de terminal duplicados; [documentación](https://ratatui.rs/concepts/backends/). |
| Persistencia | **rusqlite 0.40.2**, SQLite bundled, escritor único custodio; objetos cifrados antes de SQLite, sin índices plaintext de títulos/contraseñas. WAL y transacciones, `synchronous=FULL`; backup lógico de producto, no copiar solo `.db`. [Binding](https://docs.rs/rusqlite/0.40.2/rusqlite/), [WAL](https://sqlite.org/wal.html), [synchronous](https://sqlite.org/pragma.html#pragma_synchronous). |
| Criptografía de bóveda | **libsodium 1.0.22 + libsodium-sys-stable 1.24.0** según [formato v1](key-hierarchy.md). Un módulo seguro acota FFI/zeroización; sin framework genérico de proveedores de secretos. |
| Transporte | **rustls 0.23.44**, proveedor aws-lc-rs, contrato RPK de [identidad §4](agent-identity.md). Crypto TLS separada de cifrado del archivo; no reutilizar claves. |
| Codificación autenticada | **minicbor 2.3.0**, encoder/decoder tipados; el perfil determinista y rechazo de malformados se comprueban explícitamente, no se presumen por el codec. [API](https://docs.rs/minicbor/2.3.0/minicbor/). |
| APIs del SO | **libc 0.2.189** Unix y **windows-sys 0.61.2** Windows, FFI confinado por plataforma; no replicar structs nativos a mano. [libc](https://docs.rs/libc/0.2.189/libc/), [Windows](https://docs.rs/windows-sys/0.61.2/windows_sys/Win32/index.html). |

Versiones **consultadas y elegidas para diseñar**, no grafo Cargo resuelto ni prueba ABI. No hay Cargo/rustc en este entorno, no se instalaron. Al autorizar implementación se fijarán lockfile, hash de distribución C y transitorias; actualizaciones de seguridad pueden ajustar patch sin reabrir decisiones de dominio. No generar manifiestos ficticios para aparentar build validada. El binding libsodium permite archivos locales/prefijos compilados; **prohibir fetch-latest y descargas implícitas durante build**, incluidos binarios Windows por default. Usar distribución previamente verificada/hash fijado, sin confiar solo en un tag movible. [Configuración de build](https://docs.rs/crate/libsodium-sys-stable/1.24.0), [aclaración upstream sobre tarballs 1.0.22](https://github.com/jedisct1/libsodium/discussions/1533). Auditoría de licencias/artefactos en G8.

Terminal: TTY UTF-8 interactiva con movimiento de cursor, entrada raw y resize; no exigir mouse, truecolor, Nerd Fonts ni teclado propietario. Piso de layout 80×24; debajo, pantalla de redimensionado sin revelar campos. Matriz de aceptación inicial: Ghostty en Linux, Terminal.app en macOS, Windows Terminal/ConPTY; rutas ASCII y color básico mantienen todas las funciones. No emitir secuencias de control contenidas en etiquetas/importaciones; presentación sanitizada nunca modifica el valor secreto guardado. Copiar requiere integración nativa explícita, no OSC52 oculto. Versiones de cada terminal se registran en las pruebas, no se deducen de la versión del compilador.
