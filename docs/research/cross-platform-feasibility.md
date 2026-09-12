# Viabilidad: Windows junto a Linux/macOS desde el inicio

Investigación documental, 2026-09-12. No implementa ni elige stack. **No hay pruebas runtime Windows/macOS realizadas aquí.**

## Conclusión — inferencia de arquitectura, no garantía probada

**No se identificó una imposibilidad inherente de incluir Windows desde el inicio** para un motor custodio de secretos con CLI, MCP y TUI, sin Electron. Las fuentes muestran primitivas suficientes para plantearlo; el costo adicional es implementación y validación específica de plataforma, especialmente identidad, custodia de claves, IPC, instalación y reinicio desatendido. Una TUI portable no convierte automáticamente en portable ni seguro el motor.

## Hechos verificados

### Superficie portable

- Ratatui ofrece backends de terminal y recomienda Crossterm cuando importa Windows. El repositorio de Crossterm enumera terminales probados en Windows, Linux y macOS. Esto es evidencia de una ruta TUI sin navegador embebido, **no una selección de Rust/Ratatui ni una garantía para cualquier terminal**. Fuentes: [comparación Ratatui](https://ratatui.rs/concepts/backends/comparison/), [Crossterm: Tested Terminals](https://github.com/crossterm-rs/crossterm#tested-terminals).
- MCP define mensajes JSON-RPC sobre stdio o Streamable HTTP. En stdio el cliente lanza el servidor como subproceso y puede capturar stderr. **Inferencia:** un adaptador MCP que vive junto al agente puede ser portable, pero no debe convertirse en el custodio de la bóveda; debe dirigirse al motor aislado y jamás emitir secretos en mensajes/logs. Fuente: [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

### Windows: piezas específicas

- **DPAPI no es una frontera por aplicación.** `CryptProtectData` normalmente vincula descifrado a credenciales de inicio de sesión y equipo. Con `CRYPTPROTECT_LOCAL_MACHINE`, cualquier usuario del equipo puede descifrar el blob si obtiene acceso a él. Ofrece un camino no interactivo; eso no autentica a un agente ni restringe una operación autorizada. **Inferencia:** DPAPI puede proteger material de desbloqueo bajo la identidad custodia, pero no basta si el agente comparte esa identidad o accede a su contexto. Fuente: [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
- Cada servicio ejecuta bajo una cuenta; SCM carga el perfil y crea un token para ella. Los SID por servicio permiten ACL específicas sin depender de LocalSystem. **Inferencia:** es viable diseñar un motor con identidad distinta a los agentes y mínimo privilegio; escoger cuenta, SID y ACL requiere validar el conjunto, no activar un único flag. Fuentes: [Service User Accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts), [SERVICE_SID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).
- SCM admite inicio automático tras reinicio **sin usuario conectado**. Esto prueba disponibilidad del mecanismo de arranque, no que la clave, perfil, bóveda, disco o red estén disponibles. Fuente: [sc.exe create, start=auto](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create).
- Los servicios no deben presentar UI directamente; Microsoft recomienda aplicación de sesión separada e IPC. Los named pipes admiten DACL; su configuración predeterminada puede conceder lectura a Everyone/Anonymous. **Inferencia:** separar endpoints/operaciones de administración humana y uso delegado; autenticar el contexto llamante y establecer ACL explícitas. Fuentes: [Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services), [Named Pipe Security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
- Crear servicios requiere privilegios administrativos; derechos como `SERVICE_CHANGE_CONFIG` permiten cambiar el ejecutable. Windows también controla lectura/escritura de memoria mediante derechos de proceso. **Consecuencia de diseño:** agentes sin facultad administrativa sobre custodio, binarios, configuración, ACL ni mecanismos de actualización; excluir administrador/kernel comprometido de una garantía ordinaria de aislamiento. Fuentes: [Service Security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), [Process Security](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

### No copiar semánticas entre sistemas

- Apple documenta keychains de usuario y de sistema y aclara que macOS no aplica directamente el mismo mecanismo Data Protection que sus otras plataformas. No trasladar sin más las clases/garantías de iOS. Fuente: [Apple Platform Security: Keychain](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web).
- Arranque por usuario no equivale a arranque sin login: Apple distingue agentes de sesión de daemons de sistema en su [guía arquitectónica archivada de launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html); systemd documenta `enable-linger` para servicios de usuario que sobreviven al logout y arrancan al boot. Son modelos distintos que requieren adaptadores propios; no se prescribe aquí instalación macOS con APIs archivadas. Fuente Linux: [loginctl](https://www.freedesktop.org/software/systemd/man/252/loginctl.html).

## Recomendación y condiciones de aceptación

Mantener un contrato de producto común y adaptadores por SO para **almacenamiento de claves, identidad/aislamiento, IPC autenticado, ciclo de vida y distribución**. Diseñar estados independientes: «UI humana bloqueada», «autorización delegada persistente» y «motor capaz de usar una credencial»; cerrar la TUI no debe revocar implícitamente lo delegado, salvo política explícita.

Antes de anunciar soporte equivalente, probar por SO: arranque frío antes/después de login; sesión bloqueada/logout; recuperación de clave; revocación persistente; denegación de lectura de archivos/memoria del custodio; denegación de administración/reemplazo del servicio por agentes; IPC de otro usuario/cliente no autorizado; actualización y recuperación. Un grant persistente no basta si la clave quedó inaccesible tras reboot. Si el disco exige desbloqueo humano antes de arrancar el SO, «autónomo tras reinicio» debe delimitarse o incorporar un mecanismo de bootstrap aprobado: el servicio no elimina ese requisito.

**Pendiente:** versiones/ediciones/arquitecturas soportadas, terminales, empaquetado y pruebas nativas. WSL no debe contarse como evidencia de aislamiento o custodia nativos de Windows. Esta revisión avala factibilidad documental, no seguridad auditada ni paridad ya entregada.
