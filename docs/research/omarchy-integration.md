# Password manager: integración con Omarchy

Investigación de solo lectura del sistema, 2026-09-12. No se instaló ningún plugin ni se cambió configuración. Propuestas, no decisiones aprobadas.

**Actualización tras confirmación del contrato:** la interfaz humana será una TUI completa y portable, no una aplicación gráfica separada. El plugin Omarchy queda para otro repositorio y una etapa posterior. Las recomendaciones de UI siguientes son históricas; prevalece la [especificación v0.1](../../.scratch/passwordmanager/spec.md). También se acordaron agentes aislados sin administración del custodio y exclusión de sesiones externas de la garantía.

## Hechos verificados

- **Entorno instalado:** `omarchy version` y `pacman -Q omarchy quickshell` reportan Omarchy **4.0.3-1** y Quickshell **0.3.1-1**. No usar `/usr/share/omarchy/version` para identificar la versión instalada: contiene `4.0.0.alpha`; el comando consulta los paquetes. Fuente: [/usr/share/omarchy/bin/omarchy-version:20–28](/usr/share/omarchy/bin/omarchy-version#L20).
- **Sí hay plugins reales.** Son componentes QML cargados en un único proceso Quickshell por sesión gráfica. Pueden aportar widgets de barra, paneles, overlays, menús, servicios sin UI o una barra completa. Un `service` de plugin sigue siendo un componente dentro del shell, no un daemon aislado. Fuentes: [/usr/share/omarchy/shell/README.md:3–14,74–98](/usr/share/omarchy/shell/README.md#L3), [manual oficial](https://omarchy.org/manual/shell-plugins/).
- **Contrato:** `manifest.json`, `schemaVersion: 1`, ID, nombre, versión, `kinds` y `entryPoints`; el registro verifica rutas relativas de entrada. El host ofrece interfaces acotadas a plugins externos y las invocaciones del shell permiten abrir/cerrar componentes por IPC. Fuentes: [/usr/share/omarchy/shell/services/PluginRegistry.qml:36–89](/usr/share/omarchy/shell/services/PluginRegistry.qml#L36), [/usr/share/omarchy/shell/README.md:172–210](/usr/share/omarchy/shell/README.md#L172).
- **No son un sandbox.** Comparten proceso y escena visual; las interfaces acotadas no aíslan el árbol QML. La documentación vigente advierte que ejecutan con permisos del usuario. El código local contiene protecciones específicas para servicios de autenticación propios, pero no convierte al shell en una bóveda aislada para terceros. Fuentes: [/usr/share/omarchy/shell/services/PluginShellApi.qml:3–9](/usr/share/omarchy/shell/services/PluginShellApi.qml#L3), [/usr/share/omarchy/shell/shell.qml:894–942](/usr/share/omarchy/shell/shell.qml#L894), [guía de desarrollo](https://plugins.omarchy.org/develop.html).
- **Distribución:** un repositorio Git con manifest raíz se clona en `~/.config/omarchy/plugins/<id>/`; las actualizaciones usan fast-forward y revisión del diff. El instalador no ejecuta hooks ni `sudo`; no instala por sí solo un servicio privilegiado o todas las dependencias externas. En el código instalado, operaciones sin terminal requieren `--yes`; habilitar necesita opción o confirmación explícita. Fuentes: [/usr/share/omarchy/shell/README.md:102–129](/usr/share/omarchy/shell/README.md#L102), [/usr/share/omarchy/bin/omarchy-plugin-add:26–33,149–174](/usr/share/omarchy/bin/omarchy-plugin-add#L26).
- **Marketplace:** publicar requiere repositorio GitHub público, manifest válido, README, licencia e instalación/desinstalación documentadas; una solicitud pasa validación y aprobación. La validación del catálogo **no es una auditoría de seguridad**. Fuente: [guía de publicación](https://plugins.omarchy.org/publish.html).

## Recomendación para el producto completo

**Aplicación desktop + núcleo de credenciales separado + plugin de integración Omarchy**, no una bóveda enteramente dentro de Quickshell.

1. Plugin: indicador de estado, acceso rápido y lanzamiento de la aplicación. Nada de contraseña maestra, secretos o material de sesión en propiedades QML, payloads del shell, notificaciones o configuración del plugin.
2. Aplicación propia: operaciones humanas sensibles y administración de la bóveda, fuera del proceso compartido del shell.
3. Núcleo propio: almacenamiento cifrado, desbloqueo y autenticación mediante adaptadores. CLI/MCP serían clientes acotados, no APIs generales de extracción de contraseñas.
4. Empaquetado separado para aplicación/núcleo y plugin; definir versiones compatibles, verificación de actualizaciones y tratamiento de dependencias. Esto no implica dejar funciones para después: son límites internos del producto completo.

Un precedente de integración ligera es el [plugin Basecamp oficial](https://github.com/basecamp/omarchy-basecamp-plugin), cuyo README declara que usa la CLI y no lee, copia ni almacena tokens. Es un ejemplo de separación, no prueba de aislamiento para nuestra amenaza.

## Decisiones abiertas y límites de esta investigación

- «El agente no recibe la contraseña» puede significar no introducirla en contexto/logs, o impedir técnicamente que un agente hostil la extraiga. La segunda promesa requiere un modelo de aislamiento verificable; **separar procesos, por sí solo, no demuestra esa garantía**.
- Precisar si el agente comparte usuario/sesión con el humano, qué acceso tendrá al navegador y si se promete proteger también cookies/tokens reutilizables. No hay aquí una integración de navegador validada.
- Definir desbloqueo tras reinicio, sesión bloqueada, caída del shell y funcionamiento sin humano. No asumir que un plugin arrancado con la sesión gráfica satisface operación desatendida antes del login.
- Las protecciones QML observadas reducen exposición directa, no justifican anunciar defensa frente a código arbitrario del usuario, plugins maliciosos o root.
- Fuentes web y código local pueden diferir: el README instalado ya documenta facades y confirmaciones más estrictas que la copia indexada de GitHub. Para implementar en esta máquina debe verificarse el contrato local; para distribuir, fijar matriz de versiones soportadas.
