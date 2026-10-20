# Passwordmanager

Passwordmanager es una bóveda local cifrada. La TUI permite al propietario administrar sus elementos; el CLI y MCP ofrecen operaciones delegadas para agentes registrados sin entregarles los secretos de la bóveda. La bóveda no administra las sesiones que un servicio externo cree después de autenticar.

## Estado

Este árbol es para desarrollo y evaluación, no una distribución lista para producción. El CLI ofrece la entrada humana **pm tui** cuando ya existen un perfil humano, su clave protegida y el socket humano correctos. No es una ruta de provisión ni expone los comandos administrativos del custodio. La implementación Linux también reconoce archivos locales versionados para asociar claves RPK con UID y para fijar adaptadores; esto no proporciona por sí solo un instalador ni un procedimiento completo y verificado para preparar un host normal.

No introduzcas credenciales reales ni conectes un agente que pueda leer la TUI, su terminal, el portapapeles, la bóveda o las claves locales.

La [guía de evaluación Linux](docs/user/evaluacion-linux.md) explica qué se puede ejecutar hoy, los requisitos previos y los límites de la evidencia.
