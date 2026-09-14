# Acuerdos del repositorio

- Mantén cambios enfocados y preserva el trabajo existente. Distingue requisitos confirmados, propuestas y evidencia verificada.
- El alcance actual es documentación y validación de diseño. No implementar el producto, crear prototipos ni instalar dependencias sin autorización posterior explícita.
- La [especificación](.scratch/passwordmanager/spec.md), sección 15, es el estado consolidado de acuerdos confirmados, cierres de diseño G1–G8 y evidencia pendiente. No reabrir acuerdos por falta de pruebas ni tratar documentación como seguridad validada o autorización para implementar.
- No ampliar la bóveda hacia permisos de negocio o gestión de sesiones externas. El plugin Omarchy se hará después y en otro repositorio.
- Nunca introducir credenciales reales en documentación, fixtures, incidencias, logs o ejemplos. Usar datos sintéticos identificables.
- Antes de declarar una tarea terminada, verificar el resultado observable. En cambios documentales, comprobar enlaces, consistencia de estados y ausencia de contradicciones con el contrato.

## Agent skills

### Issue tracker

Seguimiento local en Markdown bajo `.scratch/`. Para especificaciones, incidencias, dependencias y estados, consultar [docs/agents/issue-tracker.md](docs/agents/issue-tracker.md). No publicar en servicios externos sin autorización.

### Domain docs

Contexto único: [CONTEXT.md](CONTEXT.md) es el vocabulario canónico. Para convenciones de dominio y ADR, consultar [docs/agents/domain.md](docs/agents/domain.md); leer solo los [ADR](docs/adr/) pertinentes al trabajo.

### Investigación y planificación

Las notas en [docs/research/](docs/research/) son evidencia o propuestas, no sustituyen decisiones confirmadas. Antes de planificar implementación, cerrar decisiones relevantes y comprobar viabilidad crítica; las pruebas del producto se planifican como criterios de aceptación, no se exigen ejecutadas antes de que exista. Crear tickets, prototipos o código sigue requiriendo autorización. Reutilizar el estado de la sección 15 en vez de agregar listas paralelas o rondas genéricas de investigación. No crear una segunda fuente de instrucciones `CLAUDE.md`.

### Verificación nativa hospedada

Antes de preparar o ejecutar runners hospedados, seguir el [Método CI nativo efímero](docs/verification/native-ci.md). Ese documento delimita preflight de entorno, futura aceptación de producto y evidencia que sigue requiriendo laboratorios humanos o de reboot; un runner disponible no acredita soporte.
