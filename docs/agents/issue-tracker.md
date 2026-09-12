# Seguimiento local en Markdown

## Configuración

- Backend: archivos locales, elegido por el usuario. No GitHub/GitLab ni llamadas a servicios externos.
- Un esfuerzo por directorio: `.scratch/<slug>/`.
- Especificación canónica de este esfuerzo: [.scratch/passwordmanager/spec.md](../../.scratch/passwordmanager/spec.md).
- Incidencias, cuando se autorice crearlas: `.scratch/<slug>/issues/NN-<slug>.md`, un archivo por incidencia y números únicos consecutivos desde `01` dentro del esfuerzo.
- `.scratch/` contiene seguimiento durable: no borrarlo como caché ni excluirlo indiscriminadamente de control de versiones. No se ha realizado ningún commit mediante este setup.

## Operaciones

- **Publicar:** crear el archivo local correspondiente; nunca interpretar «publicar al tracker» como autorización para escribir en un servicio remoto.
- **Consultar:** leer el archivo indicado. Resolver números dentro del esfuerzo, no globalmente.
- **Comentar:** añadir fecha, autor y texto al final bajo `## Comments`, sin reemplazar comentarios previos.
- **Actualizar:** preservar ID, especificación de origen, requisitos y evidencia existente; registrar cambios relevantes en comentarios.
- **Resolver:** completar criterios verificables, añadir resultado/evidencia y establecer `Status: resolved`. No cerrar automáticamente la especificación padre ni otras incidencias.

## Campos de una incidencia

La siguiente es una plantilla documental, no una incidencia creada ni un permiso para ejecutar trabajo:

```markdown
# NN — Título concreto

Type: research | prototype | grilling | task
Status: open
Owner: unassigned
Blocked by: none
Spec: ../spec.md
Requirements: Rxx

## Objective
Resultado acotado y verificable.

## Scope
Incluido, excluido y autorización aplicable.

## Acceptance criteria
- [ ] Evidencia observable del resultado.

## Answer
Resultado y evidencia al resolver, o motivo de cierre sin ejecución.

## Comments
```

- `Status` representa ciclo de vida: `open`, `claimed`, `resolved`. Una tarea bloqueada sigue `open`; sus dependencias determinan el bloqueo.
- `Owner` identifica al responsable. Antes de iniciar trabajo autorizado, comprobar dependencias y guardar `Status: claimed` y responsable; no sobrescribir una reclamación ajena.
- `Blocked by` contiene `none` o IDs del mismo esfuerzo, por ejemplo `01, 03`. No admitir IDs inexistentes, dependencia consigo misma ni ciclos.
- Una dependencia queda satisfecha solo cuando está `resolved` **y su resultado requerido fue entregado**; cerrar como descartada no desbloquea automáticamente trabajo que necesitaba ese resultado.
- Requisitos y bloqueos deben ser concretos. La disponibilidad de un skill no autoriza ejecutar prototipos o implementación fuera del permiso del usuario.

## Triage y preparación

No hay un skill `triage` instalado dentro de este repositorio. Su disponibilidad en el catálogo de la sesión no es instalación/configuración local. Por la condición del setup, **no se crea `triage-labels.md` ni se configura un vocabulario de etiquetas de triage**. Los estados anteriores son solo el ciclo de vida del tracker.

Si posteriormente se incorpora triage al repositorio, configurar sus etiquetas en una acción explícita, preservando los estados y referencias existentes. No aplicar `ready-for-agent` cuando falten decisiones esenciales de diseño o viabilidad crítica del alcance afectado. Las pruebas de implementación pueden estar pendientes si están definidas como criterios verificables; no exigir que el producto esté construido antes de planificarlo. Consultar el estado consolidado en la sección 15 de la especificación y no confundir preparación con autorización de ejecución.

## Wayfinding opcional

Si se solicita `wayfinder`, su mapa será `.scratch/<slug>/map.md` y enlazará los archivos individuales de `issues/`. Usará los mismos campos y reglas de bloqueo; no mantener un segundo estado contradictorio en el mapa. Resolver una incidencia añade al mapa un resumen y enlace, no copia todo su contenido.

## Estado de este setup

Solo se configuran convenciones. La especificación v0.1 conserva sus puertas G1–G8; no se crean tickets de producto, mapas de trabajo ni etiquetas de preparación mediante este cambio.
