# Convenciones de documentación de dominio

## Estructura elegida

Contexto único: [CONTEXT.md](../../CONTEXT.md) en la raíz. El repositorio no presenta workspaces ni paquetes de un monorepo; no crear `CONTEXT-MAP.md` ni contextos por módulo técnico.

- Vocabulario: [CONTEXT.md](../../CONTEXT.md).
- Decisiones con consecuencias duraderas: [docs/adr/](../adr/).
- Contrato funcional y propuesta técnica: [especificación](../../.scratch/passwordmanager/spec.md).
- Investigación con fuentes: [docs/research/](../research/).

## Uso

1. Leer el glosario antes de nombrar conceptos en documentos, investigaciones, incidencias o futuro código.
2. Leer los ADR que afecten la decisión en curso, no todos por rutina.
3. Usar un término por concepto. No sustituir «agente registrado», «credencial habilitada» y «sesión externa» por un «acceso» ambiguo.
4. Si falta un término, incorporarlo cuando su significado esté resuelto; no añadir propuestas como si fueran acuerdos.
5. Si una propuesta contradice una decisión aceptada, señalar el conflicto antes de modificar el contrato. Una nota de investigación no revoca un ADR ni una confirmación del usuario.

## Glosario

Definiciones cortas de dominio e invariantes, sin frameworks, bases de datos, algoritmos, tablas ni procedimientos de implementación. Usar `_Evitar_` para sinónimos que confundan conceptos, no para prohibir vocabulario sin motivo.

La sección de vocabulario de la especificación debe mantenerse alineada con `CONTEXT.md`; las decisiones funcionales confirmadas de la especificación no se alteran mediante un cambio de nombre en el glosario.

## ADR

Crear un ADR solo si la decisión es difícil de revertir, sorprendente sin contexto y resultado de un trade-off real. Numeración consecutiva `docs/adr/NNNN-slug.md`, sin reutilizar números.

Registrar contexto, decisión, estado y consecuencias relevantes. Estados: `proposed`, `accepted`, `deprecated` o `superseded` con enlace al reemplazo. No declarar aceptada una propuesta técnica solo porque la sugirió un agente.

Conservar el razonamiento histórico al sustituir una decisión. Los detalles técnicos aún abiertos permanecen como propuestas o puertas de validación, no ADR aceptados.

## Comprobación al terminar

Verificar enlaces relativos, consistencia de términos con la especificación y ausencia de detalles de implementación en el glosario. No afirmar alineación con código o esquemas mientras todavía no existen.
