# Borrado frente a edición concurrente

Status: accepted
Date: 2026-09-12

## Contexto

El contrato utiliza last-write-wins por timestamp para contenido y conserva historial y papelera. Faltaba decidir qué ocurre si un dispositivo borra un elemento mientras otro lo edita. Aplicar LWW también al estado activo podría hacer reaparecer el elemento sin restauración humana.

## Decisión

El usuario aprobó explícitamente que el borrado prevalezca frente a una edición concurrente. El elemento permanece en papelera; la edición ganadora por LWW se conserva allí. Volver al estado activo exige restauración humana explícita.

## Consecuencias

- Separar la selección del contenido de su estado activo/papelera.
- No perder la edición concurrente ni utilizarla como restauración implícita.
- Mantener LWW de contenido e historial, sin resolución manual de esos conflictos.
- La restauración humana es una operación del producto, no una intervención exigida para resolver cada edición concurrente.
- Esta aprobación no fija plazos de retención, compactación, formatos, algoritmos de precedencia ni todas las carreras entre restauraciones y nuevas eliminaciones. Esos aspectos conservan su estado técnico previo.

Referencias: [especificación](../../.scratch/passwordmanager/spec.md), [diseño de sincronización](../design/synchronization.md). La decisión funcional queda cerrada; su implementación y validación no se han realizado.
