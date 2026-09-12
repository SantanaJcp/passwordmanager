# Custodiar credenciales, no administrar sesiones externas

Status: accepted
Date: 2026-09-12

El [contrato funcional confirmado](../../.scratch/passwordmanager/spec.md) limita el producto a custodiar, habilitar y utilizar credenciales para autenticar. Se consideró extenderlo a proteger cookies/tokens de sesión y controlar acciones posteriores; el usuario rechazó esa ampliación para conservar una responsabilidad única.

## Decisión

Los agentes autorizados utilizan credenciales habilitadas sin recibir los secretos de la bóveda. Los permisos de negocio, las acciones posteriores y la gestión de sesiones externas no pertenecen al producto. Un token guardado expresamente como elemento sí es un secreto de la bóveda; no deja de estar protegido por llamarse «token».

## Consecuencias

- No añadir control de sesiones, políticas de acciones externas o logout remoto universal como supuesto requisito de seguridad.
- La exclusión de sesiones posteriores no permite entregar el secreto original durante la autenticación ni presentarlo como si fuera un resultado de sesión.
- Las integraciones deben demostrar esa separación; no prometer soporte universal ni seguridad validada mientras sigan abiertas las puertas técnicas.
- Suspender o revocar agentes detiene nuevos usos dentro de la bóveda, no deshace accesos externos ya establecidos.

Este ADR registra una decisión de alcance aceptada, no una implementación ni evidencia de aislamiento.
