# Autenticación sin intervención humana

Fecha: 2026-09-12. Investigación para la entrevista de diseño; no es una especificación aprobada.

**Actualización tras confirmación del contrato:** ante una exigencia humana se pausa inmediatamente solo esa autenticación, sin intentar otra vía automáticamente, y se reanuda al comprobar la resolución si sigue vigente/autorizada. Los agentes estarán aislados sin administración del custodio. La protección se limita a secretos de la bóveda, no a sesiones externas posteriores. Prevalece la [especificación v0.1](../../.scratch/passwordmanager/spec.md).

## Requisito del usuario

Los agentes deben trabajar sin recibir contraseñas ni poder extraerlas con sus herramientas. Deben conservar acceso a credenciales habilitadas tras un reinicio y funcionar sin intervención humana. El control de acciones posteriores dentro de un servicio queda fuera del gestor.

## Hechos verificados

- TOTP calcula códigos a partir de un secreto compartido y el tiempo. No exige por algoritmo una interacción humana para cada generación. El secreto y los códigos siguen siendo material sensible. [RFC 6238, secciones 3–5](https://www.rfc-editor.org/rfc/rfc6238.txt).
- WebAuthn exige presencia del usuario en el modelo de autenticación y permite exigir verificación del usuario. Los indicadores UP/UV deben reflejar pruebas realmente realizadas; almacenar una passkey no demuestra que pueda utilizarse desatendidamente. [W3C, datos del autenticador](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data), [modelo de assertion](https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion), [validación del servicio](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).
- WebAuthn documenta autenticadores virtuales para automatización. Su existencia no prueba compatibilidad ni garantías equivalentes para autenticación desatendida en servicios reales. [W3C, automatización](https://www.w3.org/TR/webauthn-3/#sctn-automation).
- Linux permite inspección de procesos según identidad, capacidades y restricciones como Yama. Un proceso separado no constituye por sí solo una frontera suficiente frente a un agente con herramientas bajo la misma identidad o con privilegios amplios. [Documentación del kernel: Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html).

## Inferencias y recomendaciones, aún no aprobadas

- Prometer ejecución desatendida para métodos e integraciones verificados, no éxito universal frente a cualquier desafío del proveedor.
- **Propuesta histórica rechazada:** intentar una alternativa habilitada ante exigencia humana y terminar si no existe. No implementar: la decisión posterior es pausa inmediata del intento, indicada arriba.
- Investigar un límite de privilegios real entre el agente y la custodia de secretos. Distinguir administración de servidores remotos de administración irrestricta del propio equipo custodio.
- Separar la entrega de una sesión del aislamiento del navegador durante el login: ocultar contraseñas de las respuestas de herramientas no demuestra que el agente no pueda extraerlas.

## Decisiones abiertas

1. Mecanismo técnico verificable de aislamiento por plataforma; el requisito de agentes sin administración del custodio ya está acordado.
2. Detección/resolución de desafíos y vencimientos; el comportamiento de pausa/reanudación ya está acordado.
3. Integraciones y runtimes concretos para verificar compatibilidad, sin convertir el motor en un gestor de sesiones externas.

No se han ejecutado pruebas contra proveedores ni implementado autenticadores.
