# Decisiones de ejecución

Este registro conserva decisiones explícitas del propietario. No sustituye la especificación §15, los contratos de diseño ni los estados/evidencia de tickets.

## 2026-10-14 — Registro nativo confiable por agente (1A)

- **Confirmación:** el propietario respondió «1 A» a las dos opciones presentadas en chef-mode.
- **Decisión:** implementar un registro local instalado y versionado que vincule RPK de cada agente con su principal nativo UID/SID y con la bóveda/dispositivo. Conservar el enrolamiento y la revocación humanos como autoridad; la admisión requiere ambas fuentes vigentes. La migración convierte explícitamente el par bootstrap ya confiable, verifica continuidad y rechaza entradas ambiguas.
- **Alternativa descartada para este correctivo:** cambiar el formato de alta firmada y los eventos sincronizados para incorporar bindings nativos por dispositivo.
- **Alcance:** código, configuración y pruebas sintéticas locales del daemon; sin TOFU, aprendizaje de principal desde etiquetas, permisos por compartir UID/SID, reinterpretación automática de datos existentes, instalación sobre equipos reales o publicación. Detalles de representación/provisión se resuelven técnicamente dentro del contrato aprobado, sin introducir fallback.
- **Comprobación específica:** agentes A/B reales en daemon ordinario, clave y peer nativo correctos, pares cruzados rechazados, concesión vigente y revocación caliente, aislamiento de roles, migración explícita sin activar autoridad obsoleta y rechazo de registro ausente/alterado/inseguro.
- **Revisitar:** solo ante un fallo concreto que contradiga estas garantías o si el propietario amplía el alcance. Principios: `doors`, `design`, `prove`.

## 2026-10-14 — Configuración instalada de adaptadores (2A)

- **Confirmación:** el propietario respondió «2 A».
- **Decisión:** implementar configuración instalada de adaptadores reales, perfiles y endpoints confiables, con binding nativo; el daemon selecciona por integración/perfil y usa el worker, persistencia y reconciliación existentes. El adaptador conserva su perfil privado y su lifecycle externo.
- **Alternativa descartada para este correctivo:** que el daemon cree y supervise procesos de adaptador.
- **Alcance:** configuración versionada, validación de owner/permisos/identidad, selección y conexión explícitas, más pruebas locales. Configuración ausente, inválida, ambigua o retirada falla de forma explícita; jamás deriva a un proveedor de laboratorio ni a otra integración. No modifica eventos/wire publicados, gestión de sesiones externas, límites ni plazos. No autoriza instalación sobre hosts reales, credenciales reales, secrets, gasto, publicación ni nuevos runners.
- **Comprobación específica:** intento ordinario contra adaptador permitido, ownership y resolución humana conservados, perfil/destino/método exactos, negativa por binding/configuración incorrecta o retirada, recuperación sin repetir autenticación y evidencia real de proveedor separada de dobles sintéticos.
- **Revisitar:** solo ante evidencia concreta que refute la composición o una ampliación explícita del propietario. Principios: `doors`, `no-fallbacks`, `design`, `prove`.
