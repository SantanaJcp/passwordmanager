# 23 — TUI completa de contenido y exposición humana

Type: task
Status: resolved
Owner: sol-23
Blocked by: 05,18
Spec: ../spec.md
Requirements: R01,R03,R04,R05,R12
Model: gpt-5.6-sol

## Objective
Todos los tipos, búsqueda/organización/generador/historia/papelera/purga operan vía motor real por teclado; unlock/lock, idle/reveal expiry, copiar explícito con API/helper fijado y carrera de clipboard cumplen G7 sin OSC52 oculto; resize/80×24/Unicode/control sequences se prueban en PTY y terminal nativo Linux, sin pérdida de datos ni secretos por seleccionar fila.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G1 terminal; G7; V02,V07,V20,V24; H3–11,43–45.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [x] Todos los tipos, búsqueda/organización/generador/historia/papelera/purga operan vía motor real por teclado.
- [x] unlock/lock, idle/reveal expiry, copiar explícito con API/helper fijado y carrera de clipboard cumplen G7 sin OSC52 oculto.
- [x] resize/80×24/Unicode/control sequences se prueban en PTY y terminal nativo Linux, sin pérdida de datos ni secretos por seleccionar fila.
- [x] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [x] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer

Integrado: TUI Ratatui/Crossterm por teclado sobre el canal humano real
TLS-RPK, con catálogo de los siete tipos y selección explícita de campo para
reveal/copy. Cubre búsqueda, organización, generador, historia, papelera,
restore y purgas; conserva expiraciones, lock, clipboard y PTY hostiles de G7.
Los opcodes implícitos 47/48 y `primary_human_secret` no existen como rutas de
producto; 47/48 solo permanecen en una negativa que comprueba su rechazo.
Evidencia y límites exactos en
[ticket-23](../../../docs/verification/ticket-23.md).

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-13 — Claimed tras integrar 05 y 18. Escalado de Luna a Sol conforme execution.md: unlock/lock y exposición de secretos, temporizadores y carrera de clipboard afectan garantías G7, además de conectar la TUI al canal humano real. Revisión formal Astra solo al final.

2026-09-13 — Checkpoint SOLO23: TUI Ratatui/Crossterm real sobre `/dev/tty` y canal humano TLS-RPK; catálogo de siete tipos, mutaciones de organización, búsqueda, generador50, historia, trash/restore/purgas y selección explícita de todos los descriptores mediante opcodes51–53. Lab PTY/Wayland real verde con wrong-password sin mutación, resize, Unicode/control injection, expiraciones y carrera de `wl-copy` preservando selección ajena. `scripts/check.sh` y clean locked/offline verdes; 13 labs verdes y web-auth verde en retry exacto tras un primer timeout registrado en `docs/verification/ticket-23.md`. No resolver ni presentar como candidato integrable: el fallback heredado `primary_human_secret` de opcodes47/48 sigue sin cambio y espera autorización explícita.

2026-09-13 — Autorizada la selección explícita sin sustitución de notas. La
composición con la base unificada conserva todos los campos de
`TokenExchange`; 47/48 y `primary_human_secret` se retiraron y el canal real los
rechaza. Notas, source/custom, auth y attachments permanecen accesibles por
51–53 con selección exacta. Pendiente gate completo y merger separado.

2026-09-13 — Candidato SOLO23 congelado tras gate completo. La TUI real conserva
los siete tipos y ocho records compuestos, incluido `TokenExchange`; notas,
source/custom, auth múltiples y attachments son campos seleccionables por
51–53. El fallback heredado 47/48 + `primary_human_secret` quedó eliminado bajo
la autorización registrada y ambos opcodes se rechazan por el canal humano.
`check.sh`, clean locked/offline y 18/18 labs Linux secuenciales pasaron. La
evidencia conserva los RED de composición y de orden PTY; el harness espera el
input visible antes de Enter sin retry ni aumento de deadlines. Pendiente
únicamente integración por merger separado; no se resuelve aquí.


2026-09-13 — Merger Sol distinto integró `f1c375e` sin conflictos textuales
como `c74aba0`, preservó el método asíncrono ya integrado y verificó
independientemente `check.sh`, clean locked/offline y una corrida ordenada con
propagación fiable de errores: 18/18 laboratorios Linux pasaron. La limitación
de attachments mayores que el frame humano permanece explícita y no se
presenta como descarga/copiado TUI completo. Ticket resuelto; revisión formal
Astra continúa reservada al cierre del DAG.
