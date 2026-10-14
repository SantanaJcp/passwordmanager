# Triage R2 — Unix D1/D2

Skeptic y Architect completaron la segunda y última ronda sobre `894aa3600610e23a1834d831668bf66dc2bb7112`, delta desde `7b7026e`. Ambos PASS de fuente: D1 (global4) y D2 (terminalizar desconocido por preflight local) resueltos. No P0/P1 previos abiertos; no se inicia tercera revisión. Informes: [Skeptic](skeptic.md), [Architect](architect.md).

Las mediciones RED→GREEN/checks son del autor; revisores solo objetos Git fijados, sin tests. Aceptación de fuente habilita composición local exacta, no merge master/publicación ni PASS del lote. Principios: `prove`, `truthful-state`, `no-fallbacks`, `cross-review`.

Antes de TLS los RPK del mismo UID comparten presupuesto nativo: mismo principal OS, no nueva separación. Tras TLS y antes del magic cada RPK dispone de cuatro permisos. Caídas largas reconciliando pueden añadir auditoría a ~100 ms (comportamiento heredado, reportado, no nuevo fallback).

Windows/macOS y proveedor/SSH reales pendientes; G7, clean/52 y `kitchen integrate` exacto siguen NOT_RUN. No modificar gates/plazos ni cierres de tickets por esta revisión.
