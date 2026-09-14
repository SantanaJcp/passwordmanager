# 28 — Fallos operativos, canarios y crash safety integral

Type: task
Status: claimed
Owner: sol_integrator (gpt-5.6-sol, medium)
Blocked by: 09,10,11,12,14,15,17,18,19,20,21,22,25
Spec: ../spec.md
Requirements: R09,R10,R13,R15,R18
Model: gpt-5.6-sol

## Objective
Fault injection en boundaries reales de fsync/WAL/staging/commit/outbox/audit y disco lleno conserva atomicidad/autoridad y nunca doble login ciego; canarios activos/históricos cubren stdout/stderr/logs/errores/argv/env/temp/dumps y recursos de agente; memoria/dump/clock/rate límites G7 y pérdida de custodia producen fallo documentado, sin tests verdes por redacción posterior. Ports nativos se vuelven a ejecutar en 30–32.

## Scope
Corte aprobado del DAG; implementar únicamente este ticket, preservando todos los contratos. No omitir criterios ni declarar soporte de plataforma/proveedor no probado. Sin secretos reales, sin cambios de sistema fuera de laboratorio autorizado, sin acciones/sesiones externas administradas por la bóveda.

## Context pointers
- [Especificación](../spec.md) — referencias aplicables: G7; G2/G4/G5/G6; V05,V07–V08,V20–V23; H43,45,52–53,58–59,64.
- [Ejecución y toolchain](../execution.md).
- [DAG aprobado y cobertura](../implementation-plan.md).
- [Contratos seleccionados](../spec.md#53-anexos-normativos-y-ubicación-de-cada-decisión).
- [Tracker](../../../docs/agents/issue-tracker.md).

## Acceptance criteria
- [ ] Fault injection en boundaries reales de fsync/WAL/staging/commit/outbox/audit y disco lleno conserva atomicidad/autoridad y nunca doble login ciego.
- [ ] canarios activos/históricos cubren stdout/stderr/logs/errores/argv/env/temp/dumps y recursos de agente.
- [ ] memoria/dump/clock/rate límites G7 y pérdida de custodia producen fallo documentado, sin tests verdes por redacción posterior. Ports nativos se vuelven a ejecutar en 30–32.
- [ ] Evidencia TDD red/green y comandos exactos de tests/checks; sin skip/stubs para simular cumplimiento.
- [ ] Cambios revisados contra estándares y contrato; integración verificada por merger antes de resolver.

## Answer
Pendiente de implementación y evidencia.

## Comments
2026-09-12 — Publicado tras aprobación explícita del DAG de 35 tickets. La solicitud implement-spec autoriza esta ejecución; no reabrir alcance ni confundir contrato con validación.

2026-09-14 — Astra: dependencias 09–25 requeridas verificadas como resueltas e integradas; ticket reclamado para Sol medium en worktree aislado. Preparación estática en paralelo; toda ejecución Cargo/build/labs espera ventana Linux exclusiva explícita.

2026-09-14 — Método integral escrito antes de código en
[`docs/verification/ticket-28.md`](../../../docs/verification/ticket-28.md).
Primer tracer RED preparado, todavía **no ejecutado** por exclusión de ventana:
observa sobre el proceso humano real core=0, dumpability, memoria propia
bloqueada, denegación con memlock=0 y ausencia del canario en argv/env/salidas.
No existe implementación productiva anticipada. Los fallbacks de cleanup
heredados encontrados se registraron en el método y se informaron; no se
modifican sin autorización. `persist_new` pertenece al cambio separado ya
autorizado y se compondrá antes del gate integral, no se duplica aquí.

2026-09-14 — Cleanup-errors `1412185` compuesto por merge normal `05902c7`.
RED conductual inicial reproducido en `/tmp/pm28-red-process-security-2.log`:
tras probar attach/detach positivo sobre el hijo control, el proceso humano real
llegó al prompt y falló porque su core soft/hard no era `0/0`. El intento previo
fue un defecto de cleanup del harness y no cuenta como RED de producto. Ventana
Linux liberada inmediatamente; GREEN de guardas/memoria se prepara estático
hasta nueva concesión.

2026-09-14 — Primer vertical Unix GREEN: claves propias centrales usan
`sodium_malloc`+`sodium_mlock`, presupuesto agregado 32 MiB y cleanup nativo;
cliente humano/custodio fijan core=0 y dumpable=0 antes de secretos. El tracer
con control ptrace positivo y UID no privilegiado terminó rc0, seguido de
pm-crypto, check y clean offline verdes. Cobertura expresamente incompleta:
faltan buffers plaintext, Windows/macOS y los recorridos de fault/crash/canarios;
ningún criterio de 28 se marca cerrado todavía.

2026-09-14 — Segundo tracer RED reproducido en
`/tmp/pm28-red-plaintext-buffer.log` (rc1, 3 s): con memlock=0 y sólo la primera
línea de password, el binario aceptó el `Vec` desbloqueado, imprimió la petición
de confirmación y acabó como `unexpected end of input`, en vez de rechazar el
primer secreto como `RESOURCE_UNAVAILABLE`. Inventario y orden de los siguientes
seams (custodio/vault/adaptadores y fault real de disco/fsync/WAL/audit/outbox/
crash) quedan en el método. No se escribió GREEN antes de observar este RED.
El GREEN preparado limpia el buffer temporal y lo bloquea antes del siguiente
prompt, pero la lectura aún ocurre brevemente en `Zeroizing<Vec<u8>>`; no se
considera entrada directa protegida ni cierre G7 hasta eliminar ese tramo.

2026-09-14 — Segundo checkpoint GREEN: `pm-crypto` y `pm-cli` enfocados rc0;
lab público `/tmp/pm28-green-plaintext-buffer.log` rc0 en 3 s, con control ptrace
positivo, rechazo memlock antes de confirmación y cleanup verificado. Un intento
previo rc101 no compiló por `Cargo.lock` desincronizado y no cuenta como RED; se
conserva en `/tmp/pm28-green2-pm-crypto.log`. Sigue sin probar lectura directa
en memoria bloqueada ni los demás buffers/canales, por lo que 28 queda abierto.

2026-09-14 — Tercer RED preparado sin ejecución: con stdin abierto y cero bytes
enviados, memlock=0 debe fallar tras el primer prompt; esperar entrada demuestra
que el destino no fue protegido antes de leer. Casos enfocados fijan LF, CRLF,
EOF vacío/no vacío y límite sin registrar el canario. No se escribió GREEN.

2026-09-14 — Tercer RED real `/tmp/pm28-red-direct-protected-input.log`: rc1 en
7 s, build correcto; stdin abierto con cero bytes quedó bloqueado leyendo y
agotó exactamente los 3 s del fixture. Cleanup dejó cero procesos/raíces. GREEN
estático ahora reserva+mlock antes del primer `Read`, sin `Vec` plaintext ni
`read_until`; queda pendiente de compilación y ejecución con ventana exclusiva.

2026-09-14 — GREEN propio de destino: suites enfocadas y lab público rc0; check
rc0 tras preservar tres fallos de formato/lint, y clean offline rc0 en 40 s.
Esto sólo demuestra reserva/mlock antes de `Read`: el caller conserva
`stdin.lock()` y su buffer interno puede precargar plaintext. Falta lectura
nativa sin buffer por plataforma; no se marca G7 ni el ticket como cerrado.

2026-09-14 — Cuarto RED preparado sin ejecución: socketpair propio deja un
canario sin newline tras dos passwords; `FIONREAD` del extremo lector debe
mostrarlo aún en kernel al aparecer confirmación. `StdinLock` puede precargarlo
en su `BufReader`. Método exige fd/handle nativo sin ownership del stdin original
y sin fallback; Linux no acreditará macOS/Windows. No se escribió GREEN.

2026-09-14 — RED nativo real `/tmp/pm28-red-native-stdin-prefetch.log`, rc1:
build correcto y `FIONREAD=0` frente a >=304, demostrando prefetch del canario
por `StdinLock`. Cleanup sin procesos/sockets/raíces. GREEN estático usa
`read(2)` Unix y `ReadFile` Windows sobre handles prestados, sólo hacia el buffer
bloqueado y sin fallback; pendiente compilar/ejecutar y evidencia nativa.

Corrección estática previa a cualquier gate: Windows console no puede usar
`ReadFile` sin perder la semántica UTF-8 de std. El seam ahora clasifica consola
con `GetConsoleMode`, usa `ReadConsoleW`→UTF-8 con buffers locked, y reserva
`ReadFile` para pipe/file. Handle nulo conserva EOF público rc5; no éxito. Sigue
pendiente evidencia Windows real.

Compatibilidad Windows se fijó contra `std` 1.98.1: pipe roto equivale a EOF;
la consola conserva wakeup Ctrl-Z, reintento Ctrl-C/Break, Unicode suplementario
y fallo explícito de surrogates inválidos. La futura prueba nativa cubrirá esos
casos, CRLF, handle nulo/inválido, pipe y conservación del handle prestado; un
PASS Linux no los acredita.

2026-09-14 — Usuario autorizó de forma explícita sólo los cuatro cleanups antes
pendientes: `TemporaryDirectory::drop/remove_dir_all` y los unlink de privada
tras keygen, `.partial` de download y archivo incompleto de `write_new`. Se
implementarán test-first después del vertical stdin, preservando error primario
más cleanup, path owned y un intento; no es autorización global de cleanup.
El método ya fija REDs conductuales mediante permisos reales e interposer de
syscalls limitado por PID/path/contador, además de la vida checked de
`ProcessEvidence`; todavía no se ejecutaron ni se escribió su GREEN.
