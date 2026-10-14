# Triage — diagnóstico/probes R1

Vector exacto: Windows6a2a81fa, macOS837f5564, TLS5e26f3b4, G7 0eff9d93, todos desdeea57a717. [Skeptic](skeptic.md), [Architect](architect.md), [Minimalist](minimalist.md). Todos sin P0/P1 en lo examinado; Architect PASS fuente, Minimalist ISSUES P2/P3. Skeptic incompleto por EDQUOT ([cobertura](coverage.md)); no elevar el panel entero a PASS. Ninguna ejecución por revisores; nada acredita nativos/G7/35.

## Act on

**Standards/P2 `prove`**: TLS diferencia obligatoria current>combined fija defecto en check default. Dos lentes coinciden; parent leyó `frame_cost_tests.rs:113-120`, la igualdad wire y ALPN se verifican antes. Cambiar legítimamente write_frame a una write convierte un loop auténtico correcto en RED por la aserción de ineficiencia. Nuevo writer aislado `sync-probe-gate-r2` limitado al módulo de test y nuevo reporte; prueba temporal propia RED→mismoGREEN con forma optimizada, final producción intacta. Default conserva loop literal autenticado; caracterización opt-in o métricas sin inequal congelada. No cambiar vector nueve heads en vuelo. No extra open-review; es P2 no bloqueo de source del lote actual.

## Consider / corpus

**Windows Standards/P2 `root-cause`,`truthful-state`**: PID ledger numérico vivo en cleanup puede ser PID reutilizado ajeno tras stop probado. Parent leyó Register-StoppedSyncStages (:367-375): Win32_Service stopped/deleted y luego exige ningún Win32_Process actual con los enteros anteriores. FalsoRED fail-closed, no borrado inseguro. Repro real y eventual tuplePID/creation-time/controlSCM deben preservar salvaguardas; PowerShell/Windows NOT_RUN. Retener corpus/preflight de permiso3; no relajar guard en Linux ni atribuir causa del RETIRE.

**G7 Design/Request/P2 `doors`,`prove`**: characterization de staging exacto deberá migrar con representación decidida por propietario4. Conservar retry/firma/receipt/content/replay; no borrar payload ni debilitar baseline mientras decisión pendiente.

## Noted

- G7 counts hook read-only altera efecto de checkpoint/WAL respecto del lab original read-write; bootstrap rc diferente no es prueba de intermitencia idéntica. Parent leyó wrapper: inserta además assert calls==[1] antes de retornar counts. No llamar puro observador/invariancia de todo outcome; relaciones autoridad/receipt/prefijo son solo muestras instrumentadas. Final original rc y muestra no hacen suite PASS.
- Test fixture Drop unwrap cleanup puede doublepanic/abort durante unwinding; test-only P3, no nuevo prod fallback. PythonSQL duplicatecount=2 no prueba rechazo por sí solo, Rust sí lo prueba; regex/sourcepointers son probe puntual no aceptación permanente.
- NativeSCM estados transitorios/caída antesregistrarPID presentan falsoRED/retención visible, no mask; sourcebyteidéntico W1 no autoriza reabrircleanup global. Mac regression duplicada inocua.

## Dismissed

Ningún P0/P1 descartado. No transformar gap de cuotas de Skeptic o nativos ausentes en bug de producto; gap permanece. No inferir speed/rootcause de 32/1088 versus16/736 local TLS.

Puertas3/4 limitan sus acciones, no trabajo local. Integrador y guía continúan. `cross-review`,`evidence`,`truthful-state`,`owner-attention`,`small-owned`.
