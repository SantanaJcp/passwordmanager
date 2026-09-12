# Ejecución de la especificación v1.0

## Autorización y roles

El usuario solicitó explícitamente `implement-spec` después de publicar la especificación: autoriza pasar de documentación a implementación del alcance aprobado, sin cambios funcionales ni publicación en un destino inventado. La excepción de autorización posterior de AGENTS.md queda satisfecha por esta solicitud. La base histórica de la spec permanece; sus frases sobre ausencia de autorización describían la fase de síntesis.

- Astra (`gpt-6-astra`): coordinación de DAG y revisión; no delegar revisión de seguridad al mismo implementador que produjo el cambio.
- Sol (`gpt-5.6-sol`): implementación con complejidad criptográfica, autoridad, protocolos, persistencia, nativos o integración sensible.
- Luna (`gpt-5.6-luna`): cambios acotados/mecánicos sobre contratos y seams ya presentes. Escalar a Sol si afecta garantías de seguridad; no hacer avanzar tickets bloqueados para ocupar agentes.
- Merger separado: integrar serialmente y verificar suite completa, manteniendo la rama unificada verde.

## Base e integración

- Base documental: `a7597bef21e6d6ebe0a03e492b8f96a89fdf1ae4` en `master`.
- Rama unificada: `codex/implement-passwordmanager`.
- Cada implementador: worktree propio bajo `.worktrees/<ticket>` y rama `codex/pm-<ticket>` creada desde HEAD verificado de la rama unificada. Nunca implementar en el checkout compartido del coordinador.
- Frontera: solo tickets cuyos `Blocked by` estén resueltos con entregables requeridos integrados y comprobados. El primer ticket debe establecer toolchain/build y seam real antes de depender de ellos.
- Prompts de despacho: rutas absolutas del worktree, spec, ticket, contratos y skills; no transcribir especificaciones gigantes.
- TDD: conservar evidencia de red/green, checks y revisión por ticket; no considerar ausencias de dependencias como prueba roja válida de comportamiento.
- Integración: merger verifica commit/alcance, integra rama sin reescritura destructiva, ejecuta suite/configuración disponibles y reporta evidencia. Solo entonces resolver ticket y recalcular frontera.
- Worktree se retira solo tras integrar y verificar, si está limpio; conservar rama/commit para trazabilidad. Nunca borrar archivos de otro agente activo.
- Revisión final Astra por dos ejes aislados (`Standards` y `Spec`) conforme `code-review`; no anunciar implementación completa por resolver un subconjunto.

## Condiciones de entrega

El usuario autorizó crear repositorio público y publicar documentación/código: [SantanaJcp/passwordmanager](https://github.com/SantanaJcp/passwordmanager). Origin configurado; base documental subida a master. PR borrador aún no creado: requiere commits de ejecución en rama unificada. No publicar credenciales ni información ajena al proyecto. Un Markdown con enlace previsto no es un PR creado.

Solo Linux x86_64 está observado en este host. Las pruebas nativas de los otros cinco targets, Chromium propio, revisión independiente y firma/notarización necesitan sus entornos/artefactos. No simular resultados ni retirar esas puertas del alcance; documentar evidencia real y qué no se ejecutó.

La especificación y contratos están en [spec.md](spec.md). Este documento registra ejecución, no sustituye el estado de diseño de §15 ni redefine contratos.

## Preparación comprobada

Rust instalado de forma local en `.toolchain/`, sin modificar PATH/configuración global. Comandos futuros deben establecer `RUSTUP_HOME=<raíz-del-repo>/.toolchain/rustup`, `CARGO_HOME=<raíz-del-repo>/.toolchain/cargo` y anteponer ese `cargo/bin` al PATH; worktrees no deben crear instalaciones divergentes ni usar su propio PWD como raíz de toolchain.

Verificado en este host: `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`; rustfmt/clippy instalados para el mismo toolchain. Bootstrap oficial rustup-init validado SHA-256 `dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71`. [Manifest oficial del toolchain](https://static.rust-lang.org/dist/channel-rust-1.98.1.toml), [bootstrap checksum](https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256). Existencia de versiones no equivale a build del proyecto ni lockfile resuelto: todavía no hay código de producto ni tests ejecutados.

Astra entregó [propuesta de DAG de 35 tickets](implementation-plan.md), comprobada con IDs consecutivos/dependencias previas/sin ciclos y criterios/punteros presentes. Se solicitó aprobación de granularidad/orden antes de publicar los tickets, conforme `to-tickets`. La frontera inicial será 01; no se puede ejecutar tickets descendientes en paralelo antes de integrar sus dependencias.
