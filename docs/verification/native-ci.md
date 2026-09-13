# Método CI nativo efímero

Estado: método adicional autorizado y preparación local; **ninguna ejecución de
GitHub Actions observada todavía**. Este documento no acredita soporte de
producto, no resuelve los tickets 26--32 y no sustituye sus laboratorios
humanos, de reboot/FDE o de firma real.

## Alcance y fuente de verdad

Este método añade un laboratorio hospedado, nativo, efímero y de un solo boot
al método por procesos reales ya usado por el proyecto. Sirve primero para
comprobar el entorno y, cuando existan los ports y entrypoints de cada ticket,
para ejecutar la parte automatizable de su aceptación. Compilar para otra CPU
no es ejecutarla allí: WSL, Rosetta, QEMU, WoW64 y cross-compilation no cuentan
como evidencia nativa.

G1 exige Linux kernel 6.1/glibc 2.36/systemd 252 en x86-64 y AArch64, macOS 13+
en Intel y Apple silicon, y Windows 11 en x64 y ARM64. Los perfiles completos
están en [aislamiento](../design/isolation.md), los artefactos en
[distribución](../design/distribution.md) y los controles de crash/clipboard en
[operaciones de seguridad](../design/security-operations.md). La aceptación
por target sigue en los tickets
[26](../../.scratch/passwordmanager/issues/26-custodia-y-canal-humano-macos.md),
[27](../../.scratch/passwordmanager/issues/27-custodia-y-canal-humano-windows.md),
[28](../../.scratch/passwordmanager/issues/28-fallos-operativos-canarios-y-crash-safety-integral.md),
[29](../../.scratch/passwordmanager/issues/29-paquetes-tuf-mantenimiento-y-fuente-correspondiente.md),
[30](../../.scratch/passwordmanager/issues/30-evidencia-nativa-linux-en-dos-arquitecturas.md),
[31](../../.scratch/passwordmanager/issues/31-evidencia-nativa-macos-en-dos-arquitecturas.md)
y [32](../../.scratch/passwordmanager/issues/32-evidencia-nativa-windows-en-dos-arquitecturas.md).

GitHub documenta que los runners estándar son gratuitos e ilimitados en
repositorios públicos y que cada label salvo `ubuntu-slim` obtiene una VM nueva.
Linux/macOS tienen `sudo` sin contraseña y Windows se ejecuta como administrador
con UAC desactivado. Los límites actuales son 6 horas por job y, en GitHub Free,
20 jobs estándar concurrentes con máximo 5 macOS. No se usan larger runners,
cachés ni artefactos: larger siempre se cobra, y almacenamiento tiene cupos y
precio propios. Fuentes primarias:
[runners hospedados](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[límites](https://docs.github.com/en/actions/reference/limits),
[facturación](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
e [imágenes](https://github.com/actions/runner-images).

## Targets de preparación

El workflow manual
[`native-environment-preflight.yml`](../../.github/workflows/native-environment-preflight.yml)
usa exactamente estos cinco targets estándar:

| Target | Label fijado | Recursos estándar públicos | Mínimo G1 | Alcance |
| --- | --- | --- | --- | --- |
| Linux x86-64 | `ubuntu-24.04` | 4 CPU, 16 GB RAM, 14 GB SSD | Sí | Entorno solamente. |
| Linux AArch64 | `ubuntu-24.04-arm` | 4 CPU, 16 GB RAM, 14 GB SSD | Sí | Entorno solamente. |
| macOS Intel | `macos-15-intel` | 4 CPU, 14 GB RAM, 14 GB SSD | Sí | Entorno solamente; GitHub [anunció](https://github.com/actions/runner-images/issues/13045) fin de esta última imagen Intel para agosto de 2027. |
| macOS Apple silicon | `macos-15` | M1 3 CPU, 7 GB RAM, 14 GB SSD | Sí | Entorno solamente; sin nested virtualization ni UUID/UDID estático. |
| Windows 11 ARM64 | `windows-11-vs2026-arm` | 4 CPU, 16 GB RAM, 14 GB SSD | Sí | Entorno solamente; exige PowerShell y toolchain ARM64, no proceso emulado. |

Los labels fijan familia de OS y CPU, **no** `ImageVersion`; GitHub actualiza
las imágenes regularmente. Cada corrida debe conservar el commit, label,
`ImageOS`, `ImageVersion`, versión/build del OS, CPU y host Rust observados.
El preflight exige Rust/Cargo 1.98.1 y compila, inspecciona y ejecuta un binario
mínimo de la arquitectura nativa. El toolchain exacto debe estar ya instalado;
el preflight no lo descarga ni instala. También comprueba privilegio administrativo,
gestor de servicios y herramientas nativas necesarias. Un preflight verde solo
significa que el entorno es candidato; no demuestra custodia, aislamiento,
crash-safety, empaquetado ni soporte.

Windows x64 queda fuera: los runners estándar x64 publicados son Windows Server
2022/2025, no el Windows 11 requerido por G1. El Windows 11 Desktop x64 de larger
runners es pagado y no está autorizado. No se ejecutará Windows Server como
sustituto. La imagen Windows ARM puede incluir herramientas x64; por eso no
basta `RUNNER_ARCH`: el host Rust, PowerShell y el PE producido tienen que ser
ARM64.

## Seguridad y coste de la preparación

- Único trigger: `workflow_dispatch`; no hay `push`, PR, schedule ni ejecución
  automática.
- `permissions: contents: read`; `actions/checkout` se fija al commit
  `11d5960a326750d5838078e36cf38b85af677262` de v4.4.0 y no persiste
  credenciales.
- No hay secrets propios, credenciales/certificados de firma, datos reales,
  cache, artifact upload, publicación ni larger runner.
- No se imprime el entorno completo. Solo metadata de runner/OS/CPU/usuario,
  versiones de herramientas y el canario público `PM_NATIVE_CI_PROBE`.
- Un comando, versión, arquitectura o prerrequisito ausente termina el job en
  error. No se descarga una alternativa, no se cambia de label y no se acepta
  emulación.
- `fail-fast: false` permite observar los cinco resultados independientes; un
  fallo de cualquier instancia mantiene fallido el workflow completo y no se
  convierte en éxito.

## Método de ejecución y evidencia

Prerrequisito de plataforma: GitHub solo entrega `workflow_dispatch` cuando el
archivo del workflow existe en la rama por defecto. El repositorio usa
`master`. Publicar este archivo solo en una rama/PR no habilita el dispatch.
El paso de publicación autorizado debe colocar **este mismo archivo**, sin
triggers adicionales, en `master`; el ref elegido manualmente debe contener el
mismo workflow y sus dos scripts de preflight. Eso habilita seleccionar el ref
confiable sin fusionar el PR de producto ni cambiar protecciones. Esta exigencia está documentada en
[workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onworkflow_dispatch)
y [manual runs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

Secuencia después de satisfacer ese prerrequisito:

1. Seleccionar `Native environment preflight` mediante dispatch manual sobre el
   ref confiable y registrar el commit exacto que resuelva GitHub.
2. Confirmar cinco instancias, los cinco labels exactos y ausencia de larger
   runners.
3. Guardar URLs de workflow/job y los hechos emitidos por cada preflight. Logs y
   job summaries no se subirán como artifacts.
4. Exigir cinco conclusiones `PASS ... scope=environment-only
   product-validation=NOT_RUN`. Cualquier target fallido permanece fallido y
   se registra con su error exacto.
5. Registrar resultados observados en evidencia versionada separando entorno
   de producto. No convertir disponibilidad del runner en cierre de tickets.

Validación local previa a publicar:

```text
./scripts/verify-native-ci-config.sh
git diff --check
```

El primer comando valida trigger manual, permisos, cinco labels, SHA de checkout,
ausencia de secrets/cache/artifacts/larger/emulación y enlaces al método. La
sintaxis YAML se comprueba además con un parser local disponible, sin instalar
dependencias; esto no sustituye el parser de GitHub, que solo será observado
tras la integración en `master` y el dispatch autorizado.

## Futura aceptación de producto

No se crea ahora un workflow de aceptación porque los ports y entrypoints de
26/27 aún no existen. Cuando cada ticket entregue su laboratorio real y su
nombre quede documentado, el workflow de aceptación deberá:

1. comprobar que el entrypoint requerido existe y es ejecutable; si falta,
   terminar en error antes de anunciar ninguna prueba;
2. construir y ejecutar en el mismo target nativo, y comprobar arquitectura del
   artefacto/proceso antes de interpretar resultados;
3. instalar identidades reales separadas de custodio, humano y agente; el
   runner admin solo orquesta, y el proceso agente debe usar un token/UID no
   privilegiado real;
4. ejecutar servicio, canal/peer, permisos, negativas, crash/recovery y
   mantenimiento de un solo boot que el ticket defina, con canarios únicamente
   sintéticos;
5. fallar ante falta de puerto, herramienta, identidad restringida o resultado,
   sin skip, mock, inspección estática como sustituto ni cambio de plataforma.

Esta clase CI nunca contará como evidencia de `install -> reboot FDE`, TTY
humano auténtico, Ghostty/Terminal.app/Windows Terminal, clipboard humano
completo, firma/notarización/Authenticode real o Windows 11 x64. Esas pruebas
siguen requiriendo laboratorios nativos distintos; su ausencia mantiene los
tickets abiertos.

Limitación conocida a comprobar antes de pruebas multi-UID Linux: una
[incidencia abierta de runner-images](https://github.com/actions/runner-images/issues/14649)
documenta `XDG_RUNTIME_DIR` global apuntando al UID de `runner` en Ubuntu 24.04
x64/ARM64. Si afecta una sesión requerida, la prueba falla y el entorno queda
no apto; este método no corrige la imagen ni sustituye la sesión real.
