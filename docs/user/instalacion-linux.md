# Instalación local en Linux

Instala el gestor en este equipo Linux x86_64 a partir de este checkout: sin descargas, paquetes ni CI. Sigue el layout de [distribución G8](../design/distribution.md) y el [aislamiento G1](../design/isolation.md).

## Qué queda instalado

| Pieza | Dónde | Propietario |
| --- | --- | --- |
| Binarios | `/opt/passwordmanager/releases/<commit>/bin`, enlace `current` | root |
| Comandos | `/usr/local/bin/pm`, `pm-tui`, `pm-agent` | root |
| Perfiles y dispositivo | `/etc/passwordmanager/` | root |
| Bóveda, bootstrap y clave del custodio | `/var/lib/passwordmanager/` (0700) | cuenta de sistema `passwordmanager` |
| Sockets | `/run/passwordmanager/{human,agent}.sock` | servicio |
| Servicio | `passwordmanager.service` (systemd) | `passwordmanager` |
| Tu clave humana | `~/.config/passwordmanager/human.key` (0400) | tú |
| Agente | cuenta `pm-agent`, clave en `/var/lib/pm-agent/.config/passwordmanager/` | `pm-agent` |

El custodio, tú y el agente son tres UID distintos: el diseño lo exige. Los agentes que deban usar credenciales corren como `pm-agent`, nunca con tu cuenta.

## Pasos

1. Compilar, como tu usuario:

       ./scripts/build-linux-release.sh

2. Instalar. Crea las cuentas, las claves y la bóveda, y arranca el servicio. Te pide la contraseña maestra y te muestra el código de recuperación: guárdalo fuera del equipo.

       sudo ./scripts/install-linux-local.sh install

   Al terminar imprime una **línea de inscripción** del agente.

3. Abrir la TUI, como tu usuario:

       pm-tui

   - Desbloquea con la contraseña maestra.
   - `n` crea un login (`título|usuario|URL|notas` y luego la contraseña enmascarada; si la dejas vacía, se genera una de 24 caracteres). `e` edita el seleccionado.
   - `m` importa CSV de Chrome o Apple, o un 1PUX de 1Password.
   - `a` abre el acceso delegado: `n` y pega la línea de inscripción; `s` reanuda el acceso delegado (una bóveda nueva empieza suspendida); en una credencial, `e` la habilita para agentes. `Esc` vuelve al contenido.
   - `b` gestiona backup y recuperación; `l` bloquea y sale.

4. Registrar la identidad nativa del agente (una vez, después de inscribirlo):

       sudo ./scripts/install-linux-local.sh register-agent

5. Probar como agente:

       sudo -u pm-agent pm-agent capabilities --json
       sudo -u pm-agent pm-agent credentials list --json

   Por MCP: `pm-agent mcp` (stdio), ejecutado como `pm-agent`.

## Actualizar y diagnosticar

    ./scripts/build-linux-release.sh && sudo ./scripts/install-linux-local.sh upgrade
    sudo ./scripts/install-linux-local.sh status
    journalctl -u passwordmanager

`upgrade` sustituye los binarios y reinicia el servicio; no toca la bóveda ni las claves.

## Límites actuales

- Solo Linux x86_64 en este equipo. macOS, Windows, aarch64, paquetes firmados y TUF quedan fuera (ver [decisiones](../../decisions.md)).
- La sincronización entre dispositivos no se instala ni se configura.
- Los adaptadores de integración (SSH, GitHub, Keycloak) no se configuran por defecto. Sin un adaptador provisionado (`pm-custody provision-adapters`), `auth start` falla de forma explícita con `ADAPTER_UNAVAILABLE`. Hoy son demostradores de contrato: el consumidor SSH, por ejemplo, abre y cierra un canal autenticado, pero no entrega una sesión interactiva.
- Si un error de disco (EIO/ENOSPC) interrumpe la subida de un adjunto, quedan datos cifrados de staging que no se limpian al reiniciar. La autoridad y el contenido confirmado no cambian.
- El volumen debe estar cifrado (FDE) para proteger la clave bootstrap frente a copia de disco; el instalador no lo comprueba.
