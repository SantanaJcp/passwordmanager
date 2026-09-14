# Sondeo acotado: laboratorio Linux descartable para futura aceptación 03

Fecha: 2026-09-12. Host sondeado: Linux x86_64. **Esto no implementa 03, no es evidencia de aceptación 03 y no valida el perfil de producción.** No se editó el repositorio, no se instalaron dependencias, no se elevaron privilegios y no se crearon usuarios, unidades systemd, contenedores persistentes ni secretos.

## Conclusión

**Viable sin acción externa para un laboratorio descartable de integración:** un *user namespace* no privilegiado puede mapear tres UIDs/GIDs distintos a sub-UIDs/sub-GIDs reales del kernel, ejecutar custodio/humano/agente como UIDs diferentes, aplicar DAC a archivos y directorios, obtener `SO_PEERCRED` bilateral real en sockets Unix, rechazar un agente en el endpoint humano y reiniciar el proceso custodio conservando un archivo bootstrap sintético.

La alternativa recomendada para la futura prueba es `unshare` + rangos subordinate ya asignados + un harness temporal. Docker rootless no está preparado y no aporta nada necesario a este corte.

## Base del host verificada

Comandos ejecutados (solo lectura):

```sh
id
uname -srmo
/usr/lib/systemd/systemd --version | head -2
cat /proc/sys/kernel/unprivileged_userns_clone
cat /proc/sys/user/max_user_namespaces
me=$(id -un)
awk -F: -v u="$me" '$1==u {print $2 ":" $3}' /etc/subuid
awk -F: -v u="$me" '$1==u {print $2 ":" $3}' /etc/subgid
stat -c '%n mode=%A owner=%U:%G' /usr/bin/newuidmap /usr/bin/newgidmap /usr/bin/bwrap
getcap /usr/bin/newuidmap /usr/bin/newgidmap /usr/bin/bwrap
docker context ls
timeout 6 docker info --format 'rootless={{json .SecurityOptions}} server={{.ServerVersion}} driver={{.Driver}}'
```

Resultados relevantes:

- UID/GID invocante: `1000:1000`; kernel `7.2.3-arch1-3`; systemd `261`.
- `kernel.unprivileged_userns_clone=1`; `user.max_user_namespaces=126448`.
- Para el usuario actual existen `subuid=100000:65536` y `subgid=100000:65536`.
- `newuidmap` tiene `cap_setuid=ep`; `newgidmap`, `cap_setgid=ep`.
- `unshare 2.42.3`, `bwrap`, Docker y `systemd-nspawn` existen. Una prueba mínima de `bwrap --unshare-user` funcionó.
- Docker solo tiene contexto `default` a `/var/run/docker.sock`; el usuario recibe `permission denied`. No están instalados `dockerd-rootless.sh`, `dockerd-rootless-setuptool.sh` ni `rootlesskit`. Por tanto **no** se cuenta Docker como alternativa rootless disponible.

## Prueba temporal ejecutada

Se creó `/tmp/pm_linux_lab_probe.py`, se ejecutó una vez dentro del siguiente mapa y el propio harness eliminó script y directorio temporal al terminar:

```sh
unshare --user \
  --map-users 0:1000:1 --map-users 1:100000:65535 \
  --map-groups 0:1000:1 --map-groups 1:100000:65535 \
  python /tmp/pm_linux_lab_probe.py
```

Mapa observado dentro del laboratorio:

```text
uid_map/gid_map:
0  1000    1
1  100000  65535
```

El harness usó UIDs internos `1=custodio`, `2=humano`, `3=agente`; corresponden a credenciales kernel distintas (sub-UIDs externos 100000, 100001 y 100002). Creó solo datos sintéticos:

- directorio de estado del custodio `0700`;
- `bootstrap.synthetic` `0400`, propietario UID custodio;
- directorio de runtime propiedad del custodio sin escritura para agente;
- sockets Unix separados `agent.sock` y `human.sock`.

Operaciones comprobadas y evidencia:

```text
custodio pid 3669320 uid 1; SHA-256 bootstrap ed3a...704ed2
agente uid 3: read_bootstrap       -> DENIED errno 13
agente uid 3: overwrite_bootstrap  -> DENIED errno 13
agente uid 3: unlink_agent_socket  -> DENIED errno 13

server agent.sock: peer_uid=3 expected=3 -> ALLOW
client agente: SO_PEERCRED server_uid=1 expected=1 -> true
server human.sock: peer_uid=2 expected=2 -> ALLOW
client humano: SO_PEERCRED server_uid=1 expected=1 -> true
server human.sock: peer_uid=3 expected=2 -> DENY
client impostor recibió DENY

reinicio: pid 3669320 -> 3669327
segundo custodio uid 1; SHA-256 bootstrap ed3a...704ed2 (igual)
agente reconectó; ambas partes volvieron a observar UIDs esperados por SO_PEERCRED
```

`SO_PEERCRED` se leyó mediante `getsockopt(SOL_SOCKET, SO_PEERCRED)` sobre cada socket conectado, tanto en servidor como en cliente; no fue un campo declarado por el peer. El reinicio fue de proceso, no reboot del host. Al finalizar, `find /tmp -maxdepth 1 -name 'pm-linux-lab-*'` no devolvió residuos.

## Qué permite afirmar y qué no

Permite afirmar solamente que este host tiene mecanismos suficientes para construir una prueba no privilegiada y descartable de:

1. tres credenciales UID/GID kernel distintas;
2. denegación DAC de lectura, escritura y sustitución de recursos sintéticos;
3. identificación bilateral real por `SO_PEERCRED` y rechazo de peer con UID incorrecto;
4. persistencia de archivo sintético y reconexión tras reinicio del proceso.

No permite afirmar ni debe contarse como:

- cuentas nativas persistentes en `/etc/passwd`, `User=passwordmanager` real o servicio systemd de sistema;
- equivalencia entre namespace y perfil Linux de producción;
- integridad de binarios/configuración `root-owned`, resistencia frente al administrador/namespace-root, aislamiento de memoria, escritorio, terminal o portapapeles;
- TLS 1.3 RPK/pinning/ALPN, claves reales, lógica del producto o `CUSTODY_UNAVAILABLE`;
- reboot real, desbloqueo/FDE, protección offline o soporte de plataforma;
- aceptación 03. El ticket 02 sigue siendo dependencia y la implementación real debe aportar TDD y checks exactos.

## Recomendación para la futura aceptación 03

Usar este harness como **capa de laboratorio**, sustituyendo el servidor sintético por los binarios implementados y conservando negativas explícitas. El test debe fallar cerrado si no puede establecer el mapa multi-UID, permisos o peer esperado; no degradarse a mismo UID ni simular credenciales. Registrar `/proc/<pid>/uid_map`, ownership/modos, PIDs, `SO_PEERCRED` de ambos extremos y códigos públicos reales.

No hace falta ninguna acción externa para ejecutar ese laboratorio en este host. Para validar además el perfil nativo de producción (cuenta sin login, unidad systemd, recursos root-owned y reboot/FDE), la acción externa mínima posterior sería autorizar una VM Linux descartable administrable —no modificar este host— y ejecutar allí la matriz nativa. Esa validación es separada y no queda cubierta por este sondeo.
