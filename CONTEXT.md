# Dominio: custodia y uso de credenciales

La bóveda permite al propietario administrar sus secretos y autorizar su utilización por agentes. Su responsabilidad no incluye controlar acciones ni sesiones posteriores en servicios externos.

## Lenguaje

### Propiedad y autoridad

**Humano propietario**: persona que administra la bóveda y decide qué agentes y credenciales habilita.
_Evitar_: «usuario» cuando pueda confundirse con una cuenta del servicio externo.

**Agente registrado**: agente cuya identidad fue autorizada por el propietario y que puede ser revocado individualmente; estar registrado no permite usar una credencial deshabilitada.
_Evitar_: «cualquier agente», «proceso local» como equivalentes de autorización.

**Dispositivo autorizado**: instalación emparejada por el propietario para participar en el uso o sincronización de su bóveda; no equivale a la identidad de un agente.
_Evitar_: «agente» para identificar el equipo.

**Custodio**: responsable de conservar los secretos y aplicar la autoridad del propietario sobre su utilización.
_Evitar_: «gestor de permisos externos».

### Contenido de la bóveda

**Bóveda**: colección protegida de elementos perteneciente al propietario; no es una cuenta de un proveedor ni una sesión autenticada.

**Elemento**: unidad de contenido de la bóveda, como una credencial, nota o archivo seguro. No todo elemento puede utilizarse para autenticar.
_Evitar_: «contraseña» para referirse a cualquier elemento.

**Credencial**: elemento que permite acreditar una identidad ante un destino mediante un método compatible; incluye más que contraseñas.

**Secreto de la bóveda**: valor protegido de un elemento, como una contraseña, semilla de códigos temporales o clave privada. El humano puede revelarlo explícitamente; el agente no debe recibirlo.

**Metadatos habilitados**: información no secreta autorizada para identificar una credencial del conjunto común, como su nombre y destino. No abarca indiscriminadamente notas o campos libres.

**Credencial habilitada**: credencial que el propietario incorporó al conjunto común de uso delegado.
_Evitar_: «credencial disponible» si solo significa que existe en la bóveda.

**Conjunto común**: selección única de credenciales habilitadas compartida por todos los agentes autorizados, sin subdivisión por agente ni proyecto.

### Autenticación

**Destino de autenticación**: servicio o sistema ante el que se utiliza una credencial, con la cuenta correspondiente cuando aplique.
_Evitar_: «proyecto» como sinónimo de destino.

**Intento de autenticación**: operación individual de uso de una credencial para autenticar; puede completarse, pausarse, vencer, cancelarse o fallar independientemente de otros intentos.
_Evitar_: «tarea del agente» como sinónimo.

**Intervención humana requerida**: verificación exigida por el proveedor que detiene únicamente el intento afectado, hasta que se comprueba su resolución o deja de ser válido.

**Sesión externa**: acceso establecido con el proveedor después de autenticar. Su gestión queda fuera de la bóveda; sus datos solo pasan a ser contenido custodiado si el humano los guarda expresamente como elementos.
_Evitar_: «secreto de la bóveda» para toda cookie o token emitido posteriormente.

### Delegación y bloqueo

**Autorización delegada**: permiso del propietario para que un agente registrado utilice las credenciales habilitadas sin recibir sus secretos; no concede administración humana de la bóveda.

**Bloqueo humano**: estado que impide el acceso humano a operaciones sensibles hasta desbloquearlo; no suspende por sí mismo la autorización delegada.
_Evitar_: «suspensión de agentes» como sinónimo.

**Suspensión de agentes**: interrupción global de nuevos usos delegados de credenciales; no cierra sesiones externas ya establecidas.

**Revocación de agente**: retirada de autorización a una identidad concreta. En un dispositivo desconectado, una revocación remota se conoce al sincronizar.

### Historia y recuperación

**Revisión de elemento**: versión conservada de un elemento. La resolución por última escritura selecciona la visible por timestamp y conserva el historial; no prueba cuál edición ocurrió más tarde en tiempo real con relojes desajustados.

**Papelera**: estado recuperable de un elemento eliminado; no equivale al borrado definitivo de todas sus copias.

Si borrado y edición son concurrentes, el elemento permanece en papelera y conserva el contenido ganador por última escritura. Solo una restauración humana explícita lo devuelve al estado activo; una edición no lo restaura implícitamente.

**Copia cifrada de recuperación**: copia protegida que permite restaurar datos con una vía de acceso válida; no autoriza por sí misma nuevos agentes.

**Clave de recuperación**: secreto conservado fuera del equipo que, junto con una copia cifrada utilizable, permite recuperar la bóveda sin una puerta trasera del operador.

**Servidor de sincronización**: servicio elegido por el propietario para intercambiar datos cifrados entre dispositivos autorizados, sin capacidad de descifrar la bóveda.
_Evitar_: «custodio» o «servicio de recuperación» para este servidor.
