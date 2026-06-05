# glpi-firewall — Net Backup & Firewall Audit para GLPI 11

> **En desarrollo activo — funcional en producción.**

Tenía el problema de siempre: cada vez que quería ver qué había cambiado en la config de algún switch o firewall, terminaba conectándome a mano, copiando el running-config y comparándolo con otro que había guardado en una carpeta con nombre "backup_final_FINAL_v2". Sin historial, sin automatización, sin diff.

Ya tenemos GLPI para inventario y help desk, así que lo natural era que el backup de configs también viviera ahí. No encontré ningún plugin que funcionara en GLPI 11 y soportara los vendors que uso (Mikrotik, Cisco ASA, HPE), así que lo armé yo.

---

## Qué hace

### Backup automático de configuraciones
Backup vía SSH o Telnet de routers, switches y firewalls. Programable por equipo: manual, diario o semanal. Detección automática de cambios por hash SHA-256 — si la config no cambió, lo sabe. El proceso corre en background desvinculado de Apache, así que podés cerrar el navegador y sigue corriendo.

### Comparador de configuraciones con historial
Vista por dispositivo con historial de backups, indicador de si hubo cambios entre versiones, y diff lado a lado con highlight verde/rojo. El diff lo hace `diff -u` del sistema operativo — no PHP puro, que explota con configs grandes.

### Auditoría de reglas de firewall
Parseo cross-vendor de reglas (ASA ACLs, RouterOS filter chains, Fortinet policies). Vista unificada con filtros, comparación entre dos firewalls distintos, detección de reglas idénticas y únicas.

### Mapa de topología de red automático
El plugin arma el mapa solo a partir de tres fuentes:

- **L2 (gris):** tabla MAC vía SNMP → qué dispositivo está conectado en qué puerto del switch. Se cruza con el inventario de GLPI para identificar los equipos.
- **L3 subnet (azul punteado):** interfaces con IPs parseadas del running-config. Dos dispositivos que comparten subnet aparecen conectados. Los equipos con IP dinámica (DHCP) participan usando el hostname configurado como IP /32 de management.
- **Ruta estática (naranja punteado):** si un dispositivo tiene una ruta estática o default cuyo gateway es la IP de otro dispositivo conocido, se dibuja el enlace. Solo aparece cuando no hay ya un link L3 directo entre ese par.

Interfaces virtuales soportadas: VLANs sobre bridge (RouterOS), sub-interfaces Cisco, Vlan-interface Comware, VLANs ProCurve.

---

## Vendors soportados

| Vendor | Backup | Reglas FW | Interfaces | Rutas |
|--------|--------|-----------|-----------|-------|
| Mikrotik RouterOS | ✓ | ✓ | ✓ | ✓ |
| Cisco ASA | ✓ | ✓ | ✓ | ✓ |
| Cisco IOS/IOS-XE | ✓ | ✓ | ✓ | ✓ |
| Cisco FTD | ✓ | — | — | — |
| HPE ProCurve / Comware | ✓ | ✓ | ✓ | ✓ |
| Fortinet FortiGate | ✓ | ✓ | — | — |
| TP-Link | ✓ | — | — | — |

Para agregar un vendor nuevo: crear `inc/driver/nuevomarca.class.php`. El registry lo autodescubre solo.

---

## Requisitos

**GLPI 11.x** (probado en 11.0.7), **PHP 8.2+**

Paquetes en el servidor:
```bash
apt install sshpass snmp snmp-mibs-downloader
```

> La extensión `php-ssh2` **no es necesaria**. El plugin usa `proc_open` + `sshpass`, así que no dependés de libssh2.

---

## Instalación

```bash
cp -r glpi-firewall/ /var/www/html/glpi/plugins/firewall/
chown -R www-data:www-data /var/www/html/glpi/plugins/firewall/
```

Después desde GLPI → **Configuración → Plugins** → instalar y activar. Crea las tablas automáticamente.

Para los backups automáticos, agregar el cron de GLPI si no está:
```bash
# crontab -u www-data -e
*/5 * * * * php /var/www/html/glpi/bin/console cron:run
```

---

## Configurar un dispositivo

Desde **Net Backup → Dispositivos → Nuevo**.

El campo **Modelo** es importante para HPE: el driver detecta automáticamente si es Comware (HP1920, HP5500, etc.) o ProCurve y usa el comando correcto en cada caso (`display current-configuration` vs `show running-config`).

Para Cisco ASA con firmware viejo que necesita ciphers deprecados, agregar a `/etc/ssh/ssh_config` en el servidor GLPI:
```
Host <IP_DEL_ASA>
    KexAlgorithms +diffie-hellman-group14-sha1
    HostKeyAlgorithms +ssh-rsa
    Ciphers +aes256-cbc
```

Para Mikrotik, el usuario SSH necesita permiso de lectura (grupo `read` es suficiente):
```
/user add name=glpi-backup group=read password=TUPASSWORD
```

---

## Agregar un vendor nuevo

Crear `inc/driver/nuevomarca.class.php`:

```php
<?php
PluginFirewallDriverRegistry::register('nuevomarca', 'PluginFirewallDriverNuevomarca', 'Nuevo Marca', false, true);

class PluginFirewallDriverNuevomarca {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass = PluginFirewallConfig::decryptPassword($device['password_enc']);
        return $conn->sshCommand($device['hostname'], (int)$device['port'],
                                 $device['username'], $pass, 'show running-config');
    }

    // Opcionales:
    public static function parseFirewallRules(string $config): array { return []; }
    public static function parseInterfaces(string $config): array    { return []; }
    public static function parseRoutes(string $config): array        { return []; }
}
```

El registry lo registra al incluir el archivo. No hay que tocar nada más.

---

## Estructura del proyecto

```
firewall/
├── ajax/          # Handlers AJAX (backup en vivo, SNMP poll, CSRF)
├── cli/           # CLI runner independiente de Apache
├── front/         # Pages GLPI
├── inc/
│   ├── driver/    # Un archivo por vendor
│   ├── backup.class.php
│   ├── diff.class.php
│   ├── networkmap.class.php
│   └── ...
├── hook.php       # Install/uninstall
└── setup.php      # Metadata del plugin
```

---

## Licencia

MIT
