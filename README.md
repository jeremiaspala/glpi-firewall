# glpi-firewall — Net Backup & Firewall Audit Plugin for GLPI 11

Plugin para GLPI 11 que centraliza el backup de configuraciones de equipos de red (routers, switches, firewalls), la auditoría de reglas cross-vendor, la comparación de configuraciones con diff histórico y la generación automática del mapa de topología de red.

> **Estado:** En desarrollo activo — funcional en producción con Mikrotik RouterOS, Cisco ASA y switches HPE.

---

## Funcionalidades

### Backup automático de configuraciones
- Backup vía SSH/Telnet de cualquier equipo de red
- Programación por dispositivo: manual, diario o semanal
- Log de ejecución en tiempo real durante el backup
- Detección automática de cambios (hash SHA-256 por backup)
- Retención configurable (default: 90 días)

### Drivers de dispositivos soportados

| Vendor key | Dispositivos | Backup | Reglas FW | Interfaces | Rutas |
|------------|-------------|--------|-----------|-----------|-------|
| `mikrotik` | RouterOS (RB, CCR, CRS) | ✓ | ✓ | ✓ | ✓ |
| `cisco_asa` | Cisco ASA | ✓ | ✓ | ✓ | ✓ |
| `cisco` | Cisco IOS/IOS-XE | ✓ | ✓ | ✓ | ✓ |
| `cisco_ftd` | Cisco Firepower FTD | ✓ | — | — | — |
| `hpe` | HPE ProCurve / Comware | ✓ | ✓ | ✓ | ✓ |
| `fortinet` | FortiGate FortiOS | ✓ | ✓ | — | — |
| `tplink` | TP-Link (SSH/Telnet) | ✓ | — | — | — |

Agregar un nuevo vendor: crear `inc/driver/nuevo.class.php` con la clase correspondiente. El registry la autodescubre sin tocar nada más.

### Comparador de configuraciones
- Vista por dispositivo con historial de backups
- Indicador de cambios entre versiones (hash comparison)
- Diff lado a lado con highlight verde/rojo
- Diff optimizado con `diff -u` del sistema (sin OOM en configs grandes)

### Auditoría de reglas de firewall
- Parseo cross-vendor de reglas (ASA ACLs, RouterOS filter chains, Fortinet policies)
- Vista unificada con filtros por chain, action, protocolo, dirección
- Comparación de reglas entre dos firewalls distintos
- Detección de reglas idénticas, únicas y conflictivas

### Mapa de topología de red (D3.js)

El plugin construye el mapa automáticamente a partir de tres capas de información:

**L2 (gris):** tabla MAC vía SNMP → qué dispositivo está conectado en qué puerto del switch. Se cruza con el inventario de GLPI para identificar equipos.

**L3 subnet (azul punteado):** interfaces con IPs parseadas del running-config. Dos dispositivos que comparten subnet aparecen conectados. Para equipos con IP dinámica (DHCP), se usa el hostname configurado en el plugin como IP de management /32.

**Rutas estáticas (naranja punteado):** tabla de ruteo parseada del config. Si un dispositivo tiene una ruta estática o default cuyo gateway es la IP de otro dispositivo conocido, se dibuja un enlace de ruteo (solo cuando no hay ya un link L3 directo entre ese par).

Interfaces virtuales soportadas: VLANs sobre bridge (RouterOS), sub-interfaces Cisco, Vlan-interface Comware, VLANs ProCurve.

---

## Requisitos del servidor

### GLPI
- GLPI 11.x (probado en 11.0.7)
- PHP 8.2+

### Paquetes del sistema (en el servidor GLPI)

```bash
# SSH sin contraseña interactiva
apt install sshpass

# SNMP para el mapa de topología
apt install snmp snmp-mibs-downloader

# diff del sistema (ya viene en cualquier Linux)
which diff
```

### Extensiones PHP requeridas
```
php-mbstring
php-pcre   # viene con PHP core
```

> **Nota:** La extensión `ssh2` de PHP NO es requerida. El plugin usa `proc_open` + `sshpass` para no depender de libssh2.

### Puertos / acceso de red
- El servidor GLPI necesita alcance SSH (22) o Telnet (23) a todos los equipos configurados
- Para equipos con cipher heredados (Cisco ASA viejo): asegurarse que `sshpass` soporte las opciones de `KexAlgorithms` y `HostKeyAlgorithms` configuradas en el driver

---

## Instalación

### 1. Copiar el plugin

```bash
cp -r glpi-firewall/ /var/www/html/glpi/plugins/firewall/
chown -R www-data:www-data /var/www/html/glpi/plugins/firewall/
```

### 2. Activar en GLPI

1. Ir a **Configuración → Plugins**
2. Buscar "Net Backup & Firewall Audit"
3. Instalar → Activar

El proceso de instalación crea las tablas necesarias en la base de datos:
- `glpi_plugin_firewall_devices`
- `glpi_plugin_firewall_backups`
- `glpi_plugin_firewall_rules`
- `glpi_plugin_firewall_interfaces`
- `glpi_plugin_firewall_routes`
- `glpi_plugin_firewall_snmp_macs`
- `glpi_plugin_firewall_config`

### 3. Configurar el cron (backups automáticos)

```bash
# Agregar al crontab de www-data
crontab -u www-data -e

# Agregar esta línea:
*/5 * * * * php /var/www/html/glpi/bin/console cron:run
```

---

## Configuración de dispositivos

Desde el menú **Net Backup → Dispositivos → Nuevo**:

| Campo | Descripción |
|-------|-------------|
| Vendor | Tipo de dispositivo (mikrotik, cisco_asa, etc.) |
| Hostname/IP | IP de gestión del equipo |
| Protocolo | SSH (default) o Telnet |
| Puerto | 22 para SSH, 23 para Telnet |
| Usuario | Usuario SSH del equipo |
| Password | Password SSH (se encripta en DB con AES) |
| Enable password | Solo para Cisco IOS/ASA con enable |
| SNMP Community | Para el mapa de topología (default: public) |
| Schedule | manual / daily / weekly |

### Ejemplo: Mikrotik RouterOS

El plugin ejecuta `/export verbose` via SSH no interactivo. El usuario SSH debe tener permiso de read sobre `/ip firewall filter`, `/ip address`, `/ip route` y `/interface`.

```
# En RouterOS
/user add name=glpi-backup group=read password=YOURPASSWORD
```

### Ejemplo: Cisco ASA con cipher heredado

Para ASA con firmware antiguo que requiere algoritmos deprecated:

```
# En el servidor GLPI, agregar a /etc/ssh/ssh_config o ~/.ssh/config:
Host 10.x.x.x
    KexAlgorithms +diffie-hellman-group14-sha1
    HostKeyAlgorithms +ssh-rsa
    Ciphers +aes256-cbc
```

El driver `cisco_asa` detecta automáticamente si necesita modo interactivo con enable.

---

## Mapa de topología — lógica de construcción

Para que un dispositivo aparezca en el mapa:

1. **Tener un backup exitoso** → el plugin parsea interfaces y rutas al hacer backup
2. **Tener IP en alguna interfaz** (estática o via hostname como fallback) → permite detectar adjacencias L3
3. **SNMP habilitado** (opcional) → permite detectar conexiones L2 y equipos del inventario

Los switches con IP dinámica (DHCP) participan automáticamente si su hostname/IP de gestión está configurado en el plugin — el algoritmo de adjacencia usa `min(prefix_A, prefix_B)` para detectar si caen en la misma subnet que otro dispositivo.

---

## Estructura del proyecto

```
firewall/
├── ajax/           # Handlers AJAX (backup en vivo, SNMP poll, CSRF)
├── cli/            # CLI runners (run_backup.php — independiente de Apache)
├── front/          # Pages GLPI (devices, backups, diff, audit, networkmap)
├── inc/
│   ├── driver/     # Drivers por vendor (mikrotik, cisco_asa, cisco_ios, hpe, ...)
│   ├── backup.class.php
│   ├── diff.class.php
│   ├── driverregistry.class.php
│   ├── networkmap.class.php
│   └── ...
├── hook.php        # Install/uninstall GLPI hooks
└── setup.php       # Plugin metadata
```

---

## Contribuir / Agregar un vendor nuevo

1. Crear `inc/driver/nuevomarca.class.php`
2. Al inicio del archivo, llamar a `PluginFirewallDriverRegistry::register()`
3. Implementar los métodos estáticos que correspondan:
   - `getConfig(array $device, PluginFirewallConnector $conn): string` — **obligatorio**
   - `parseFirewallRules(string $config): array` — opcional
   - `parseInterfaces(string $config): array` — opcional (habilita topología)
   - `parseRoutes(string $config): array` — opcional (habilita rutas en mapa)

El registry los autodescubre. No hay que registrar nada en ningún otro lado.

---

## Licencia

MIT — libre uso, modificación y distribución con atribución.
