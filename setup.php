<?php
/**
 * Network Backup & Firewall Audit Plugin for GLPI 11
 * setup.php
 */

define('PLUGIN_FIREWALL_VERSION', '1.0.0');
define('PLUGIN_FIREWALL_MIN_GLPI', '11.0.0');
define('PLUGIN_FIREWALL_MAX_GLPI', '12.0.0');

function plugin_version_firewall() {
    return [
        'name'         => 'Network Backup & Firewall Audit',
        'version'      => PLUGIN_FIREWALL_VERSION,
        'author'       => 'Jeremías Palazzesi',
        'license'      => 'GPL v2+',
        'homepage'     => '',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_FIREWALL_MIN_GLPI,
                'max' => PLUGIN_FIREWALL_MAX_GLPI,
            ],
        ],
    ];
}

function plugin_firewall_check_prerequisites() {
    if (version_compare(GLPI_VERSION, PLUGIN_FIREWALL_MIN_GLPI, 'lt') ||
        version_compare(GLPI_VERSION, PLUGIN_FIREWALL_MAX_GLPI, 'ge')) {
        echo "Requires GLPI >= " . PLUGIN_FIREWALL_MIN_GLPI . " and < " . PLUGIN_FIREWALL_MAX_GLPI;
        return false;
    }
    if (!function_exists('proc_open')) {
        echo "Requires proc_open() to be enabled in PHP.";
        return false;
    }
    return true;
}

function plugin_firewall_check_config() {
    return true;
}

function plugin_firewall_init() {
    // legacy alias — no-op
}

function plugin_init_firewall() {
    global $PLUGIN_HOOKS;

    Plugin::registerClass('PluginFirewallDevice');
    Plugin::registerClass('PluginFirewallBackup');
    Plugin::registerClass('PluginFirewallAudit');
    Plugin::registerClass('PluginFirewallNetworkMap');
    Plugin::registerClass('PluginFirewallConfig');

    $PLUGIN_HOOKS['csrf_compliant']['firewall'] = true;

    $PLUGIN_HOOKS['menu_toadd']['firewall'] = [
        'firewall' => ['PluginFirewallDevice'],
    ];

    $PLUGIN_HOOKS['redefine_menus']['firewall'] = function ($menu) {
        $existing_types = $menu['firewall']['types'] ?? [];
        $menu['firewall'] = [
            'title'   => 'Net Backup',
            'icon'    => 'ti ti-router',
            'default' => '/plugins/firewall/front/device.php',
            'content' => [
                'devices' => ['title' => 'Dispositivos',  'page' => '/plugins/firewall/front/device.php',       'icon' => 'ti ti-router'],
                'backups' => ['title' => 'Backups',        'page' => '/plugins/firewall/front/backup.php',        'icon' => 'ti ti-database'],
                'diff'    => ['title' => 'Diferencias',    'page' => '/plugins/firewall/front/diff.php',          'icon' => 'ti ti-git-compare'],
                'audit'   => ['title' => 'Auditoría FW',   'page' => '/plugins/firewall/front/firewallaudit.php', 'icon' => 'ti ti-shield-check'],
                'netmap'  => ['title' => 'Mapa de Red',    'page' => '/plugins/firewall/front/networkmap.php',    'icon' => 'ti ti-topology-star-3'],
                'config'  => ['title' => 'Configuración',  'page' => '/plugins/firewall/front/config.php',        'icon' => 'ti ti-settings'],
            ],
            'types' => $existing_types,
        ];
        return $menu;
    };
}
