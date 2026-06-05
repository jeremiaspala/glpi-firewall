<?php
/**
 * Plugin config helper
 */
class PluginFirewallConfig extends CommonDBTM {

    static $rightname = 'plugin_firewall';

    private static array $cache = [];

    public static function get(string $key, $default = null) {
        global $DB;
        if (isset(self::$cache[$key])) {
            return self::$cache[$key];
        }
        $rows = $DB->request([
            'FROM'  => 'glpi_plugin_firewall_config',
            'WHERE' => ['config_key' => $key],
            'LIMIT' => 1,
        ]);
        foreach ($rows as $row) {
            self::$cache[$key] = $row['config_value'];
            return $row['config_value'];
        }
        return $default;
    }

    public static function set(string $key, $value): void {
        global $DB;
        self::$cache[$key] = $value;
        $exists = $DB->request([
            'FROM'  => 'glpi_plugin_firewall_config',
            'WHERE' => ['config_key' => $key],
        ]);
        if (count($exists) > 0) {
            $DB->update('glpi_plugin_firewall_config', ['config_value' => $value], ['config_key' => $key]);
        } else {
            $DB->insert('glpi_plugin_firewall_config', ['config_key' => $key, 'config_value' => $value]);
        }
    }

    /**
     * Encrypt a password for storage using AES-256-CBC
     */
    public static function encryptPassword(string $plain): string {
        $key = hex2bin(self::get('encryption_key', str_repeat('00', 16)));
        $iv  = random_bytes(16);
        $enc = openssl_encrypt($plain, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $enc);
    }

    public static function decryptPassword(string $encrypted): string {
        if (empty($encrypted)) return '';
        try {
            $key  = hex2bin(self::get('encryption_key', str_repeat('00', 16)));
            $data = base64_decode($encrypted);
            $iv   = substr($data, 0, 16);
            $enc  = substr($data, 16);
            return openssl_decrypt($enc, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv) ?: '';
        } catch (\Throwable $e) {
            return '';
        }
    }

    public static function getTypeName($nb = 0) {
        return 'Net Backup Config';
    }
}
