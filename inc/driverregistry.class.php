<?php
/**
 * Driver registry — add a new vendor by dropping a class into inc/driver/
 * and calling PluginFirewallDriverRegistry::register().
 *
 * Each driver class must implement:
 *   static getConfig(array $device, PluginFirewallConnector $conn): string
 *   static parseFirewallRules(string $config): array   (can return [] if N/A)
 *
 * Auto-discovery: any file matching inc/driver/*.class.php whose class
 * calls register() in its body is picked up automatically.
 */
class PluginFirewallDriverRegistry {

    private static array $drivers = [];

    /**
     * Register a driver.
     * $label: human-readable label shown in the UI
     * $isFirewall: whether the vendor has parseable firewall rules
     * $supportsSnmpMap: whether we can poll this device's MAC table via SNMP
     */
    public static function register(
        string $vendorKey,
        string $className,
        string $label,
        bool   $isFirewall      = false,
        bool   $supportsSnmpMap = true
    ): void {
        self::$drivers[$vendorKey] = [
            'class'           => $className,
            'label'           => $label,
            'is_firewall'     => $isFirewall,
            'supports_snmp'   => $supportsSnmpMap,
        ];
    }

    public static function all(): array {
        self::loadAll();
        return self::$drivers;
    }

    public static function get(string $vendorKey): ?array {
        self::loadAll();
        return self::$drivers[$vendorKey] ?? null;
    }

    public static function getLabel(string $vendorKey): string {
        $d = self::get($vendorKey);
        return $d ? $d['label'] : $vendorKey;
    }

    public static function isFirewall(string $vendorKey): bool {
        $d = self::get($vendorKey);
        return $d ? $d['is_firewall'] : false;
    }

    /**
     * Default backup commands shown as placeholder in the device form.
     * Used when no custom backup_command is set.
     */
    public static function defaultBackupCommand(string $vendor, string $model = ''): string {
        return match($vendor) {
            'mikrotik'  => '/export verbose',
            'cisco_asa' => 'show running-config',
            'cisco'     => 'show running-config',
            'cisco_ftd' => '',
            'hpe'       => (bool)preg_match('/(comware|1910|1920|1950|5500|5900|7500)/i', $model)
                               ? 'display current-configuration'
                               : 'show running-config',
            'fortinet'  => 'show full-configuration',
            'tplink'    => 'show running-config',
            default     => '',
        };
    }

    public static function fetchConfig(array $device, PluginFirewallConnector $conn): string {
        $customCmd = trim($device['backup_command'] ?? '');
        $d = self::get($device['vendor']);
        if (!$d) {
            throw new \RuntimeException("Vendor desconocido: {$device['vendor']}");
        }

        if (!empty($customCmd)) {
            // If the driver signals it needs interactive SSH (e.g. Comware devices that don't
            // support SSH exec channel), route through getConfig() which handles it properly.
            $needsInteractive = method_exists($d['class'], 'requiresInteractiveSsh')
                             && call_user_func([$d['class'], 'requiresInteractiveSsh'], $device);
            if (!$needsInteractive) {
                $pass = PluginFirewallConfig::decryptPassword($device['password_enc']);
                return $conn->sshCommand(
                    $device['hostname'], (int)$device['port'],
                    $device['username'], $pass, $customCmd
                );
            }
        }

        return call_user_func([$d['class'], 'getConfig'], $device, $conn);
    }

    public static function parseRules(string $vendor, string $config): array {
        $d = self::get($vendor);
        if (!$d) return [];
        return call_user_func([$d['class'], 'parseFirewallRules'], $config);
    }

    public static function parseInterfaces(string $vendor, string $config): array {
        $d = self::get($vendor);
        if (!$d || !method_exists($d['class'], 'parseInterfaces')) return [];
        return call_user_func([$d['class'], 'parseInterfaces'], $config);
    }

    public static function parseRoutes(string $vendor, string $config): array {
        $d = self::get($vendor);
        if (!$d || !method_exists($d['class'], 'parseRoutes')) return [];
        return call_user_func([$d['class'], 'parseRoutes'], $config);
    }

    private static bool $loaded = false;

    private static function loadAll(): void {
        if (self::$loaded) return;
        self::$loaded = true;
        $dir = __DIR__ . '/driver';
        foreach (glob("$dir/*.class.php") as $file) {
            require_once $file;
        }
    }
}
