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

    public static function fetchConfig(array $device, PluginFirewallConnector $conn): string {
        $d = self::get($device['vendor']);
        if (!$d) {
            throw new \RuntimeException("Vendor desconocido: {$device['vendor']}");
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
