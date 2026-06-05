<?php
PluginFirewallDriverRegistry::register('tplink', 'PluginFirewallDriverTplink', 'TP-Link Managed', false, true);

class PluginFirewallDriverTplink {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass  = PluginFirewallConfig::decryptPassword($device['password_enc']);
        $proto = strtolower($device['protocol']);

        // Try HTTP backup API first (works on all TP-Link Smart/Managed switches).
        // SSH exec channel fails on OpenSSH 10+ due to ssh-dss key removal.
        // Fallback to SSH/Telnet for older models with RSA SSH support.
        $httpOutput = self::getConfigHttp($device['hostname'], $device['username'], $pass);
        if (!empty($httpOutput)) {
            return trim($httpOutput);
        }

        if ($proto === 'ssh') {
            return trim($conn->sshCommand(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                'show running-config'
            ));
        }

        return trim($conn->telnet(
            $device['hostname'], (int)$device['port'],
            $device['username'], $pass,
            [
                ['expect' => 'User Name:', 'send' => $device['username'], 'timeout' => 10, 'sensitive' => true],
                ['expect' => 'Password:',  'send' => $pass,               'timeout' => 10, 'sensitive' => true],
                ['expect' => '#',          'send' => 'terminal length 0', 'timeout' => 10],
                ['expect' => '#',          'send' => 'show running-config', 'timeout' => 5],
                ['drain'  => 30],
                ['send'   => 'exit'],
            ]
        ));
    }

    /**
     * TP-Link Smart switch HTTP API backup.
     * Login → /data/login.json  (POST JSON, returns _tid_ token)
     * Backup → /data/sysConfigBackup.cfg?operation=write&unit_id=0&_tid_=TOKEN&usrLvl=3
     */
    private static function getConfigHttp(string $host, string $user, string $pass): string {
        if (!function_exists('curl_init')) {
            return '';
        }

        $baseUrl = 'http://' . $host;

        // Step 1: login
        $ch = curl_init($baseUrl . '/data/login.json');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode(['operation' => 'write', 'username' => $user, 'password' => $pass]),
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $loginResp = curl_exec($ch);
        $loginCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (!$loginResp || $loginCode !== 200) {
            return '';
        }

        $loginData = json_decode($loginResp, true);
        if (!isset($loginData['errorcode']) || (int)$loginData['errorcode'] !== 0) {
            return '';
        }

        $tid    = $loginData['data']['_tid_'] ?? '';
        $usrLvl = $loginData['data']['usrLvl'] ?? 3;

        if (empty($tid)) {
            return '';
        }

        // Step 2: download config
        $url = $baseUrl . '/data/sysConfigBackup.cfg?operation=write&unit_id=0'
             . '&_tid_=' . urlencode($tid)
             . '&usrLvl=' . (int)$usrLvl;

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $config     = curl_exec($ch);
        $configCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (!$config || $configCode !== 200) {
            return '';
        }

        // Sanity check: TP-Link config starts with '!' or 'version' — reject JSON/HTML error pages
        $firstChar = ltrim($config)[0] ?? '';
        if ($firstChar === '{' || $firstChar === '<') {
            return '';
        }

        return $config;
    }

    public static function parseFirewallRules(string $config): array {
        return [];
    }

    public static function parseInterfaces(string $config): array {
        $ifaces = [];
        // TP-Link Smart switch config: interface vlan X / ip address X.X.X.X Y.Y.Y.Y
        preg_match_all('/^interface vlan(\d+)(.*?)^!/ms', $config, $blocks, PREG_SET_ORDER);
        foreach ($blocks as $b) {
            $vlanId = $b[1];
            $body   = $b[2];
            $ip = null; $prefix = null;
            if (preg_match('/\s+ip address\s+(\S+)\s+(\S+)/m', $body, $m)) {
                $ip     = $m[1];
                $prefix = self::maskToPrefix($m[2]);
            }
            $desc = null;
            if (preg_match('/\s+name\s+"?([^"\n]+)"?/m', $body, $dm)) $desc = trim($dm[1]);
            $ifaces[] = [
                'if_name'     => 'vlan' . $vlanId,
                'nameif'      => null,
                'description' => $desc ?? "VLAN $vlanId",
                'ip_address'  => $ip,
                'prefix_len'  => $prefix,
                'is_active'   => 1,
                'is_dhcp'     => 0,
                'parent_if'   => null,
            ];
        }
        return $ifaces;
    }

    public static function parseRoutes(string $config): array {
        $routes = [];
        foreach (explode("\n", $config) as $line) {
            // ip route <dst> <mask> <gateway> [distance]
            if (!preg_match('/^ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?/', rtrim($line), $m)) continue;
            if (filter_var($m[3], FILTER_VALIDATE_IP) === false) continue;
            $prefix    = self::maskToPrefix($m[2]);
            $isDefault = ($m[1] === '0.0.0.0' && $prefix === 0);
            $routes[]  = [
                'dst_network' => $m[1],
                'dst_prefix'  => $prefix,
                'gateway'     => $m[3],
                'metric'      => (int)($m[4] ?? 1),
                'is_default'  => $isDefault ? 1 : 0,
                'is_active'   => 1,
            ];
        }
        return $routes;
    }

    private static function maskToPrefix(string $mask): int {
        $long = ip2long($mask);
        if ($long === false) return (is_numeric($mask) ? (int)$mask : 32);
        return strlen(rtrim(sprintf('%032b', $long & 0xFFFFFFFF), '0'));
    }
}
