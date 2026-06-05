<?php
PluginFirewallDriverRegistry::register('hpe', 'PluginFirewallDriverHpe', 'HPE (ProCurve/Aruba/Comware)', false, true);

class PluginFirewallDriverHpe {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass  = PluginFirewallConfig::decryptPassword($device['password_enc']);
        $model = $device['model'] ?? '';
        // \b fails on "HP1920" (HP+1920 are both \w), use plain substring match
        $isComware = (bool)preg_match('/(comware|1910|1920|1950|5500|5900|7500)/i', $model);

        if ($isComware) {
            // Comware: screen-length disable → display current-configuration
            $output = $conn->sshInteractive(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                [
                    ['expect' => '>',  'send' => 'screen-length disable',       'timeout' => 10],
                    ['expect' => '>',  'send' => 'display current-configuration','timeout' => 5],
                    ['drain'  => 120],
                    ['send'   => 'quit'],
                ]
            );
        } else {
            // ProCurve/ArubaOS-Switch: no page then show running-config
            $output = $conn->sshInteractive(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                [
                    ['expect' => '#',  'send' => 'no page',           'timeout' => 10],
                    ['expect' => '#',  'send' => 'show running-config','timeout' => 5],
                    ['drain'  => 120],
                ]
            );
        }
        return trim($output);
    }

    public static function parseInterfaces(string $config): array {
        $isComware = strpos($config, 'interface Vlan-interface') !== false
                  || strpos($config, 'ip route-static') !== false;
        return $isComware ? self::parseInterfacesComware($config) : self::parseInterfacesProCurve($config);
    }

    private static function parseInterfacesComware(string $config): array {
        $ifaces = [];
        preg_match_all('/^interface (\S+)(.*?)^#/ms', $config, $blocks, PREG_SET_ORDER);
        foreach ($blocks as $b) {
            $ifName = $b[1]; $body = $b[2];
            $ip = null; $prefix = null;
            if (preg_match('/\s+ip address\s+(\S+)\s+(\S+)/m', $body, $m)) {
                $ip     = $m[1];
                $prefix = is_numeric($m[2]) ? (int)$m[2] : self::maskToPrefix($m[2]);
            }
            $desc = null;
            if (preg_match('/\s+description\s+(.+)/m', $body, $dm)) $desc = trim($dm[1]);
            $ifaces[] = [
                'if_name'     => $ifName,
                'nameif'      => null,
                'description' => $desc,
                'ip_address'  => $ip,
                'prefix_len'  => $prefix,
                'is_active'   => (bool)preg_match('/\s+shutdown\b/m', $body) ? 0 : 1,
                'is_dhcp'     => 0,
                'parent_if'   => null,
            ];
        }
        return $ifaces;
    }

    private static function parseInterfacesProCurve(string $config): array {
        $ifaces = [];
        // VLAN SVIs
        preg_match_all('/^vlan (\d+)(.*?)^!/ms', $config, $blocks, PREG_SET_ORDER);
        foreach ($blocks as $b) {
            $vlanId = $b[1]; $body = $b[2];
            if (!preg_match('/\s+ip address\s+(\S+)\s+(\S+)/m', $body, $m)) continue;
            $name = null;
            if (preg_match('/\s+name\s+"?([^"\n]+)"?/m', $body, $nm)) $name = trim($nm[1]);
            $ifaces['vlan'.$vlanId] = [
                'if_name'     => 'vlan' . $vlanId,
                'nameif'      => $name,
                'description' => "VLAN $vlanId",
                'ip_address'  => $m[1],
                'prefix_len'  => self::maskToPrefix($m[2]),
                'is_active'   => 1,
                'is_dhcp'     => 0,
                'parent_if'   => null,
            ];
        }
        // Routed physical interfaces
        preg_match_all('/^interface (\S+)(.*?)^!/ms', $config, $blocks, PREG_SET_ORDER);
        foreach ($blocks as $b) {
            $ifName = $b[1]; $body = $b[2];
            if (!preg_match('/\s+ip address\s+(\S+)\s+(\S+)/m', $body, $m)) continue;
            $desc = null;
            if (preg_match('/\s+description\s+(.+)/m', $body, $dm)) $desc = trim($dm[1]);
            $ifaces[$ifName] = [
                'if_name'     => $ifName,
                'nameif'      => null,
                'description' => $desc,
                'ip_address'  => $m[1],
                'prefix_len'  => self::maskToPrefix($m[2]),
                'is_active'   => 1,
                'is_dhcp'     => 0,
                'parent_if'   => null,
            ];
        }
        return array_values($ifaces);
    }

    public static function parseRoutes(string $config): array {
        $routes = [];
        if (strpos($config, 'ip route-static') !== false) {
            // Comware: ip route-static <dst> <mask|prefix> <gateway> [preference <n>]
            foreach (explode("\n", $config) as $line) {
                if (!preg_match('/^ip route-static\s+(\S+)\s+(\S+)\s+(\S+)/', rtrim($line), $m)) continue;
                $prefix    = is_numeric($m[2]) ? (int)$m[2] : self::maskToPrefix($m[2]);
                $isDefault = ($m[1] === '0.0.0.0' && $prefix === 0);
                $routes[]  = ['dst_network'=>$m[1],'dst_prefix'=>$prefix,'gateway'=>$m[3],
                              'metric'=>1,'is_default'=>$isDefault?1:0,'is_active'=>1];
            }
        } else {
            // ProCurve: ip route <dst> <mask> <gateway> [metric]
            foreach (explode("\n", $config) as $line) {
                if (!preg_match('/^ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?/', rtrim($line), $m)) continue;
                $prefix    = self::maskToPrefix($m[2]);
                $isDefault = ($m[1] === '0.0.0.0' && $prefix === 0);
                $routes[]  = ['dst_network'=>$m[1],'dst_prefix'=>$prefix,'gateway'=>$m[3],
                              'metric'=>(int)($m[4]??1),'is_default'=>$isDefault?1:0,'is_active'=>1];
            }
        }
        return $routes;
    }

    private static function maskToPrefix(string $mask): int {
        $long = ip2long($mask);
        if ($long === false) return 32;
        return strlen(rtrim(sprintf('%032b', $long & 0xFFFFFFFF), '0'));
    }

    public static function parseFirewallRules(string $config): array {
        $rules = []; $idx = 0; $acl = null;
        foreach (explode("\n", $config) as $line) {
            $line = rtrim($line);
            if (preg_match('/^acl (?:number )?(\d+)/', $line, $m)) { $acl = 'acl-'.$m[1]; continue; }
            if ($acl && preg_match('/^\s*rule \d+ (permit|deny)(?:\s+(.*))?/', $line, $m)) {
                $body = $m[2] ?? '';
                $r = ['rule_index'=>++$idx,'chain'=>$acl,'action'=>$m[1],'protocol'=>null,
                      'src_address'=>null,'dst_address'=>null,'src_port'=>null,'dst_port'=>null,
                      'interface_in'=>null,'interface_out'=>null,'comment'=>null,'enabled'=>1,
                      'raw_rule'=>trim($line)];
                if (preg_match('/source (\S+)(?:\s+(\S+))?/', $body, $sm)) $r['src_address'] = $sm[1].(isset($sm[2])?'/'.$sm[2]:'');
                if (preg_match('/destination (\S+)(?:\s+(\S+))?/', $body, $dm)) $r['dst_address'] = $dm[1].(isset($dm[2])?'/'.$dm[2]:'');
                $r['rule_hash'] = md5($acl.$m[1].$r['src_address'].$r['dst_address']);
                $rules[] = $r;
            }
        }
        return $rules;
    }
}
