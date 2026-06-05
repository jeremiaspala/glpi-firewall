<?php
PluginFirewallDriverRegistry::register('mikrotik', 'PluginFirewallDriverMikrotik', 'Mikrotik RouterOS', true, true);

class PluginFirewallDriverMikrotik {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass = PluginFirewallConfig::decryptPassword($device['password_enc']);

        // SSH no interactivo — el comando se ejecuta y SSH termina solo
        $raw = $conn->sshCommand(
            $device['hostname'], (int)$device['port'],
            $device['username'], $pass,
            '/export verbose'
        );

        $raw = str_replace("\r\n", "\n", $raw);
        // Limpiar: quedarse desde la primera línea que empieza con '#'
        if (preg_match('/(# [^\n]*\n.*)/s', $raw, $m)) {
            return trim($m[1]);
        }
        return trim($raw);
    }

    public static function parseFirewallRules(string $config): array {
        $rules  = [];
        $idx    = 0;
        $config = str_replace("\r\n", "\n", $config);

        if (!preg_match('/\/ip firewall filter\n(.*?)(?=^\/|\Z)/ms', $config, $section)) {
            return $rules;
        }

        // Join continuation lines: trailing \ + newline + indent → single space
        $flat = preg_replace('/\\\\\n\s*/', ' ', $section[1]);

        foreach (explode("\n", $flat) as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') continue;
            if (strpos($line, 'add ') !== 0) continue;
            $rules[] = self::parseLine($line, ++$idx);
        }

        return $rules;
    }

    private static function parseLine(string $line, int $idx): array {
        $r = [
            'rule_index'    => $idx,
            'chain'         => self::val($line, 'chain'),
            'action'        => self::val($line, 'action'),
            'protocol'      => self::val($line, 'protocol'),
            'src_address'   => self::val($line, 'src-address'),
            'dst_address'   => self::val($line, 'dst-address'),
            'src_port'      => self::val($line, 'src-port'),
            'dst_port'      => self::val($line, 'dst-port'),
            'interface_in'  => self::val($line, 'in-interface'),
            'interface_out' => self::val($line, 'out-interface'),
            'comment'       => self::val($line, 'comment'),
            'enabled'       => strpos($line, 'disabled=yes') === false ? 1 : 0,
            'raw_rule'      => $line,
        ];
        $r['rule_hash'] = md5($r['chain'].$r['action'].$r['protocol'].$r['src_address'].$r['dst_address'].$r['src_port'].$r['dst_port']);
        return $r;
    }

    public static function parseRoutes(string $config): array {
        $config = str_replace("\r\n", "\n", $config);
        $routes = [];

        if (!preg_match('/\/ip route\n(.*?)(?=^\/|\Z)/ms', $config, $section)) {
            return $routes;
        }

        $flat = preg_replace('/\\\\\n\s*/', ' ', $section[1]);

        foreach (explode("\n", $flat) as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#' || strpos($line, 'add ') !== 0) continue;

            $dst      = self::val($line, 'dst-address') ?? '0.0.0.0/0';
            $gateway  = self::val($line, 'gateway');
            $disabled = strpos($line, 'disabled=yes') !== false;

            if (!$gateway || filter_var($gateway, FILTER_VALIDATE_IP) === false) continue;

            [$net, $prefix] = str_contains($dst, '/') ? explode('/', $dst, 2) : [$dst, '32'];
            $isDefault = ($net === '0.0.0.0' && (int)$prefix === 0);

            $routes[] = [
                'dst_network' => $net,
                'dst_prefix'  => (int)$prefix,
                'gateway'     => $gateway,
                'metric'      => 1,
                'is_default'  => $isDefault ? 1 : 0,
                'is_active'   => $disabled ? 0 : 1,
            ];
        }

        return $routes;
    }

    private static function mergeValues(array &$r, string $line): void {
        foreach (['src-address'=>'src_address','dst-address'=>'dst_address','src-port'=>'src_port','dst-port'=>'dst_port','protocol'=>'protocol','comment'=>'comment'] as $k=>$f) {
            $v = self::val($line, $k);
            if ($v !== null) $r[$f] = $v;
        }
    }

    public static function parseInterfaces(string $config): array {
        $config = str_replace("\r\n", "\n", $config);
        $ifaces = [];

        // 1. Static IPs from /ip address
        if (preg_match('/\/ip address\n(.*?)(?=^\/|\Z)/ms', $config, $section)) {
            $flat = preg_replace('/\\\\\n\s*/', ' ', $section[1]);
            foreach (explode("\n", $flat) as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#' || strpos($line, 'add ') !== 0) continue;
                $address  = self::val($line, 'address');
                $iface    = self::val($line, 'interface');
                $disabled = strpos($line, 'disabled=yes') !== false;
                $comment  = self::val($line, 'comment');
                if (!$address || !$iface) continue;
                [$ip, $prefix] = str_contains($address, '/') ? explode('/', $address, 2) : [$address, '32'];
                $ifaces[$iface] = [
                    'if_name'     => $iface,
                    'nameif'      => null,
                    'description' => $comment,
                    'ip_address'  => $ip,
                    'prefix_len'  => (int)$prefix,
                    'is_active'   => $disabled ? 0 : 1,
                    'is_dhcp'     => 0,
                    'parent_if'   => null,
                ];
            }
        }

        // 2. VLAN virtual interfaces from /interface vlan
        if (preg_match('/\/interface vlan\n(.*?)(?=^\/|\Z)/ms', $config, $section)) {
            $flat = preg_replace('/\\\\\n\s*/', ' ', $section[1]);
            foreach (explode("\n", $flat) as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#' || strpos($line, 'add ') !== 0) continue;
                $name     = self::val($line, 'name');
                $parent   = self::val($line, 'interface');
                $vlanId   = self::val($line, 'vlan-id');
                $disabled = strpos($line, 'disabled=yes') !== false;
                if (!$name) continue;
                if (!isset($ifaces[$name])) {
                    $ifaces[$name] = [
                        'if_name'     => $name,
                        'nameif'      => null,
                        'description' => $vlanId ? "VLAN $vlanId" : null,
                        'ip_address'  => null,
                        'prefix_len'  => null,
                        'is_active'   => $disabled ? 0 : 1,
                        'is_dhcp'     => 0,
                        'parent_if'   => $parent,
                    ];
                } else {
                    if ($parent && !$ifaces[$name]['parent_if']) $ifaces[$name]['parent_if'] = $parent;
                    if ($vlanId && !$ifaces[$name]['description']) $ifaces[$name]['description'] = "VLAN $vlanId";
                }
            }
        }

        // 3. Bridge interfaces from /interface bridge
        if (preg_match('/\/interface bridge\n(.*?)(?=^\/|\Z)/ms', $config, $section)) {
            $flat = preg_replace('/\\\\\n\s*/', ' ', $section[1]);
            foreach (explode("\n", $flat) as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#' || strpos($line, 'add ') !== 0) continue;
                $name     = self::val($line, 'name');
                $disabled = strpos($line, 'disabled=yes') !== false;
                $comment  = self::val($line, 'comment');
                if (!$name || isset($ifaces[$name])) continue;
                $ifaces[$name] = [
                    'if_name'     => $name,
                    'nameif'      => null,
                    'description' => $comment ?: 'bridge',
                    'ip_address'  => null,
                    'prefix_len'  => null,
                    'is_active'   => $disabled ? 0 : 1,
                    'is_dhcp'     => 0,
                    'parent_if'   => null,
                ];
            }
        }

        // 4. DHCP clients from /ip dhcp-client — marks interface as dynamic
        if (preg_match('/\/ip dhcp-client\n(.*?)(?=^\/|\Z)/ms', $config, $section)) {
            $flat = preg_replace('/\\\\\n\s*/', ' ', $section[1]);
            foreach (explode("\n", $flat) as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#' || strpos($line, 'add ') !== 0) continue;
                $iface    = self::val($line, 'interface');
                $disabled = strpos($line, 'disabled=yes') !== false;
                if (!$iface) continue;
                if (!isset($ifaces[$iface])) {
                    $ifaces[$iface] = [
                        'if_name'     => $iface,
                        'nameif'      => null,
                        'description' => null,
                        'ip_address'  => null,
                        'prefix_len'  => null,
                        'is_active'   => $disabled ? 0 : 1,
                        'is_dhcp'     => 1,
                        'parent_if'   => null,
                    ];
                } else {
                    $ifaces[$iface]['is_dhcp'] = 1;
                }
            }
        }

        return array_values($ifaces);
    }

    private static function val(string $line, string $key): ?string {
        if (preg_match('/' . preg_quote($key, '/') . '=\s*"([^"]*)"/', $line, $m)) return $m[1];
        if (preg_match('/' . preg_quote($key, '/') . '=\s*(\S+)/', $line, $m))     return $m[1];
        return null;
    }
}
