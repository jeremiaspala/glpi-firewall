<?php
PluginFirewallDriverRegistry::register('cisco', 'PluginFirewallDriverCiscoIos', 'Cisco IOS/IOS-XE', false, true);

class PluginFirewallDriverCiscoIos {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass   = PluginFirewallConfig::decryptPassword($device['password_enc']);
        $enable = PluginFirewallConfig::decryptPassword($device['enable_password_enc'] ?? '');

        if ($enable) {
            $output = $conn->sshInteractive(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                [
                    ['expect' => '>',  'send' => 'enable',               'timeout' => 10],
                    ['expect' => '#',  'send' => 'terminal length 0',   'timeout' => 10],
                    ['expect' => '#',  'send' => 'show running-config', 'timeout' => 5],
                    ['drain'  => 60],
                    ['send'   => 'exit'],
                ]
            );
        } else {
            $output = $conn->sshCommand(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                'terminal length 0 ; show running-config'
            );
        }

        if (preg_match('/(Building configuration.*?\nCurrent configuration.*)/s', $output, $m)) {
            return preg_replace('/\nend\s*$/s', "\nend", trim($m[1]));
        }
        return trim($output);
    }

    public static function parseInterfaces(string $config): array {
        $ifaces = [];
        // Match interface blocks terminated by "!" or next "interface"
        preg_match_all('/^interface (\S+)(.*?)(?=^interface |\Z)/ms', $config, $blocks, PREG_SET_ORDER);
        foreach ($blocks as $b) {
            $ifName = $b[1]; $body = $b[2];
            $ip = null; $prefix = null;
            if (preg_match('/^\s+ip address\s+(\S+)\s+(\S+)/m', $body, $m)) {
                $ip     = $m[1];
                $prefix = self::maskToPrefix($m[2]);
            }
            $desc = null;
            if (preg_match('/^\s+description\s+(.+)/m', $body, $dm)) $desc = trim($dm[1]);
            $ifaces[] = [
                'if_name'     => $ifName,
                'nameif'      => null,
                'description' => $desc,
                'ip_address'  => $ip,
                'prefix_len'  => $prefix,
                'is_active'   => preg_match('/^\s+shutdown\b/m', $body) ? 0 : 1,
                'is_dhcp'     => preg_match('/^\s+ip address dhcp\b/m', $body) ? 1 : 0,
                'parent_if'   => null,
            ];
        }
        return $ifaces;
    }

    public static function parseRoutes(string $config): array {
        $routes = [];
        foreach (explode("\n", $config) as $line) {
            // ip route <dst> <mask> <gateway|iface> [metric]
            if (!preg_match('/^ip route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?/', rtrim($line), $m)) continue;
            // Skip if gateway is an interface name (not an IP)
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
        if ($long === false) return 32;
        return strlen(rtrim(sprintf('%032b', $long & 0xFFFFFFFF), '0'));
    }

    public static function parseFirewallRules(string $config): array {
        $rules = [];
        $idx   = 0;
        $acl   = null;
        foreach (explode("\n", $config) as $line) {
            $line = rtrim($line);
            if (preg_match('/^ip access-list (?:extended|standard) (.+)/', $line, $m)) {
                $acl = $m[1]; continue;
            }
            $entry = null;
            if (preg_match('/^\s*(permit|deny)\s+(.+)/', $line, $m)) {
                $entry = self::aclEntry($m[1], $m[2], $acl ?? 'unnamed', ++$idx);
            } elseif (preg_match('/^access-list (\d+) (permit|deny)\s+(.+)/', $line, $m)) {
                $entry = self::aclEntry($m[2], $m[3], 'acl-'.$m[1], ++$idx);
            }
            if ($entry) { $entry['raw_rule'] = trim($line); $rules[] = $entry; }
            if ($acl && $line !== '' && $line[0] !== ' ' && !preg_match('/^ip access-list/', $line)) $acl = null;
        }
        return $rules;
    }

    private static function aclEntry(string $action, string $body, string $chain, int $idx): array {
        $t = preg_split('/\s+/', trim($body)); $i = 0;
        $proto = in_array(strtolower($t[0]??''), ['tcp','udp','icmp','ip','ospf','eigrp']) ? $t[$i++] : null;
        [$src,$i] = self::addr($t,$i); [$sprt,$i] = self::port($t,$i);
        [$dst,$i] = self::addr($t,$i); [$dprt,$i] = self::port($t,$i);
        $r = ['rule_index'=>$idx,'chain'=>$chain,'action'=>$action,'protocol'=>$proto,
              'src_address'=>$src,'dst_address'=>$dst,'src_port'=>$sprt,'dst_port'=>$dprt,
              'interface_in'=>null,'interface_out'=>null,'comment'=>null,'enabled'=>1,'raw_rule'=>''];
        $r['rule_hash'] = md5($chain.$action.$proto.$src.$dst.$sprt.$dprt);
        return $r;
    }

    private static function addr(array $t, int $i): array {
        if (!isset($t[$i])) return [null,$i];
        if ($t[$i]==='any') return ['any',$i+1];
        if ($t[$i]==='host' && isset($t[$i+1])) return [$t[$i+1],$i+2];
        if (isset($t[$i+1]) && preg_match('/^\d+\.\d+\.\d+\.\d+$/',$t[$i+1])) return [$t[$i].'/'.$t[$i+1],$i+2];
        return [$t[$i],$i+1];
    }

    private static function port(array $t, int $i): array {
        if (!isset($t[$i])) return [null,$i];
        $kw = strtolower($t[$i]);
        if ($kw==='eq'    && isset($t[$i+1]))   return [$t[$i+1],$i+2];
        if ($kw==='range' && isset($t[$i+2]))   return [$t[$i+1].'-'.$t[$i+2],$i+3];
        if ($kw==='gt'    && isset($t[$i+1]))   return ['>'.$t[$i+1],$i+2];
        if ($kw==='lt'    && isset($t[$i+1]))   return ['<'.$t[$i+1],$i+2];
        return [null,$i];
    }
}
