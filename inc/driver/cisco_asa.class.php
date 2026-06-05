<?php
PluginFirewallDriverRegistry::register('cisco_asa', 'PluginFirewallDriverCiscoAsa', 'Cisco ASA', true, false);

class PluginFirewallDriverCiscoAsa {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass   = PluginFirewallConfig::decryptPassword($device['password_enc']);
        $enable = PluginFirewallConfig::decryptPassword($device['enable_password_enc'] ?? '');

        if ($enable) {
            // Necesita enable: modo interactivo pero con timeouts cortos
            $output = $conn->sshInteractive(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                [
                    ['expect' => '>',        'send' => 'enable',           'timeout' => 10],
                    ['expect' => 'assword:', 'send' => $enable,            'timeout' => 10, 'sensitive' => true],
                    ['expect' => '#',        'send' => 'terminal pager 0','timeout' => 10],
                    ['expect' => '#',        'send' => 'show running-config', 'timeout' => 5],
                    ['drain'  => 60],   // drenar hasta 60s o silencio de 3s
                    ['send'   => 'exit'],
                ]
            );
        } else {
            // Sin enable: comandos directos en una sola sesión SSH
            $output = $conn->sshCommand(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                'terminal pager 0 ; show running-config'
            );
        }

        if (preg_match('/((?:ASA Version|: Saved).*)/s', $output, $m)) {
            return trim($m[1]);
        }
        return trim($output);
    }

    public static function parseInterfaces(string $config): array {
        $config = str_replace("\r\n", "\n", $config);
        $ifaces = [];

        // Match each interface block: from "interface X" to next "!"
        preg_match_all('/^interface (\S+)(.*?)^!/ms', $config, $blocks, PREG_SET_ORDER);

        foreach ($blocks as $b) {
            $ifName = $b[1];
            $body   = $b[2];

            $nameif = null;
            if (preg_match('/^\s+nameif\s+(\S+)/m', $body, $m)) $nameif = $m[1];

            $desc = null;
            if (preg_match('/^\s+description\s+(.+)/m', $body, $m)) $desc = trim($m[1]);

            $ip = null; $prefix = null;
            if (preg_match('/^\s+ip address\s+(\S+)\s+(\S+)/m', $body, $m)) {
                $ip     = $m[1];
                $prefix = self::maskToPrefix($m[2]);
            }

            // Skip shutdown or sub-interfaces without IPs (VLANs/tunnels without address)
            $shutdown = (bool)preg_match('/^\s+shutdown\b/m', $body);

            $ifaces[] = [
                'if_name'     => $ifName,
                'nameif'      => $nameif,
                'description' => $desc,
                'ip_address'  => $ip,
                'prefix_len'  => $prefix,
                'is_active'   => $shutdown ? 0 : 1,
            ];
        }

        return $ifaces;
    }

    public static function parseRoutes(string $config): array {
        $config = str_replace("\r\n", "\n", $config);
        $routes = [];
        foreach (explode("\n", $config) as $line) {
            // route <iface> <dst-net> <dst-mask> <gateway> [metric]
            if (!preg_match('/^route\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?/', rtrim($line), $m)) continue;
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
        foreach (explode("\n", $config) as $line) {
            $line = rtrim($line);
            if (!preg_match('/^access-list (\S+) extended (permit|deny)\s+(.+)/', $line, $m)) continue;
            $rule = self::parseEntry($m[2], $m[3], $m[1], ++$idx);
            $rule['raw_rule'] = trim($line);
            $rules[] = $rule;
        }
        return $rules;
    }

    private static function parseEntry(string $action, string $body, string $chain, int $idx): array {
        $t = preg_split('/\s+/', trim($body));
        $i = 0;

        // Protocol can be a service object-group
        if (isset($t[$i]) && $t[$i] === 'object-group' && isset($t[$i+1])) {
            $proto = 'grp:' . $t[$i+1];
            $i += 2;
        } else {
            $proto = $t[$i++] ?? null;
        }

        [$src,  $i] = self::addr($t, $i);
        [$sprt, $i] = self::port($t, $i);
        [$dst,  $i] = self::addr($t, $i);
        [$dprt, $i] = self::port($t, $i);

        // Service object-group as dst port (appears after dst addr)
        if ($dprt === null && isset($t[$i]) && $t[$i] === 'object-group' && isset($t[$i+1])) {
            $dprt = 'grp:' . $t[$i+1];
        }

        $r = ['rule_index'=>$idx,'chain'=>$chain,'action'=>$action,'protocol'=>$proto,
              'src_address'=>$src,'dst_address'=>$dst,'src_port'=>$sprt,'dst_port'=>$dprt,
              'interface_in'=>null,'interface_out'=>null,'comment'=>null,'enabled'=>1,'raw_rule'=>''];
        $r['rule_hash'] = md5($chain.$action.$proto.$src.$dst.$sprt.$dprt);
        return $r;
    }

    private static function addr(array $t, int $i): array {
        if (!isset($t[$i])) return [null,$i];
        if (in_array($t[$i],['any','any4','any6']))          return ['any',$i+1];
        if ($t[$i]==='host' && isset($t[$i+1]))             return [$t[$i+1],$i+2];
        if (strpos($t[$i],'/')!==false)                     return [$t[$i],$i+1];
        if ($t[$i]==='object-group' && isset($t[$i+1]))     return ['grp:'.$t[$i+1],$i+2];
        if ($t[$i]==='object' && isset($t[$i+1]))           return ['obj:'.$t[$i+1],$i+2];
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
