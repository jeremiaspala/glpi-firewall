<?php
PluginFirewallDriverRegistry::register('fortinet', 'PluginFirewallDriverFortinet', 'Fortinet FortiGate', true, true);

class PluginFirewallDriverFortinet {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass = PluginFirewallConfig::decryptPassword($device['password_enc']);

        // FortiOS acepta comandos directos por SSH
        $output = $conn->sshCommand(
            $device['hostname'], (int)$device['port'],
            $device['username'], $pass,
            'show full-configuration'
        );

        if (preg_match('/(#config-version=.*)/s', $output, $m)) {
            return trim($m[1]);
        }
        return trim($output);
    }

    public static function parseFirewallRules(string $config): array {
        $rules = [];
        $idx   = 0;
        if (!preg_match('/config firewall policy\n(.*?)^end$/ms', $config, $m)) return $rules;
        preg_match_all('/edit (\d+)\n(.*?)next/s', $m[1], $blocks, PREG_SET_ORDER);
        foreach ($blocks as $b) {
            $body = $b[2];
            $r = [
                'rule_index'    => ++$idx,
                'chain'         => 'policy-'.$b[1],
                'action'        => self::f($body,'action') ?? 'accept',
                'protocol'      => self::f($body,'service'),
                'src_address'   => self::f($body,'srcaddr'),
                'dst_address'   => self::f($body,'dstaddr'),
                'src_port'      => null, 'dst_port' => null,
                'interface_in'  => self::f($body,'srcintf'),
                'interface_out' => self::f($body,'dstintf'),
                'comment'       => self::f($body,'comments'),
                'enabled'       => self::f($body,'status') !== 'disable' ? 1 : 0,
                'raw_rule'      => "edit {$b[1]}\n".trim($body)."\nnext",
            ];
            $r['rule_hash'] = md5($r['chain'].$r['action'].$r['protocol'].$r['src_address'].$r['dst_address'].$r['interface_in'].$r['interface_out']);
            $rules[] = $r;
        }
        return $rules;
    }

    private static function f(string $body, string $field): ?string {
        if (preg_match('/set '.preg_quote($field,'/').' "([^"]+)"/', $body, $m)) return $m[1];
        if (preg_match('/set '.preg_quote($field,'/').' (\S+)/',     $body, $m)) return $m[1];
        return null;
    }
}
