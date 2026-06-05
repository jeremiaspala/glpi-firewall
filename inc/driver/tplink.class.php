<?php
PluginFirewallDriverRegistry::register('tplink', 'PluginFirewallDriverTplink', 'TP-Link Managed', false, true);

class PluginFirewallDriverTplink {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass  = PluginFirewallConfig::decryptPassword($device['password_enc']);
        $proto = strtolower($device['protocol']);

        if ($proto === 'ssh') {
            $output = $conn->sshCommand(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                'terminal length 0 ; show running-config'
            );
        } else {
            $output = $conn->telnet(
                $device['hostname'], (int)$device['port'],
                $device['username'], $pass,
                [
                    ['expect' => 'User Name:', 'send' => $device['username'], 'timeout' => 10, 'sensitive' => true],
                    ['expect' => 'Password:',  'send' => $pass,               'timeout' => 10, 'sensitive' => true],
                    ['expect' => '#',          'send' => 'terminal length 0', 'timeout' => 10],
                    ['expect' => '#',          'send' => 'show running-config','timeout' => 5],
                    ['drain'  => 30],
                    ['send'   => 'exit'],
                ]
            );
        }
        return trim($output);
    }

    public static function parseFirewallRules(string $config): array {
        return PluginFirewallDriverCiscoIos::parseFirewallRules($config);
    }
}
