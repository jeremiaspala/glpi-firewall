<?php
PluginFirewallDriverRegistry::register('cisco_ftd', 'PluginFirewallDriverCiscoFtd', 'Cisco FTD (Firepower)', true, false);

class PluginFirewallDriverCiscoFtd {

    public static function getConfig(array $device, PluginFirewallConnector $conn): string {
        $pass = PluginFirewallConfig::decryptPassword($device['password_enc']);

        // FTD necesita entrar al CLI diagnóstico interactivo
        $output = $conn->sshInteractive(
            $device['hostname'], (int)$device['port'],
            $device['username'], $pass,
            [
                ['expect' => '>',   'send' => 'system support diagnostic-cli',  'timeout' => 10],
                ['expect' => '#',   'send' => 'terminal pager 0',               'timeout' => 10],
                ['expect' => '#',   'send' => 'show running-config',            'timeout' => 5],
                ['drain'  => 60],
                ['send'   => 'exit'],
                ['sleep'  => 1],
                ['send'   => 'exit'],
            ]
        );

        if (preg_match('/(ASA Version.*)/s', $output, $m)) return trim($m[1]);
        return trim($output);
    }

    public static function parseFirewallRules(string $config): array {
        return PluginFirewallDriverCiscoAsa::parseFirewallRules($config);
    }
}
