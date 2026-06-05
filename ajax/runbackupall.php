<?php
/**
 * Run backup for all active devices — used by cron / manual trigger
 */
include('../../../inc/includes.php');
Session::checkLoginUser();

header('Content-Type: application/json');

global $DB;
$devices = $DB->request([
    'FROM'  => 'glpi_plugin_firewall_devices',
    'WHERE' => ['is_active' => 1],
]);

$results = [];
foreach ($devices as $dev) {
    $r = PluginFirewallBackup::run((int)$dev['id'], 'manual');
    $results[] = ['device' => $dev['name'], 'result' => $r];
}

echo json_encode(['success' => true, 'results' => $results]);
