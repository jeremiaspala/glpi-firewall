<?php
include('../../../inc/includes.php');
Session::checkLoginUser();
Html::header('Net Backup - Configuraciones', $_SERVER['PHP_SELF'], 'plugins', 'firewall');

$backupA  = (int)($_GET['a']         ?? $_GET['backup_id'] ?? 0);
$backupB  = (int)($_GET['b']         ?? 0);
$deviceId = (int)($_GET['device_id'] ?? 0);

if ($backupA > 0) {
    PluginFirewallDiff::renderPage($backupA, $backupB);
} elseif ($deviceId > 0) {
    PluginFirewallDiff::renderDeviceHistory($deviceId);
} else {
    PluginFirewallDiff::renderDevicePicker();
}

Html::footer();
