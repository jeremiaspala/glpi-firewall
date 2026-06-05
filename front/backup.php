<?php
include('../../../inc/includes.php');
Session::checkLoginUser();
Html::header('Net Backup - Backups', $_SERVER['PHP_SELF'], 'plugins', 'firewall');
$deviceId = (int)($_GET['device_id'] ?? 0);
PluginFirewallBackup::renderList($deviceId);
Html::footer();
