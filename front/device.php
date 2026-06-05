<?php
include('../../../inc/includes.php');
Session::checkLoginUser();
Html::header('Net Backup - Dispositivos', $_SERVER['PHP_SELF'], 'plugins', 'firewall');
PluginFirewallDevice::renderList();
Html::footer();
