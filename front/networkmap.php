<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

// CSRF validated automatically by GLPI 11 middleware

Html::header('Net Backup - Mapa de Red', $_SERVER['PHP_SELF'], 'plugins', 'firewall');
PluginFirewallNetworkMap::renderPage();
Html::footer();
