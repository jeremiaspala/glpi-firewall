<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

// CSRF validated automatically by GLPI 11 middleware

Html::header('Net Backup - Auditoría de Firewall', $_SERVER['PHP_SELF'], 'plugins', 'firewall');
PluginFirewallAudit::renderPage();
Html::footer();
