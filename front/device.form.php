<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    PluginFirewallDevice::processForm($_POST);
    exit;
}

$id = (int)($_GET['id'] ?? 0);
Html::header('Net Backup - ' . ($id > 0 ? 'Editar' : 'Nuevo') . ' Dispositivo', $_SERVER['PHP_SELF'], 'plugins', 'firewall');

if (!empty($_GET['saved'])) {
    echo '<div class="alert alert-success alert-dismissible fade show mx-3 mt-3" role="alert">
        <i class="ti ti-check me-2"></i>Dispositivo guardado correctamente.
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
}

PluginFirewallDevice::renderForm($id);
Html::footer();
