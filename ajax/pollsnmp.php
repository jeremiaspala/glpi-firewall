<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

header('Content-Type: application/json');

$deviceId = (int)($_POST['device_id'] ?? 0);
if ($deviceId <= 0) {
    echo json_encode(['success' => false, 'error' => 'device_id inválido']);
    exit;
}

$result = PluginFirewallNetworkMap::pollDevice($deviceId);
echo json_encode($result);
