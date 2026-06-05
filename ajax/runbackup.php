<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

$deviceId = (int)($_POST['device_id'] ?? 0);
if ($deviceId <= 0) {
    return new \Symfony\Component\HttpFoundation\JsonResponse(
        ['success' => false, 'error' => 'device_id inválido']
    );
}

// Generar job_id
$jobId = sprintf('%04x%04x-%04x-%04x-%04x-%012x',
    mt_rand(0,0xffff), mt_rand(0,0xffff), mt_rand(0,0xffff),
    mt_rand(0,0x0fff)|0x4000, mt_rand(0,0x3fff)|0x8000,
    mt_rand(0,0xffffffffffff)
);

// Marcar dispositivo como "running"
global $DB;
$DB->update('glpi_plugin_firewall_devices', [
    'last_backup_status' => 'running',
    'date_mod'           => date('Y-m-d H:i:s'),
], ['id' => $deviceId]);

// Lanzar proceso PHP independiente (desvinculado de Apache)
$cliScript = __DIR__ . '/../cli/run_backup.php';
$cmd = sprintf(
    'nohup php %s %d %s > /dev/null 2>&1 &',
    escapeshellarg($cliScript),
    $deviceId,
    escapeshellarg($jobId)
);
exec($cmd);

return new \Symfony\Component\HttpFoundation\JsonResponse([
    'started' => true,
    'job_id'  => $jobId,
]);
