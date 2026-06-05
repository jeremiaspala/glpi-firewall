<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

$jobId = trim($_GET['job_id'] ?? '');

// --- Estado de un job específico ---
if ($jobId) {
    global $DB;

    // Log en vivo mientras el proceso CLI está corriendo
    $liveLogFile = sys_get_temp_dir() . '/fw_backup_' . preg_replace('/[^a-f0-9\-]/', '', $jobId) . '.log';
    $liveContent = '';
    if (file_exists($liveLogFile)) {
        $liveContent = file_get_contents($liveLogFile);
    }

    // Buscar en DB si ya terminó
    $rows = $DB->request([
        'FROM'  => 'glpi_plugin_firewall_backups',
        'WHERE' => ['job_id' => $jobId],
        'LIMIT' => 1,
    ]);
    foreach ($rows as $r) {
        return new \Symfony\Component\HttpFoundation\JsonResponse([
            'found'   => true,
            'status'  => $r['status'],
            'message' => $r['status'] === 'success'
                ? ($r['size_bytes'] > 0 ? 'Backup completado' : 'Sin cambios')
                : ($r['error_message'] ?? 'Error desconocido'),
            'log' => $r['execution_log'] ?? '',
        ]);
    }

    // No terminó aún — devolver log en vivo
    return new \Symfony\Component\HttpFoundation\JsonResponse([
        'found'   => false,
        'status'  => 'running',
        'live_log' => $liveContent,
    ]);
}

// --- Estado general: dispositivos con backup en curso ---
global $DB;
$running = [];
foreach ($DB->request([
    'FROM'  => 'glpi_plugin_firewall_devices',
    'WHERE' => ['last_backup_status' => 'running'],
]) as $r) {
    $running[] = (int)$r['id'];
}
return new \Symfony\Component\HttpFoundation\JsonResponse(['running' => $running]);
