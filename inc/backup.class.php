<?php
/**
 * Backup execution and management
 */
class PluginFirewallBackup extends CommonDBTM {

    static $rightname = 'plugin_firewall';

    public static function getTypeName($nb = 0) {
        return 'Net Backup';
    }

    /**
     * GLPI cron handler — se llama cada hora.
     * Para cada dispositivo activo revisa si le toca backup según su schedule.
     */
    public static function cronAutoBackup(CronTask $task): int {
        global $DB;

        $devices = $DB->request([
            'FROM'  => 'glpi_plugin_firewall_devices',
            'WHERE' => ['is_active' => 1, ['backup_schedule', '!=', 'manual']],
        ]);

        $count = 0;
        foreach ($devices as $device) {
            if (!self::isDue($device)) {
                continue;
            }

            $result = self::run((int)$device['id'], 'scheduled');
            $task->addVolume(1);
            $count++;

            $status = $result['success'] ? 'OK' : 'ERROR: ' . ($result['error'] ?? '');
            $task->log("{$device['name']} ({$device['hostname']}): $status");
        }

        return $count > 0 ? 1 : 0;
    }

    /**
     * Determina si un equipo necesita backup ahora según su schedule y último backup.
     */
    private static function isDue(array $device): bool {
        $schedule = $device['backup_schedule'] ?? 'manual';
        if ($schedule === 'manual') return false;

        $intervalSeconds = match ($schedule) {
            'daily'  => 86400,
            'weekly' => 604800,
            default  => 0,
        };
        if ($intervalSeconds === 0) return false;

        $lastBackup = $device['last_backup_date'];
        if (!$lastBackup) return true; // nunca hecho

        return (time() - strtotime($lastBackup)) >= $intervalSeconds;
    }

    /**
     * Run a backup for a device. Returns ['success'=>bool, 'message'=>string, 'backup_id'=>int]
     */
    public static function run(int $deviceId, string $trigger = 'manual', string $jobId = ''): array {
        global $DB;

        $rows = $DB->request(['FROM' => 'glpi_plugin_firewall_devices', 'WHERE' => ['id' => $deviceId]]);
        $device = null;
        foreach ($rows as $row) { $device = $row; break; }

        if (!$device) {
            return ['success' => false, 'error' => "Dispositivo $deviceId no encontrado"];
        }

        // Archivo de log en vivo — el polling lo lee mientras ejecuta
        $liveLogFile = $jobId ? sys_get_temp_dir() . '/fw_backup_' . $jobId . '.log' : '';
        if ($liveLogFile) {
            file_put_contents($liveLogFile, '');
        }

        $conn = new PluginFirewallConnector($liveLogFile);

        try {
            $config = self::fetchConfig($device, $conn);
            $execLog = $conn->getStepsLog();

            if (empty(trim($config))) {
                throw new \RuntimeException("Respuesta vacía del dispositivo");
            }

            $hash = hash('sha256', $config);

            $unchanged = false;
            foreach ($DB->request([
                'FROM'  => 'glpi_plugin_firewall_backups',
                'WHERE' => ['plugin_firewall_devices_id' => $deviceId, 'status' => 'success'],
                'ORDER' => 'backup_date DESC',
                'LIMIT' => 1,
            ]) as $lr) {
                if ($lr['config_hash'] === $hash) $unchanged = true;
            }

            $backupId = $DB->insert('glpi_plugin_firewall_backups', [
                'job_id'                     => $jobId ?: null,
                'plugin_firewall_devices_id' => $deviceId,
                'config_text'   => self::sanitizeForDb($config),
                'config_hash'   => $hash,
                'backup_date'   => date('Y-m-d H:i:s'),
                'trigger_type'  => $trigger,
                'status'        => 'success',
                'size_bytes'    => strlen($config),
                'execution_log' => self::sanitizeForDb($execLog),
                'date_creation' => date('Y-m-d H:i:s'),
            ]);

            $DB->update('glpi_plugin_firewall_devices', [
                'last_backup_date'   => date('Y-m-d H:i:s'),
                'last_backup_status' => 'success',
                'date_mod'           => date('Y-m-d H:i:s'),
            ], ['id' => $deviceId]);

            if (PluginFirewallDriverRegistry::isFirewall($device['vendor'])) {
                self::parseAndStoreRules($device, (int)$backupId, $config);
            }
            self::parseAndStoreInterfaces($device, (int)$backupId, $config);
            self::parseAndStoreRoutes($device, (int)$backupId, $config);

            self::purgeOld($deviceId);
            if ($liveLogFile && file_exists($liveLogFile)) unlink($liveLogFile);

            $msg = $unchanged ? 'Sin cambios desde el último backup' : 'Backup completado — configuración modificada';
            return ['success' => true, 'message' => $msg, 'backup_id' => (int)$backupId, 'unchanged' => $unchanged, 'log' => $execLog];

        } catch (\Throwable $e) {
            $errMsg  = $e->getMessage();
            $execLog = $conn->getStepsLog() . "\n[ERROR] " . $errMsg;

            $DB->insert('glpi_plugin_firewall_backups', [
                'job_id'                     => $jobId ?: null,
                'plugin_firewall_devices_id' => $deviceId,
                'backup_date'    => date('Y-m-d H:i:s'),
                'trigger_type'   => $trigger,
                'status'         => 'error',
                'error_message'  => self::sanitizeForDb($errMsg),
                'execution_log'  => self::sanitizeForDb($execLog),
                'date_creation'  => date('Y-m-d H:i:s'),
            ]);

            $DB->update('glpi_plugin_firewall_devices', [
                'last_backup_date'   => date('Y-m-d H:i:s'),
                'last_backup_status' => 'error',
                'date_mod'           => date('Y-m-d H:i:s'),
            ], ['id' => $deviceId]);

            if ($liveLogFile && file_exists($liveLogFile)) unlink($liveLogFile);
            return ['success' => false, 'error' => $errMsg, 'log' => $execLog];
        }
    }

    private static function fetchConfig(array $device, PluginFirewallConnector $conn): string {
        return PluginFirewallDriverRegistry::fetchConfig($device, $conn);
    }

    private static function sanitizeForDb(string $text): string {
        // Eliminar bytes inválidos UTF-8 y caracteres nulos que rompen MySQL
        $clean = mb_convert_encoding($text, 'UTF-8', 'UTF-8');
        return str_replace("\0", '', $clean);
    }

    private static function parseAndStoreRules(array $device, int $backupId, string $config): void {
        global $DB;

        $rules = PluginFirewallDriverRegistry::parseRules($device['vendor'], $config);

        // Remove old rules for this device (keep latest)
        $DB->delete('glpi_plugin_firewall_rules', ['plugin_firewall_devices_id' => $device['id']]);

        $now = date('Y-m-d H:i:s');
        foreach ($rules as $rule) {
            $DB->insert('glpi_plugin_firewall_rules', array_merge($rule, [
                'plugin_firewall_backups_id' => $backupId,
                'plugin_firewall_devices_id' => $device['id'],
                'date_creation'              => $now,
            ]));
        }
    }

    private static function parseAndStoreInterfaces(array $device, int $backupId, string $config): void {
        global $DB;
        $ifaces = PluginFirewallDriverRegistry::parseInterfaces($device['vendor'], $config);
        if (empty($ifaces)) return;
        $DB->delete('glpi_plugin_firewall_interfaces', ['plugin_firewall_devices_id' => $device['id']]);
        $now = date('Y-m-d H:i:s');
        foreach ($ifaces as $iface) {
            $DB->insert('glpi_plugin_firewall_interfaces', array_merge($iface, [
                'plugin_firewall_backups_id' => $backupId,
                'plugin_firewall_devices_id' => $device['id'],
                'date_creation'              => $now,
            ]));
        }
    }

    private static function parseAndStoreRoutes(array $device, int $backupId, string $config): void {
        global $DB;
        $routes = PluginFirewallDriverRegistry::parseRoutes($device['vendor'], $config);
        if (empty($routes)) return;
        $DB->delete('glpi_plugin_firewall_routes', ['plugin_firewall_devices_id' => $device['id']]);
        $now = date('Y-m-d H:i:s');
        foreach ($routes as $route) {
            $DB->insert('glpi_plugin_firewall_routes', array_merge($route, [
                'plugin_firewall_backups_id' => $backupId,
                'plugin_firewall_devices_id' => $device['id'],
                'date_creation'              => $now,
            ]));
        }
    }

    private static function purgeOld(int $deviceId): void {
        global $DB;
        $days = (int) PluginFirewallConfig::get('backup_keep_days', 90);
        $cutoff = date('Y-m-d H:i:s', strtotime("-$days days"));
        $DB->delete('glpi_plugin_firewall_backups', [
            'plugin_firewall_devices_id' => $deviceId,
            ['backup_date', '<', $cutoff],
        ]);
    }

    public static function renderList(int $deviceId = 0): void {
        global $DB;

        $where = [];
        if ($deviceId > 0) {
            $where['plugin_firewall_devices_id'] = $deviceId;
        }

        $backups = $DB->request([
            'FROM'  => 'glpi_plugin_firewall_backups',
            'WHERE' => $where,
            'ORDER' => 'backup_date DESC',
            'LIMIT' => 200,
        ]);

        // Build device name map
        $devNames = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_devices']) as $d) {
            $devNames[$d['id']] = $d['name'];
        }

        // Current device filter selector
        echo '<div class="card mb-3">';
        echo '<div class="card-header d-flex justify-content-between align-items-center">';
        echo '<h3 class="card-title mb-0"><i class="ti ti-database me-2"></i>Backups</h3>';

        echo '<form class="d-flex gap-2 align-items-center">';
        echo '<select name="device_id" class="form-select form-select-sm" onchange="this.form.submit()">';
        echo '<option value="0">Todos los dispositivos</option>';
        foreach ($devNames as $did => $dname) {
            $sel = $did == $deviceId ? 'selected' : '';
            echo "<option value='$did' $sel>" . htmlspecialchars($dname) . "</option>";
        }
        echo '</select></form>';
        echo '</div>';
        echo '<div class="card-body p-0">';

        echo '<table class="table table-hover mb-0">';
        echo '<thead><tr><th>Dispositivo</th><th>Fecha</th><th>Estado</th>';
        echo '<th>Tamaño</th><th>Cambios</th><th>Acciones</th></tr></thead>';
        echo '<tbody>';

        $prevHash = [];
        $list     = iterator_to_array($backups);

        // Build hash sequence per device for change detection
        $deviceSeq = [];
        foreach (array_reverse($list) as $b) {
            $deviceSeq[$b['plugin_firewall_devices_id']][] = $b['config_hash'];
        }

        foreach ($list as $i => $b) {
            $devName    = $devNames[$b['plugin_firewall_devices_id']] ?? "Device {$b['plugin_firewall_devices_id']}";
            $dateStr    = date('d/m/Y H:i', strtotime($b['backup_date']));
            $statusBadge = $b['status'] === 'success'
                ? '<span class="badge bg-success">OK</span>'
                : '<span class="badge bg-danger">Error</span>';
            $size = $b['size_bytes'] > 0 ? number_format($b['size_bytes'] / 1024, 1) . ' KB' : '-';

            // Detect change vs previous backup of same device
            $changed = '-';
            $prevId  = null;
            foreach (array_slice($list, $i + 1) as $prev) {
                if ($prev['plugin_firewall_devices_id'] === $b['plugin_firewall_devices_id'] && $prev['status'] === 'success') {
                    $prevId = $prev['id'];
                    if ($prev['config_hash'] !== $b['config_hash']) {
                        $changed = '<span class="badge bg-warning text-dark">Cambios</span>';
                    } else {
                        $changed = '<span class="badge bg-light text-muted">Sin cambios</span>';
                    }
                    break;
                }
            }

            echo "<tr>";
            echo "<td>" . htmlspecialchars($devName) . "</td>";
            echo "<td>$dateStr</td>";
            echo "<td>$statusBadge";
            if ($b['error_message']) echo " <small class='text-danger'>" . htmlspecialchars(substr($b['error_message'], 0, 50)) . "</small>";
            echo "</td>";
            echo "<td class='text-muted small'>$size</td>";
            echo "<td>$changed</td>";
            echo "<td>";
            if ($b['status'] === 'success') {
                echo "<a href='diff.php?backup_id={$b['id']}' class='btn btn-sm btn-outline-primary me-1' title='Ver config'><i class='ti ti-eye'></i></a>";
                if ($prevId) {
                    echo "<a href='diff.php?a={$prevId}&b={$b['id']}' class='btn btn-sm btn-outline-warning me-1' title='Ver diferencias'><i class='ti ti-git-compare'></i></a>";
                }
            }
            if (!empty($b['execution_log'])) {
                $logEsc = htmlspecialchars($b['execution_log'], ENT_QUOTES);
                echo "<button class='btn btn-sm btn-outline-secondary' title='Ver log' onclick='showLog(`{$logEsc}`)'><i class='ti ti-terminal'></i></button>";
            }
            echo "</td>";
            echo "</tr>";
        }

        if (count($list) === 0) {
            echo "<tr><td colspan='6' class='text-center text-muted py-4'>No hay backups registrados.</td></tr>";
        }

        echo '</tbody></table></div></div>';

        echo <<<HTML
        <div class="modal fade" id="logModal" tabindex="-1">
          <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title"><i class="ti ti-terminal me-2"></i>Log de ejecución SSH/Telnet</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
              </div>
              <div class="modal-body p-0">
                <pre id="logContent" style="font-size:12px;background:#1e1e1e;color:#d4d4d4;padding:1rem;margin:0;white-space:pre-wrap;word-break:break-all;min-height:200px"></pre>
              </div>
            </div>
          </div>
        </div>
        <script>
        function showLog(text) {
            document.getElementById('logContent').textContent = text;
            new bootstrap.Modal(document.getElementById('logModal')).show();
        }
        </script>
        HTML;
    }
}
