<?php
/**
 * Config diff engine — line-by-line unified diff with HTML rendering
 */
class PluginFirewallDiff {

    /**
     * Compute unified diff between two strings.
     * Returns array of chunks: ['type' => 'equal'|'insert'|'delete', 'lines' => [...]]
     */
    public static function compute(string $a, string $b): array {
        $aLines = explode("\n", str_replace("\r", '', $a));
        $bLines = explode("\n", str_replace("\r", '', $b));
        return self::myersDiff($aLines, $bLines);
    }

    /**
     * Render diff as an HTML side-by-side table
     */
    public static function renderHtml(array $chunks, string $titleA = 'Anterior', string $titleB = 'Nuevo'): string {
        $leftLines  = [];
        $rightLines = [];

        foreach ($chunks as $chunk) {
            foreach ($chunk['lines'] as $line) {
                switch ($chunk['type']) {
                    case 'equal':
                        $leftLines[]  = ['type' => 'eq',  'text' => $line];
                        $rightLines[] = ['type' => 'eq',  'text' => $line];
                        break;
                    case 'delete':
                        $leftLines[]  = ['type' => 'del', 'text' => $line];
                        $rightLines[] = ['type' => 'empty', 'text' => ''];
                        break;
                    case 'insert':
                        $leftLines[]  = ['type' => 'empty', 'text' => ''];
                        $rightLines[] = ['type' => 'ins', 'text' => $line];
                        break;
                }
            }
        }

        $nLines = max(count($leftLines), count($rightLines));
        $changed = 0;
        foreach ($chunks as $c) {
            if ($c['type'] !== 'equal') $changed += count($c['lines']);
        }

        $html  = '<div class="diff-stats mb-2 text-muted small">';
        $html .= "<span class='me-3'><i class='ti ti-minus text-danger'></i> " . array_sum(array_map(fn($c) => $c['type'] === 'delete' ? count($c['lines']) : 0, $chunks)) . " eliminadas</span>";
        $html .= "<span><i class='ti ti-plus text-success'></i> " . array_sum(array_map(fn($c) => $c['type'] === 'insert' ? count($c['lines']) : 0, $chunks)) . " agregadas</span>";
        $html .= '</div>';

        $html .= '<div class="diff-container" style="overflow:auto;max-height:calc(100vh - 220px)">';
        $html .= '<table class="table table-sm table-bordered mb-0 diff-table" style="font-family:monospace;font-size:12px;white-space:pre">';
        $html .= '<thead><tr>';
        $html .= "<th class='text-center' style='width:40px'>#</th>";
        $html .= "<th class='bg-light'><i class='ti ti-code me-1'></i>" . htmlspecialchars($titleA) . "</th>";
        $html .= "<th class='text-center' style='width:40px'>#</th>";
        $html .= "<th class='bg-light'><i class='ti ti-code me-1'></i>" . htmlspecialchars($titleB) . "</th>";
        $html .= '</tr></thead><tbody>';

        $ln = 1;
        $rn = 1;
        for ($i = 0; $i < $nLines; $i++) {
            $l = $leftLines[$i]  ?? ['type' => 'empty', 'text' => ''];
            $r = $rightLines[$i] ?? ['type' => 'empty', 'text' => ''];

            $lBg = match($l['type']) { 'del' => 'bg-danger bg-opacity-10', 'empty' => 'bg-light', default => '' };
            $rBg = match($r['type']) { 'ins' => 'bg-success bg-opacity-10', 'empty' => 'bg-light', default => '' };
            $lNum = $l['type'] !== 'empty' ? $ln++ : '';
            $rNum = $r['type'] !== 'empty' ? $rn++ : '';

            $html .= "<tr>";
            $html .= "<td class='text-muted text-end pe-1 $lBg' style='width:40px;user-select:none'>$lNum</td>";
            $html .= "<td class='$lBg'><pre class='mb-0 p-0' style='white-space:pre-wrap;word-break:break-all'>" . htmlspecialchars($l['text']) . "</pre></td>";
            $html .= "<td class='text-muted text-end pe-1 $rBg' style='width:40px;user-select:none'>$rNum</td>";
            $html .= "<td class='$rBg'><pre class='mb-0 p-0' style='white-space:pre-wrap;word-break:break-all'>" . htmlspecialchars($r['text']) . "</pre></td>";
            $html .= "</tr>";
        }

        $html .= '</tbody></table></div>';
        return $html;
    }

    /**
     * Diff via system diff(1) — O(ND) time, sin DP table en memoria.
     * -U 99999 incluye todas las líneas de contexto (equivalente al comportamiento anterior).
     */
    private static function myersDiff(array $a, array $b): array {
        if ($a === $b) {
            return [['type' => 'equal', 'lines' => $a]];
        }

        $tmpA = tempnam(sys_get_temp_dir(), 'fwdiff');
        $tmpB = tempnam(sys_get_temp_dir(), 'fwdiff');
        file_put_contents($tmpA, implode("\n", $a));
        file_put_contents($tmpB, implode("\n", $b));

        $diffOut = [];
        exec('diff -u -U 99999 ' . escapeshellarg($tmpA) . ' ' . escapeshellarg($tmpB), $diffOut, $rc);
        @unlink($tmpA);
        @unlink($tmpB);

        if ($rc === 0) {
            return [['type' => 'equal', 'lines' => $a]];
        }

        $chunks = [];
        foreach ($diffOut as $line) {
            if ($line === '' || ($line[0] ?? '') === '\\') continue;
            if (str_starts_with($line, '--- ') || str_starts_with($line, '+++ ') || str_starts_with($line, '@@ ')) continue;

            $type    = match($line[0] ?? ' ') { '-' => 'delete', '+' => 'insert', default => 'equal' };
            $content = substr($line, 1);

            if (!empty($chunks) && end($chunks)['type'] === $type) {
                $chunks[count($chunks) - 1]['lines'][] = $content;
            } else {
                $chunks[] = ['type' => $type, 'lines' => [$content]];
            }
        }

        return $chunks ?: [['type' => 'equal', 'lines' => $a]];
    }

    public static function renderDevicePicker(): void {
        global $DB;

        $devices = iterator_to_array($DB->request([
            'FROM'  => 'glpi_plugin_firewall_devices',
            'WHERE' => ['is_active' => 1],
            'ORDER' => 'name ASC',
        ]));

        // Aggregate last backup info per device in PHP
        $lastBackup = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_backups', 'ORDER' => 'backup_date DESC']) as $row) {
            $did = $row['plugin_firewall_devices_id'];
            if (!isset($lastBackup[$did])) {
                $lastBackup[$did] = ['last_date' => $row['backup_date'], 'total_ok' => 0, 'total_err' => 0];
            }
            if ($row['status'] === 'success') $lastBackup[$did]['total_ok']++;
            else                              $lastBackup[$did]['total_err']++;
        }

        echo '<div class="card mb-3">';
        echo '<div class="card-header d-flex justify-content-between align-items-center gap-2">';
        echo '<h3 class="card-title mb-0"><i class="ti ti-git-compare me-2"></i>Comparar configuraciones</h3>';
        echo '<input type="search" id="devSearch" class="form-control form-control-sm" style="max-width:260px" placeholder="Filtrar dispositivos…">';
        echo '</div>';
        echo '<div class="card-body">';

        if (empty($devices)) {
            echo '<p class="text-muted">No hay dispositivos activos.</p>';
            echo '</div></div>';
            return;
        }

        echo '<div class="row g-3" id="devGrid">';
        foreach ($devices as $dev) {
            $lb       = $lastBackup[$dev['id']] ?? null;
            $lastDate = $lb ? date('d/m/Y H:i', strtotime($lb['last_date'])) : '—';
            $badge    = $lb
                ? ($lb['total_err'] > 0
                    ? '<span class="badge bg-warning text-dark ms-1">Errores</span>'
                    : '<span class="badge bg-success ms-1">OK</span>')
                : '<span class="badge bg-secondary ms-1">Sin backups</span>';
            $vendor   = PluginFirewallDriverRegistry::getLabel($dev['vendor'] ?? '');
            $count    = $lb ? ($lb['total_ok'] + $lb['total_err']) : 0;

            echo "<div class='col-sm-6 col-lg-4 dev-card-col' data-name='" . htmlspecialchars(strtolower($dev['name'] . ' ' . $dev['hostname']), ENT_QUOTES) . "'>";
            echo "<a href='diff.php?device_id={$dev['id']}' class='text-decoration-none'>";
            echo "<div class='card h-100 border-0 shadow-sm dev-card'>";
            echo "<div class='card-body'>";
            echo "<div class='d-flex justify-content-between align-items-start mb-1'>";
            echo "<h6 class='card-title mb-0 fw-bold'>" . htmlspecialchars($dev['name']) . "</h6>";
            echo $badge;
            echo "</div>";
            echo "<div class='text-muted small mb-2'>" . htmlspecialchars($vendor) . " · " . htmlspecialchars($dev['hostname']) . "</div>";
            echo "<div class='text-muted small'><i class='ti ti-database me-1'></i>$count backups · Último: $lastDate</div>";
            echo "</div></div></a></div>";
        }
        echo '</div>';
        echo '</div></div>';

        echo '<style>.dev-card:hover{border-color:#0d6efd!important;box-shadow:0 0 0 2px rgba(13,110,253,.15)!important;transition:.15s}</style>';
        echo '<script>
document.getElementById("devSearch").addEventListener("input", function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll(".dev-card-col").forEach(function(el) {
        el.style.display = el.dataset.name.includes(q) ? "" : "none";
    });
});
</script>';
    }

    public static function renderDeviceHistory(int $deviceId): void {
        global $DB;

        $device = null;
        foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_devices', 'WHERE' => ['id' => $deviceId]]) as $d) {
            $device = $d;
        }
        if (!$device) {
            echo '<div class="alert alert-danger">Dispositivo no encontrado.</div>';
            return;
        }

        $backups = iterator_to_array($DB->request([
            'FROM'  => 'glpi_plugin_firewall_backups',
            'WHERE' => ['plugin_firewall_devices_id' => $deviceId],
            'ORDER' => 'backup_date DESC',
            'LIMIT' => 100,
        ]));

        $vendor = PluginFirewallDriverRegistry::getLabel($device['vendor'] ?? '');

        echo '<div class="mb-3">';
        echo "<a href='diff.php' class='btn btn-sm btn-outline-secondary me-2'><i class='ti ti-arrow-left me-1'></i>Dispositivos</a>";
        echo '<span class="fw-bold">' . htmlspecialchars($device['name']) . '</span>';
        echo '<span class="text-muted small ms-2">' . htmlspecialchars($vendor) . ' · ' . htmlspecialchars($device['hostname']) . '</span>';
        echo '</div>';

        echo '<div class="card">';
        echo '<div class="card-header d-flex justify-content-between align-items-center">';
        echo '<h5 class="card-title mb-0"><i class="ti ti-history me-2"></i>Historial de configuraciones</h5>';
        echo '<button id="btnCmpSelected" class="btn btn-sm btn-primary d-none" onclick="compareSelected()"><i class="ti ti-git-compare me-1"></i>Comparar seleccionados</button>';
        echo '</div>';
        echo '<div class="card-body p-0">';
        echo '<table class="table table-hover mb-0">';
        echo '<thead><tr><th style="width:32px"></th><th>Fecha</th><th>Estado</th><th>Tamaño</th><th>Cambios vs anterior</th><th>Acciones</th></tr></thead>';
        echo '<tbody>';

        $prevSuccessId   = null;
        $prevSuccessHash = null;

        foreach ($backups as $i => $b) {
            $dateStr = date('d/m/Y H:i', strtotime($b['backup_date']));
            $size    = $b['size_bytes'] > 0 ? number_format($b['size_bytes'] / 1024, 1) . ' KB' : '—';
            $ok      = $b['status'] === 'success';

            $statusBadge = $ok
                ? '<span class="badge bg-success">OK</span>'
                : '<span class="badge bg-danger">Error</span>';

            // Change indicator vs previous successful backup
            $changeBadge = '—';
            if ($ok && $prevSuccessHash !== null) {
                if ($b['config_hash'] === $prevSuccessHash) {
                    $changeBadge = '<span class="badge bg-light text-muted border">Sin cambios</span>';
                } else {
                    $changeBadge = '<a href="diff.php?a=' . $prevSuccessId . '&b=' . $b['id'] . '" class="badge bg-warning text-dark text-decoration-none">Modificado <i class="ti ti-external-link ms-1"></i></a>';
                }
            } elseif ($ok && $prevSuccessHash === null) {
                $changeBadge = '<span class="badge bg-light text-muted border">Primer backup</span>';
            }

            if ($ok) {
                $prevSuccessId   = $b['id'];
                $prevSuccessHash = $b['config_hash'];
            }

            echo '<tr>';
            echo '<td class="text-center ps-3">';
            if ($ok) echo '<input type="checkbox" class="form-check-input backup-sel" value="' . $b['id'] . '" onchange="updateCmpBtn()">';
            echo '</td>';
            echo '<td>' . $dateStr . '</td>';
            echo '<td>' . $statusBadge;
            if ($b['error_message']) echo ' <small class="text-danger">' . htmlspecialchars(substr($b['error_message'], 0, 50)) . '</small>';
            echo '</td>';
            echo '<td class="text-muted small">' . $size . '</td>';
            echo '<td>' . $changeBadge . '</td>';
            echo '<td class="text-nowrap">';
            if ($ok) {
                echo "<a href='diff.php?backup_id={$b['id']}' class='btn btn-sm btn-outline-primary me-1' title='Ver configuración'><i class='ti ti-eye'></i></a>";
            }
            if (!empty($b['execution_log'])) {
                $logEsc = htmlspecialchars($b['execution_log'], ENT_QUOTES);
                echo "<button class='btn btn-sm btn-outline-secondary' title='Ver log' onclick='showLog(`{$logEsc}`)'><i class='ti ti-terminal'></i></button>";
            }
            echo '</td>';
            echo '</tr>';
        }

        if (empty($backups)) {
            echo '<tr><td colspan="6" class="text-center text-muted py-4">Sin backups para este dispositivo.</td></tr>';
        }

        echo '</tbody></table></div></div>';

        echo '<script>
function updateCmpBtn() {
    var checked = document.querySelectorAll(".backup-sel:checked");
    var btn = document.getElementById("btnCmpSelected");
    btn.classList.toggle("d-none", checked.length !== 2);
}
function compareSelected() {
    var ids = Array.from(document.querySelectorAll(".backup-sel:checked")).map(el => parseInt(el.value));
    if (ids.length !== 2) return;
    ids.sort((a,b) => a-b);
    window.location.href = "diff.php?a=" + ids[0] + "&b=" + ids[1];
}
</script>';
    }

    public static function renderPage(int $backupIdA, int $backupIdB): void {
        global $DB;

        $getBackup = function (int $id) use ($DB): ?array {
            foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_backups', 'WHERE' => ['id' => $id]]) as $r) {
                return $r;
            }
            return null;
        };

        // Single backup view
        if ($backupIdA > 0 && $backupIdB === 0) {
            $b = $getBackup($backupIdA);
            if (!$b) { echo '<div class="alert alert-danger">Backup no encontrado</div>'; return; }
            $devId = (int)$b['plugin_firewall_devices_id'];
            $devName = '';
            foreach ($DB->request(['FROM'=>'glpi_plugin_firewall_devices','WHERE'=>['id'=>$devId]]) as $d) { $devName = $d['name']; }
            echo '<div class="mb-3">';
            echo "<a href='diff.php' class='btn btn-sm btn-outline-secondary me-1'><i class='ti ti-arrow-left me-1'></i>Dispositivos</a>";
            echo "<a href='diff.php?device_id=$devId' class='btn btn-sm btn-outline-secondary me-2'><i class='ti ti-history me-1'></i>Historial</a>";
            echo '<span class="fw-bold">' . htmlspecialchars($devName) . '</span>';
            echo '</div>';
            echo '<div class="card">';
            echo '<div class="card-header d-flex justify-content-between align-items-center">';
            echo '<h5 class="card-title mb-0"><i class="ti ti-code me-2"></i>' . date('d/m/Y H:i', strtotime($b['backup_date'])) . '</h5>';
            echo '<span class="text-muted small">' . number_format(strlen($b['config_text'] ?? '')/1024, 1) . ' KB</span>';
            echo '</div>';
            echo '<div class="card-body p-0" style="height:calc(100vh - 210px);overflow:hidden">';
            echo '<pre style="margin:0;padding:1rem;height:100%;overflow-y:scroll;overflow-x:auto;font-size:12px;font-family:monospace;background:#1e1e1e;color:#d4d4d4;white-space:pre;tab-size:4">' . htmlspecialchars($b['config_text'] ?? '') . '</pre>';
            echo '</div></div>';
            return;
        }

        $bA = $getBackup($backupIdA);
        $bB = $getBackup($backupIdB);
        if (!$bA || !$bB) { echo '<div class="alert alert-danger">Backups no encontrados</div>'; return; }

        $devId = (int)$bA['plugin_firewall_devices_id'];
        $devName = '';
        foreach ($DB->request(['FROM'=>'glpi_plugin_firewall_devices','WHERE'=>['id'=>$devId]]) as $d) { $devName = $d['name']; }

        echo '<div class="mb-3">';
        echo "<a href='diff.php' class='btn btn-sm btn-outline-secondary me-1'><i class='ti ti-arrow-left me-1'></i>Dispositivos</a>";
        echo "<a href='diff.php?device_id=$devId' class='btn btn-sm btn-outline-secondary me-2'><i class='ti ti-history me-1'></i>Historial</a>";
        echo '<span class="fw-bold">' . htmlspecialchars($devName) . '</span>';
        echo '</div>';

        $chunks  = self::compute($bA['config_text'] ?? '', $bB['config_text'] ?? '');
        $titleA  = date('d/m/Y H:i', strtotime($bA['backup_date']));
        $titleB  = date('d/m/Y H:i', strtotime($bB['backup_date']));

        echo '<div class="card">';
        echo '<div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-git-compare me-2"></i>Diferencias — ' . htmlspecialchars($devName) . '</h5></div>';
        echo '<div class="card-body">';
        echo self::renderHtml($chunks, $titleA, $titleB);
        echo '</div></div>';
    }
}
