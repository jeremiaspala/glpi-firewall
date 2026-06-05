<?php
/**
 * Firewall rule audit — compare rules across devices/vendors
 * Normalizes rules to a common format for cross-vendor comparison
 */
class PluginFirewallAudit extends CommonDBTM {

    static $rightname = 'plugin_firewall';

    public static function getTypeName($nb = 0) {
        return 'Firewall Audit';
    }

    /**
     * Compare rules from two (or more) devices.
     * Returns a structured comparison result.
     */
    public static function compareDevices(array $deviceIds): array {
        global $DB;

        $deviceRules = [];
        $deviceInfo  = [];

        foreach ($deviceIds as $devId) {
            $devId = (int)$devId;
            $rows  = $DB->request(['FROM' => 'glpi_plugin_firewall_devices', 'WHERE' => ['id' => $devId]]);
            foreach ($rows as $d) { $deviceInfo[$devId] = $d; break; }
            if (!isset($deviceInfo[$devId])) continue;

            $rules = $DB->request([
                'FROM'  => 'glpi_plugin_firewall_rules',
                'WHERE' => ['plugin_firewall_devices_id' => $devId],
                'ORDER' => 'rule_index ASC',
            ]);
            $deviceRules[$devId] = iterator_to_array($rules);
        }

        if (count($deviceRules) < 2) {
            return ['error' => 'Se necesitan al menos 2 dispositivos para comparar'];
        }

        // Build hash sets per device
        $hashSets = [];
        foreach ($deviceRules as $devId => $rules) {
            $hashSets[$devId] = [];
            foreach ($rules as $r) {
                if ($r['rule_hash']) {
                    $hashSets[$devId][$r['rule_hash']] = $r;
                }
            }
        }

        $allHashes = [];
        foreach ($hashSets as $set) {
            $allHashes = array_merge($allHashes, array_keys($set));
        }
        $allHashes = array_unique($allHashes);

        $result = [
            'devices'   => $deviceInfo,
            'identical' => [],
            'unique'    => [],  // hash => [device_id => rule]
            'summary'   => [],
        ];

        foreach ($allHashes as $hash) {
            $presentIn = [];
            foreach ($hashSets as $devId => $set) {
                if (isset($set[$hash])) {
                    $presentIn[$devId] = $set[$hash];
                }
            }

            if (count($presentIn) === count($deviceIds)) {
                $result['identical'][] = ['hash' => $hash, 'devices' => $presentIn];
            } else {
                $result['unique'][$hash] = $presentIn;
            }
        }

        // Summary per device
        foreach ($deviceIds as $devId) {
            $total   = count($deviceRules[$devId] ?? []);
            $inCommon = array_sum(array_map(
                fn($g) => isset($g['devices'][$devId]) ? 1 : 0,
                $result['identical']
            ));
            $onlyHere = array_sum(array_map(
                fn($g) => count($g) === 1 && isset($g[$devId]) ? 1 : 0,
                $result['unique']
            ));

            $result['summary'][$devId] = [
                'total'    => $total,
                'common'   => $inCommon,
                'unique'   => $onlyHere,
                'missing'  => $total - $inCommon - $onlyHere,
            ];
        }

        return $result;
    }

    public static function renderPage(): void {
        global $DB;

        // Get firewall devices only
        $fwDevices = [];
        foreach (PluginFirewallDriverRegistry::all() as $vendor => $info) {
            if ($info['is_firewall']) {
                $rows = $DB->request([
                    'FROM'  => 'glpi_plugin_firewall_devices',
                    'WHERE' => ['vendor' => $vendor, 'is_active' => 1],
                ]);
                foreach ($rows as $d) {
                    $fwDevices[$d['id']] = $d;
                }
            }
        }

        // Handle POST compare action
        $compareResult = null;
        $selectedIds   = [];
        if (!empty($_POST['device_ids'])) {
            $selectedIds   = array_map('intval', (array)$_POST['device_ids']);
            $compareResult = self::compareDevices($selectedIds);
        }

        echo '<div class="card mb-3">';
        echo '<div class="card-header"><h3 class="card-title mb-0"><i class="ti ti-shield-check me-2"></i>Auditoría de Reglas de Firewall</h3></div>';
        echo '<div class="card-body">';

        // Selection form
        echo '<form method="post">';
        echo '<input type="hidden" name="_glpi_csrf_token" value="' . Session::getNewCSRFToken() . '">';
        echo '<div class="mb-3"><label class="form-label fw-bold">Seleccionar firewalls a comparar (2 o más):</label>';
        echo '<div class="row row-cols-2 row-cols-md-3 g-2">';
        foreach ($fwDevices as $dev) {
            $checked = in_array($dev['id'], $selectedIds) ? 'checked' : '';
            $vendor  = PluginFirewallDriverRegistry::getLabel($dev['vendor']);
            echo "<div class='col'><div class='form-check'>";
            echo "<input class='form-check-input' type='checkbox' name='device_ids[]' value='{$dev['id']}' id='dev{$dev['id']}' $checked>";
            echo "<label class='form-check-label' for='dev{$dev['id']}'>";
            echo "<strong>" . htmlspecialchars($dev['name']) . "</strong><br>";
            echo "<small class='text-muted'>" . htmlspecialchars($dev['hostname']) . " · $vendor</small>";
            echo "</label></div></div>";
        }
        if (empty($fwDevices)) {
            echo "<div class='col-12 text-muted'>No hay firewalls configurados. Agregá dispositivos de tipo Firewall en la sección de Dispositivos.</div>";
        }
        echo '</div></div>';
        echo '<button type="submit" class="btn btn-primary"><i class="ti ti-search me-1"></i>Comparar reglas</button>';
        echo '</form>';

        echo '</div></div>';

        // Results
        if ($compareResult) {
            self::renderCompareResult($compareResult, $fwDevices);
        }
    }

    private static function renderCompareResult(array $result, array $allDevices): void {
        if (isset($result['error'])) {
            echo '<div class="alert alert-warning">' . htmlspecialchars($result['error']) . '</div>';
            return;
        }

        $devices = $result['devices'];
        $devIds  = array_keys($devices);

        // Summary cards
        echo '<div class="row g-3 mb-4">';
        foreach ($devices as $devId => $dev) {
            $s       = $result['summary'][$devId] ?? [];
            $vendor  = PluginFirewallDriverRegistry::getLabel($dev['vendor']);
            $pct     = $s['total'] > 0 ? round($s['common'] / $s['total'] * 100) : 0;
            echo '<div class="col-md-4"><div class="card border-0 shadow-sm">';
            echo '<div class="card-body">';
            echo '<h6 class="card-title">' . htmlspecialchars($dev['name']) . '</h6>';
            echo '<div class="text-muted small mb-2">' . htmlspecialchars($vendor) . ' · ' . htmlspecialchars($dev['hostname']) . '</div>';
            echo '<div class="row text-center">';
            echo '<div class="col"><div class="fw-bold fs-5">' . ($s['total'] ?? 0) . '</div><div class="text-muted small">Total</div></div>';
            echo '<div class="col"><div class="fw-bold fs-5 text-success">' . ($s['common'] ?? 0) . '</div><div class="text-muted small">Comunes</div></div>';
            echo '<div class="col"><div class="fw-bold fs-5 text-warning">' . ($s['unique'] ?? 0) . '</div><div class="text-muted small">Únicas</div></div>';
            echo '</div>';
            echo '<div class="progress mt-2" style="height:6px"><div class="progress-bar bg-success" style="width:' . $pct . '%"></div></div>';
            echo '</div></div></div>';
        }
        echo '</div>';

        // Identical rules
        $identicalCount = count($result['identical']);
        echo '<div class="card mb-3">';
        echo '<div class="card-header d-flex justify-content-between align-items-center">';
        echo '<h5 class="card-title mb-0 text-success"><i class="ti ti-circle-check me-2"></i>Reglas idénticas (' . $identicalCount . ')</h5>';
        echo '<button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse" data-bs-target="#identical-rules">Mostrar/ocultar</button>';
        echo '</div>';
        echo '<div class="collapse" id="identical-rules"><div class="card-body p-0">';
        echo '<table class="table table-sm mb-0"><thead><tr>';
        echo '<th>#</th><th>Cadena</th><th>Acción</th><th>Protocolo</th><th>Origen</th><th>Destino</th><th>Puertos dst</th>';
        foreach ($devices as $d) {
            echo '<th class="text-center small">' . htmlspecialchars($d['name']) . '</th>';
        }
        echo '</tr></thead><tbody>';
        foreach ($result['identical'] as $i => $group) {
            $sample = reset($group['devices']);
            echo '<tr>';
            echo '<td class="text-muted">' . ($i + 1) . '</td>';
            echo '<td><code class="small">' . htmlspecialchars($sample['chain'] ?? '') . '</code></td>';
            echo '<td>' . self::actionBadge($sample['action'] ?? '') . '</td>';
            echo '<td class="small">' . htmlspecialchars($sample['protocol'] ?? 'any') . '</td>';
            echo '<td class="small"><code>' . htmlspecialchars($sample['src_address'] ?? 'any') . '</code></td>';
            echo '<td class="small"><code>' . htmlspecialchars($sample['dst_address'] ?? 'any') . '</code></td>';
            echo '<td class="small"><code>' . htmlspecialchars($sample['dst_port'] ?? '') . '</code></td>';
            foreach ($devIds as $did) {
                echo '<td class="text-center">' . (isset($group['devices'][$did]) ? '<i class="ti ti-check text-success"></i>' : '') . '</td>';
            }
            echo '</tr>';
        }
        if ($identicalCount === 0) echo '<tr><td colspan="20" class="text-center text-muted">Sin reglas comunes</td></tr>';
        echo '</tbody></table></div></div></div>';

        // Unique / different rules
        $uniqueCount = count($result['unique']);
        echo '<div class="card mb-3">';
        echo '<div class="card-header"><h5 class="card-title mb-0 text-warning"><i class="ti ti-alert-triangle me-2"></i>Reglas distintas (' . $uniqueCount . ')</h5></div>';
        echo '<div class="card-body p-0">';
        echo '<table class="table table-sm mb-0"><thead><tr>';
        echo '<th>Presente en</th><th>Cadena</th><th>Acción</th><th>Protocolo</th><th>Origen</th><th>Destino</th><th>Puertos dst</th><th>Comentario</th>';
        echo '</tr></thead><tbody>';
        foreach ($result['unique'] as $hash => $presentIn) {
            $devNames = implode(', ', array_map(fn($did) => htmlspecialchars($devices[$did]['name'] ?? "Dev $did"), array_keys($presentIn)));
            $sample   = reset($presentIn);
            $rowClass = count($presentIn) === 1 ? 'table-warning' : '';
            echo "<tr class='$rowClass'>";
            echo '<td class="small">' . $devNames . '</td>';
            echo '<td><code class="small">' . htmlspecialchars($sample['chain'] ?? '') . '</code></td>';
            echo '<td>' . self::actionBadge($sample['action'] ?? '') . '</td>';
            echo '<td class="small">' . htmlspecialchars($sample['protocol'] ?? 'any') . '</td>';
            echo '<td class="small"><code>' . htmlspecialchars($sample['src_address'] ?? 'any') . '</code></td>';
            echo '<td class="small"><code>' . htmlspecialchars($sample['dst_address'] ?? 'any') . '</code></td>';
            echo '<td class="small"><code>' . htmlspecialchars($sample['dst_port'] ?? '') . '</code></td>';
            echo '<td class="small text-muted">' . htmlspecialchars($sample['comment'] ?? '') . '</td>';
            echo '</tr>';
        }
        if ($uniqueCount === 0) echo '<tr><td colspan="8" class="text-center text-muted">Sin reglas únicas</td></tr>';
        echo '</tbody></table></div></div>';
    }

    private static function actionBadge(string $action): string {
        $action = strtolower($action);
        $class  = match($action) {
            'accept', 'permit', 'allow' => 'bg-success',
            'drop', 'deny', 'reject'   => 'bg-danger',
            'log'                       => 'bg-info',
            default                     => 'bg-secondary',
        };
        return "<span class='badge $class'>" . htmlspecialchars($action) . "</span>";
    }
}
