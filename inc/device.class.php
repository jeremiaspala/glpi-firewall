<?php
/**
 * Network device management
 */
class PluginFirewallDevice extends CommonDBTM {

    static $rightname = 'plugin_firewall';

    const VENDOR_CISCO     = 'cisco';
    const VENDOR_CISCO_ASA = 'cisco_asa';
    const VENDOR_CISCO_FTD = 'cisco_ftd';
    const VENDOR_MIKROTIK  = 'mikrotik';
    const VENDOR_FORTINET  = 'fortinet';
    const VENDOR_HPE       = 'hpe';
    const VENDOR_TPLINK    = 'tplink';

    const TYPE_SWITCH   = 'switch';
    const TYPE_ROUTER   = 'router';
    const TYPE_FIREWALL = 'firewall';

    public static function getTypeName($nb = 0) {
        return 'Network Device';
    }

    public static function getIcon() {
        return 'ti ti-router';
    }

    public static function getMenuName() {
        return 'Net Backup';
    }

    public static function getMenuContent() {
        $menu = [];
        $menu['title'] = 'Net Backup';
        $menu['page']  = '/plugins/firewall/front/device.php';
        $menu['icon']  = 'ti ti-router';

        $menu['options']['device']['title']           = 'Dispositivos';
        $menu['options']['device']['page']            = '/plugins/firewall/front/device.php';
        $menu['options']['device']['links']['search'] = '/plugins/firewall/front/device.php';
        $menu['options']['device']['links']['add']    = '/plugins/firewall/front/device.form.php';

        return $menu;
    }

    public static function getVendors(): array {
        $out = [];
        foreach (PluginFirewallDriverRegistry::all() as $key => $d) {
            $out[$key] = $d['label'];
        }
        return $out;
    }

    public static function getDeviceTypes(): array {
        return [
            self::TYPE_SWITCH   => 'Switch',
            self::TYPE_ROUTER   => 'Router',
            self::TYPE_FIREWALL => 'Firewall',
        ];
    }

    public static function isFirewallVendor(string $vendor): bool {
        return PluginFirewallDriverRegistry::isFirewall($vendor);
    }

    public static function renderList(): void {
        global $DB;

        $devices = $DB->request([
            'FROM'  => 'glpi_plugin_firewall_devices',
            'ORDER' => 'name ASC',
        ]);

        $vendors = self::getVendors();
        $types   = self::getDeviceTypes();

        echo '<div class="card mb-3">';
        echo '<div class="card-header d-flex justify-content-between align-items-center">';
        echo '<h3 class="card-title mb-0"><i class="ti ti-router me-2"></i>Dispositivos de Red</h3>';
        echo '<a href="device.form.php" class="btn btn-primary btn-sm"><i class="ti ti-plus me-1"></i>Nuevo dispositivo</a>';
        echo '</div>';
        echo '<div class="card-body p-0">';
        echo '<table class="table table-hover mb-0">';
        echo '<thead><tr>';
        echo '<th>Nombre</th><th>Host</th><th>Tipo</th><th>Vendor</th>';
        echo '<th>Protocolo</th><th>Último backup</th><th>Estado</th><th>Acciones</th>';
        echo '</tr></thead><tbody>';

        foreach ($devices as $dev) {
            $statusClass  = $dev['last_backup_status'] === 'success' ? 'text-success' : ($dev['last_backup_status'] ? 'text-danger' : 'text-muted');
            $statusIcon   = $dev['last_backup_status'] === 'success' ? 'ti-circle-check' : ($dev['last_backup_status'] ? 'ti-alert-circle' : 'ti-minus');
            $lastBackup   = $dev['last_backup_date'] ? date('d/m/Y H:i', strtotime($dev['last_backup_date'])) : 'Nunca';
            $vendorLabel  = $vendors[$dev['vendor']] ?? $dev['vendor'];
            $typeLabel    = $types[$dev['device_type']] ?? $dev['device_type'];
            $activeClass  = $dev['is_active'] ? '' : 'table-secondary text-muted';

            echo "<tr class='$activeClass'>";
            echo "<td><a href='device.form.php?id={$dev['id']}'>" . htmlspecialchars($dev['name']) . "</a></td>";
            echo "<td><code>" . htmlspecialchars($dev['hostname']) . "</code></td>";
            echo "<td><span class='badge bg-secondary'>$typeLabel</span></td>";
            echo "<td>" . htmlspecialchars($vendorLabel) . "</td>";
            echo "<td><span class='badge bg-info'>" . strtoupper($dev['protocol']) . ":{$dev['port']}</span></td>";
            echo "<td class='text-muted small'>$lastBackup</td>";
            echo "<td id='status-{$dev['id']}' class='$statusClass'><i class='ti $statusIcon'></i></td>";
            echo "<td>";
            echo "<button class='btn btn-sm btn-outline-primary me-1' onclick='runBackup({$dev['id']})' title='Ejecutar backup'><i class='ti ti-cloud-upload'></i></button>";
            echo "<a href='backup.php?device_id={$dev['id']}' class='btn btn-sm btn-outline-secondary me-1' title='Ver backups'><i class='ti ti-database'></i></a>";
            echo "<a href='device.form.php?id={$dev['id']}' class='btn btn-sm btn-outline-secondary' title='Editar'><i class='ti ti-edit'></i></a>";
            echo "</td>";
            echo "</tr>";
        }

        if (count($devices) === 0) {
            echo "<tr><td colspan='8' class='text-center text-muted py-4'>No hay dispositivos configurados.</td></tr>";
        }

        echo '</tbody></table></div></div>';

        // Modal para mostrar el log de ejecución
        echo <<<HTML
        <div class="modal fade" id="backupLogModal" tabindex="-1">
          <div class="modal-dialog modal-lg modal-dialog-scrollable">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title"><i class="ti ti-terminal me-2"></i>Log de ejecución &nbsp;<small class="text-muted" id="backupTimer" style="font-size:12px"></small></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
              </div>
              <div class="modal-body p-0">
                <pre id="backupLogContent" style="font-size:12px;background:#1e1e1e;color:#d4d4d4;padding:1rem;margin:0;min-height:200px;white-space:pre-wrap;word-break:break-all"></pre>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
                <button type="button" class="btn btn-outline-primary" onclick="location.reload()"><i class="ti ti-refresh me-1"></i>Recargar</button>
              </div>
            </div>
          </div>
        </div>
        HTML;

        echo <<<JS
        <script>
        // Polling de backups en curso — refresca la fila cuando termina
        (function() {
            const pollingJobs = {};

            function pollJob(jobId, deviceId, btn, logEl, timerInterval) {
                fetch('../ajax/backupstatus.php?job_id=' + encodeURIComponent(jobId))
                .then(r => r.json())
                .then(data => {
                    // Mostrar log en vivo mientras corre
                    if (data.live_log && data.live_log.trim()) {
                        logEl.textContent = data.live_log;
                        logEl.scrollTop = logEl.scrollHeight;
                    }

                    if (!data.found || data.status === 'running') {
                        setTimeout(() => pollJob(jobId, deviceId, btn, logEl, timerInterval), 2000);
                        return;
                    }

                    // Terminó
                    clearInterval(timerInterval);
                    const log = data.log || logEl.textContent;
                    if (data.status === 'success') {
                        logEl.textContent = log + '\\n\\n✓ ' + data.message;
                        logEl.style.color = '#6be06b';
                    } else {
                        logEl.textContent = log + '\\n\\n✗ ERROR: ' + data.message;
                        logEl.style.color = '#ff6b6b';
                    }
                    logEl.scrollTop = logEl.scrollHeight;

                    const statusCell = document.getElementById('status-' + deviceId);
                    if (statusCell) {
                        statusCell.innerHTML = data.status === 'success'
                            ? '<i class="ti ti-circle-check text-success"></i>'
                            : '<i class="ti ti-alert-circle text-danger"></i>';
                    }
                    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="ti ti-cloud-upload"></i>'; }
                })
                .catch(() => setTimeout(() => pollJob(jobId, deviceId, btn, logEl, timerInterval), 4000));
            }

            window.runBackup = function(deviceId) {
                const btn = event.currentTarget;
                btn.disabled = true;
                btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';

                const logEl   = document.getElementById('backupLogContent');
                const timerEl = document.getElementById('backupTimer');
                logEl.style.color = '#d4d4d4';
                logEl.textContent = 'Iniciando backup...\\n';
                new bootstrap.Modal(document.getElementById('backupLogModal')).show();

                let seconds = 0;
                const timerInterval = setInterval(() => {
                    seconds++;
                    if (timerEl) timerEl.textContent = seconds + 's';
                }, 1000);

                const statusCell = document.getElementById('status-' + deviceId);
                if (statusCell) statusCell.innerHTML = '<span class="spinner-border spinner-border-sm text-primary"></span>';

                // Pedir token fresco antes de cada backup (el anterior puede haber expirado)
                fetch('../ajax/getcsrf.php')
                .then(r => r.json())
                .then(csrfData => fetch('../ajax/runbackup.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'device_id=' + deviceId + '&_glpi_csrf_token=' + encodeURIComponent(csrfData.token)
                }))
                .then(r => r.ok ? r.json() : r.text().then(t => { throw new Error('HTTP error: ' + t.substring(0,200)); }))
                .then(data => {
                    if (data.started && data.job_id) {
                        logEl.textContent += '\\n✓ Backup corriendo en el servidor (job: ' + data.job_id.substring(0,8) + '...)\\nPolling cada 3s...\\n';
                        pollJob(data.job_id, deviceId, btn, logEl, timerInterval);
                    } else {
                        clearInterval(timerInterval);
                        logEl.textContent += '\\n✗ Respuesta inesperada del servidor';
                        logEl.style.color = '#ff6b6b';
                        btn.disabled = false; btn.innerHTML = '<i class="ti ti-cloud-upload"></i>';
                    }
                })
                .catch(err => {
                    clearInterval(timerInterval);
                    logEl.textContent += '\\n✗ Error al iniciar: ' + err.message;
                    logEl.style.color = '#ff6b6b';
                    btn.disabled = false; btn.innerHTML = '<i class="ti ti-cloud-upload"></i>';
                    if (statusCell) statusCell.innerHTML = '<i class="ti ti-alert-circle text-danger"></i>';
                });
            };

            // Al cargar la página, verificar si hay backups en curso y hacer polling automático
            fetch('../ajax/backupstatus.php')
            .then(r => r.json())
            .then(data => {
                if (data.running && data.running.length > 0) {
                    data.running.forEach(deviceId => {
                        const statusCell = document.getElementById('status-' + deviceId);
                        if (statusCell) {
                            statusCell.innerHTML = '<span class="spinner-border spinner-border-sm text-primary" title="Backup en curso"></span>';
                            // Polling hasta que termine
                            const checkRunning = () => {
                                fetch('../ajax/backupstatus.php').then(r=>r.json()).then(d => {
                                    if (d.running && d.running.includes(deviceId)) {
                                        setTimeout(checkRunning, 4000);
                                    } else {
                                        location.reload();
                                    }
                                });
                            };
                            setTimeout(checkRunning, 4000);
                        }
                    });
                }
            })
            .catch(() => {});
        })();
        </script>
        JS;
    }

    public static function renderForm(int $id = 0): void {
        global $DB;

        $device = [];
        if ($id > 0) {
            $rows = $DB->request(['FROM' => 'glpi_plugin_firewall_devices', 'WHERE' => ['id' => $id]]);
            foreach ($rows as $row) { $device = $row; break; }
        }

        $vendors = self::getVendors();
        $types   = self::getDeviceTypes();

        $action  = $id > 0 ? 'Editar' : 'Nuevo';
        $v       = fn(string $k, $def = '') => htmlspecialchars($device[$k] ?? $def);

        echo '<div class="card">';
        echo '<div class="card-header"><h3 class="card-title"><i class="ti ti-router me-2"></i>' . $action . ' dispositivo</h3></div>';
        echo '<div class="card-body">';
        echo '<form method="post" action="device.form.php">';
        echo '<input type="hidden" name="_glpi_csrf_token" value="' . Session::getNewCSRFToken() . '">';
        echo '<input type="hidden" name="id" value="' . $id . '">';

        echo '<div class="row g-3">';

        // Name & hostname
        echo '<div class="col-md-4"><label class="form-label">Nombre</label>';
        echo '<input type="text" name="name" class="form-control" value="' . $v('name') . '" required></div>';

        echo '<div class="col-md-4"><label class="form-label">Hostname / IP</label>';
        echo '<input type="text" name="hostname" class="form-control" value="' . $v('hostname') . '" required></div>';

        echo '<div class="col-md-4"><label class="form-label">Modelo</label>';
        echo '<input type="text" name="model" class="form-control" value="' . $v('model') . '"></div>';

        // Vendor & type
        echo '<div class="col-md-4"><label class="form-label">Vendor</label>';
        echo '<select name="vendor" class="form-select">';
        foreach ($vendors as $val => $label) {
            $sel = ($device['vendor'] ?? '') === $val ? 'selected' : '';
            echo "<option value='$val' $sel>" . htmlspecialchars($label) . "</option>";
        }
        echo '</select></div>';

        echo '<div class="col-md-4"><label class="form-label">Tipo</label>';
        echo '<select name="device_type" class="form-select">';
        foreach ($types as $val => $label) {
            $sel = ($device['device_type'] ?? '') === $val ? 'selected' : '';
            echo "<option value='$val' $sel>$label</option>";
        }
        echo '</select></div>';

        // Protocol & port
        echo '<div class="col-md-2"><label class="form-label">Protocolo</label>';
        echo '<select name="protocol" class="form-select">';
        foreach (['ssh' => 'SSH', 'telnet' => 'Telnet'] as $val => $label) {
            $sel = ($device['protocol'] ?? 'ssh') === $val ? 'selected' : '';
            echo "<option value='$val' $sel>$label</option>";
        }
        echo '</select></div>';

        echo '<div class="col-md-2"><label class="form-label">Puerto</label>';
        echo '<input type="number" name="port" class="form-control" value="' . $v('port', '22') . '"></div>';

        // Credentials
        echo '<div class="col-md-4"><label class="form-label">Usuario</label>';
        echo '<input type="text" name="username" class="form-control" value="' . $v('username') . '"></div>';

        echo '<div class="col-md-4"><label class="form-label">Contraseña</label>';
        echo '<input type="password" name="password" class="form-control" placeholder="' . ($id > 0 ? '(sin cambios)' : '') . '" autocomplete="new-password"></div>';

        echo '<div class="col-md-4"><label class="form-label">Enable password (Cisco)</label>';
        echo '<input type="password" name="enable_password" class="form-control" placeholder="' . ($id > 0 ? '(sin cambios)' : '') . '" autocomplete="new-password"></div>';

        // Schedule & GLPI link
        echo '<div class="col-md-4"><label class="form-label">Programación backup</label>';
        echo '<select name="backup_schedule" class="form-select">';
        foreach (['manual' => 'Manual', 'daily' => 'Diario', 'weekly' => 'Semanal'] as $val => $label) {
            $sel = ($device['backup_schedule'] ?? 'manual') === $val ? 'selected' : '';
            echo "<option value='$val' $sel>$label</option>";
        }
        echo '</select></div>';

        // SNMP community for network map
        echo '<div class="col-md-4"><label class="form-label">Comunidad SNMP</label>';
        echo '<input type="text" name="snmp_community" class="form-control" placeholder="public" value="' . $v('snmp_community') . '"></div>';

        echo '<div class="col-md-4"><label class="form-label">Activo</label>';
        $checked = ($device['is_active'] ?? 1) ? 'checked' : '';
        echo '<div class="form-check mt-2"><input type="checkbox" name="is_active" class="form-check-input" id="is_active" value="1" ' . $checked . '>';
        echo '<label class="form-check-label" for="is_active">Habilitado</label></div></div>';

        echo '<div class="col-12"><label class="form-label">Comentario</label>';
        echo '<textarea name="comment" class="form-control" rows="2">' . $v('comment') . '</textarea></div>';

        // Backup command override — build default map for JS
        $defaultCmds = [];
        foreach ($vendors as $vk => $vl) {
            $defaultCmds[$vk] = PluginFirewallDriverRegistry::defaultBackupCommand($vk, $device['model'] ?? '');
        }
        $defaultCmdsJson = json_encode($defaultCmds, JSON_HEX_TAG);
        $currentCmd      = $device['backup_command'] ?? '';
        $currentVendor   = $device['vendor'] ?? 'cisco';
        $defaultPlaceholder = PluginFirewallDriverRegistry::defaultBackupCommand($currentVendor, $device['model'] ?? '');

        echo '<div class="col-12 mt-2">';
        echo '<label class="form-label d-flex align-items-center gap-2">';
        echo 'Comando de backup <span class="badge bg-secondary">Avanzado</span></label>';
        echo '<textarea name="backup_command" id="backup_command" class="form-control font-monospace" rows="2"';
        echo ' placeholder="' . htmlspecialchars($defaultPlaceholder ?: 'Usa el default del driver') . '">';
        echo htmlspecialchars($currentCmd) . '</textarea>';
        echo '<small class="text-muted">Vacío = usa la secuencia del driver. Si lo completás, siempre corre como <code>sshCommand()</code> sin modo interactivo.</small>';
        echo '</div>';

        echo '</div>'; // row

        echo <<<JS
        <script>
        (function() {
            const defaults = $defaultCmdsJson;
            const vendorSel = document.querySelector('select[name="vendor"]');
            const modelField = document.querySelector('input[name="model"]');
            const cmdField   = document.getElementById('backup_command');
            function updatePlaceholder() {
                const vendor = vendorSel ? vendorSel.value : '';
                cmdField.placeholder = defaults[vendor] || 'Usa el default del driver';
            }
            if (vendorSel) vendorSel.addEventListener('change', updatePlaceholder);
        })();
        </script>
        JS;

        echo '<div class="mt-3">';
        echo '<button type="submit" name="action" value="save" class="btn btn-primary me-2"><i class="ti ti-check me-1"></i>Guardar</button>';
        if ($id > 0) {
            echo '<button type="submit" name="action" value="delete" class="btn btn-danger" onclick="return confirm(\'¿Eliminar dispositivo?\')"><i class="ti ti-trash me-1"></i>Eliminar</button>';
        }
        echo '<a href="device.php" class="btn btn-secondary ms-2">Cancelar</a>';
        echo '</div>';

        echo '</form></div></div>';
    }

    public static function processForm(array $post): void {
        global $DB;

        $id     = (int)($post['id'] ?? 0);
        $action = $post['action'] ?? 'save';

        if ($action === 'delete' && $id > 0) {
            $DB->delete('glpi_plugin_firewall_devices', ['id' => $id]);
            Html::redirect('device.php');
            return;
        }

        $data = [
            'name'          => trim($post['name'] ?? ''),
            'hostname'      => trim($post['hostname'] ?? ''),
            'model'         => trim($post['model'] ?? ''),
            'vendor'        => $post['vendor'] ?? 'cisco',
            'device_type'   => $post['device_type'] ?? 'switch',
            'protocol'      => $post['protocol'] ?? 'ssh',
            'port'          => (int)($post['port'] ?? 22),
            'username'      => trim($post['username'] ?? ''),
            'is_active'     => isset($post['is_active']) ? 1 : 0,
            'backup_schedule' => $post['backup_schedule'] ?? 'manual',
            'comment'       => trim($post['comment'] ?? ''),
            'snmp_community' => trim($post['snmp_community'] ?? ''),
            'backup_command' => trim($post['backup_command'] ?? '') ?: null,
            'date_mod'       => date('Y-m-d H:i:s'),
        ];

        if (!empty($post['password'])) {
            $data['password_enc'] = PluginFirewallConfig::encryptPassword($post['password']);
        }
        if (!empty($post['enable_password'])) {
            $data['enable_password_enc'] = PluginFirewallConfig::encryptPassword($post['enable_password']);
        }

        if ($id > 0) {
            $DB->update('glpi_plugin_firewall_devices', $data, ['id' => $id]);
        } else {
            $data['date_creation'] = date('Y-m-d H:i:s');
            $id = $DB->insert('glpi_plugin_firewall_devices', $data);
        }

        Html::redirect("device.form.php?id=$id&saved=1");
    }
}
