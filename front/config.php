<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $keys = ['backup_keep_days', 'snmp_community', 'snmp_version', 'snmp_timeout', 'ssh_timeout', 'telnet_timeout'];
    foreach ($keys as $k) {
        if (isset($_POST[$k])) {
            PluginFirewallConfig::set($k, trim($_POST[$k]));
        }
    }
    Html::redirect('config.php?saved=1');
    exit;
}

Html::header('Net Backup - Configuración', $_SERVER['PHP_SELF'], 'plugins', 'firewall');

if (!empty($_GET['saved'])) {
    echo '<div class="alert alert-success alert-dismissible fade show mx-3 mt-3">
        <i class="ti ti-check me-2"></i>Configuración guardada.
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
}

$c = fn(string $k, $d='') => htmlspecialchars(PluginFirewallConfig::get($k, $d));

echo '<div class="card"><div class="card-header"><h3 class="card-title mb-0"><i class="ti ti-settings me-2"></i>Configuración del plugin</h3></div>';
echo '<div class="card-body">';
echo '<form method="post">';
echo '<input type="hidden" name="_glpi_csrf_token" value="' . Session::getNewCSRFToken() . '">';

echo '<h5 class="mb-3">SSH / Telnet</h5>';
echo '<div class="row g-3 mb-4">';
echo '<div class="col-md-3"><label class="form-label">Timeout SSH (seg)</label>';
echo '<input type="number" name="ssh_timeout" class="form-control" value="' . $c('ssh_timeout','30') . '"></div>';
echo '<div class="col-md-3"><label class="form-label">Timeout Telnet (seg)</label>';
echo '<input type="number" name="telnet_timeout" class="form-control" value="' . $c('telnet_timeout','20') . '"></div>';
echo '</div>';

echo '<h5 class="mb-3">SNMP</h5>';
echo '<div class="row g-3 mb-4">';
echo '<div class="col-md-3"><label class="form-label">Comunidad SNMP global</label>';
echo '<input type="text" name="snmp_community" class="form-control" value="' . $c('snmp_community','public') . '"></div>';
echo '<div class="col-md-2"><label class="form-label">Versión</label>';
echo '<select name="snmp_version" class="form-select">';
foreach (['1'=>'v1','2c'=>'v2c','3'=>'v3'] as $v=>$l) {
    $sel = PluginFirewallConfig::get('snmp_version','2c') === $v ? 'selected' : '';
    echo "<option value='$v' $sel>$l</option>";
}
echo '</select></div>';
echo '<div class="col-md-2"><label class="form-label">Timeout (seg)</label>';
echo '<input type="number" name="snmp_timeout" class="form-control" value="' . $c('snmp_timeout','5') . '"></div>';
echo '</div>';

echo '<h5 class="mb-3">Retención de backups</h5>';
echo '<div class="row g-3 mb-4">';
echo '<div class="col-md-3"><label class="form-label">Días a conservar</label>';
echo '<input type="number" name="backup_keep_days" class="form-control" value="' . $c('backup_keep_days','90') . '"></div>';
echo '</div>';

// Registered drivers info
echo '<h5 class="mb-3">Drivers registrados</h5>';
echo '<table class="table table-sm table-bordered mb-4">';
echo '<thead><tr><th>Vendor Key</th><th>Label</th><th>Firewall</th><th>SNMP Map</th></tr></thead><tbody>';
foreach (PluginFirewallDriverRegistry::all() as $key => $d) {
    echo '<tr>';
    echo '<td><code>' . htmlspecialchars($key) . '</code></td>';
    echo '<td>' . htmlspecialchars($d['label']) . '</td>';
    echo '<td class="text-center">' . ($d['is_firewall'] ? '<i class="ti ti-check text-success"></i>' : '') . '</td>';
    echo '<td class="text-center">' . ($d['supports_snmp'] ? '<i class="ti ti-check text-success"></i>' : '') . '</td>';
    echo '</tr>';
}
echo '</tbody></table>';

echo '<div class="alert alert-info small"><i class="ti ti-info-circle me-1"></i>';
echo 'Para agregar un nuevo vendor, creá el archivo <code>inc/driver/nuevomarca.class.php</code> y llamá a <code>PluginFirewallDriverRegistry::register()</code> al inicio del archivo.';
echo '</div>';

echo '<button type="submit" class="btn btn-primary"><i class="ti ti-check me-1"></i>Guardar</button>';
echo '</form></div></div>';

Html::footer();
