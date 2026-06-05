<?php
/**
 * CLI backup runner — proceso independiente de Apache.
 * Uso: php run_backup.php <device_id> <job_id>
 */

$deviceId = (int)($argv[1] ?? 0);
$jobId    = trim($argv[2] ?? '');

if ($deviceId <= 0) {
    fwrite(STDERR, "Usage: php run_backup.php <device_id> <job_id>\n");
    exit(1);
}

// cli/ → firewall/ → plugins/ → glpi/  (3 niveles)
$glpiRoot = dirname(__DIR__, 3);
chdir($glpiRoot);

require_once $glpiRoot . '/vendor/autoload.php';
require_once $glpiRoot . '/src/autoload/constants.php';
require_once $glpiRoot . '/config/config_db.php';

global $DB;
$DB = new DB();

if (!$DB->connected) {
    fwrite(STDERR, "DB connection failed\n");
    exit(2);
}

$plugDir = $glpiRoot . '/plugins/firewall';
require_once $plugDir . '/inc/config.class.php';
require_once $plugDir . '/inc/driverregistry.class.php';
require_once $plugDir . '/inc/connector.class.php';
require_once $plugDir . '/inc/backup.class.php';

foreach (glob($plugDir . '/inc/driver/*.class.php') as $f) {
    require_once $f;
}

PluginFirewallBackup::run($deviceId, 'manual', $jobId);
