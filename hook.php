<?php
/**
 * Network Backup & Firewall Audit Plugin for GLPI 11
 * hook.php — usa doQuery() compatible con GLPI 11 console y web
 */

function plugin_firewall_install() {
    global $DB;

    $tables = [
        'glpi_plugin_firewall_devices' => "
            CREATE TABLE `glpi_plugin_firewall_devices` (
              `id`                        INT NOT NULL AUTO_INCREMENT,
              `name`                      VARCHAR(255) NOT NULL DEFAULT '',
              `hostname`                  VARCHAR(255) NOT NULL DEFAULT '',
              `device_type`               VARCHAR(50) NOT NULL DEFAULT 'switch',
              `vendor`                    VARCHAR(50) NOT NULL DEFAULT 'cisco',
              `model`                     VARCHAR(255) DEFAULT NULL,
              `protocol`                  VARCHAR(10) NOT NULL DEFAULT 'ssh',
              `port`                      INT NOT NULL DEFAULT 22,
              `username`                  VARCHAR(255) DEFAULT NULL,
              `password_enc`              TEXT DEFAULT NULL,
              `enable_password_enc`       TEXT DEFAULT NULL,
              `snmp_community`            VARCHAR(100) DEFAULT NULL,
              `glpi_networkequipments_id` INT DEFAULT NULL,
              `backup_schedule`           VARCHAR(20) DEFAULT 'manual',
              `is_active`                 TINYINT(1) NOT NULL DEFAULT 1,
              `last_backup_date`          TIMESTAMP NULL DEFAULT NULL,
              `last_backup_status`        VARCHAR(20) DEFAULT NULL,
              `backup_command`             TEXT DEFAULT NULL,
              `comment`                   TEXT DEFAULT NULL,
              `date_creation`             TIMESTAMP NULL DEFAULT NULL,
              `date_mod`                  TIMESTAMP NULL DEFAULT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_hostname` (`hostname`),
              KEY `idx_vendor`   (`vendor`),
              KEY `idx_type`     (`device_type`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        'glpi_plugin_firewall_backups' => "
            CREATE TABLE `glpi_plugin_firewall_backups` (
              `id`                         INT NOT NULL AUTO_INCREMENT,
              `plugin_firewall_devices_id` INT NOT NULL,
              `config_text`                LONGTEXT DEFAULT NULL,
              `config_hash`                VARCHAR(64) DEFAULT NULL,
              `backup_date`                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              `trigger_type`               VARCHAR(20) DEFAULT 'manual',
              `status`                     VARCHAR(20) NOT NULL DEFAULT 'success',
              `error_message`              TEXT DEFAULT NULL,
              `size_bytes`                 INT DEFAULT 0,
              `date_creation`              TIMESTAMP NULL DEFAULT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_device` (`plugin_firewall_devices_id`),
              KEY `idx_date`   (`backup_date`),
              KEY `idx_hash`   (`config_hash`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        'glpi_plugin_firewall_rules' => "
            CREATE TABLE `glpi_plugin_firewall_rules` (
              `id`                         INT NOT NULL AUTO_INCREMENT,
              `plugin_firewall_backups_id` INT NOT NULL,
              `plugin_firewall_devices_id` INT NOT NULL,
              `rule_index`                 INT NOT NULL DEFAULT 0,
              `chain`                      VARCHAR(255) DEFAULT NULL,
              `action`                     VARCHAR(50) DEFAULT NULL,
              `protocol`                   VARCHAR(100) DEFAULT NULL,
              `src_address`                VARCHAR(500) DEFAULT NULL,
              `dst_address`                VARCHAR(500) DEFAULT NULL,
              `src_port`                   VARCHAR(500) DEFAULT NULL,
              `dst_port`                   VARCHAR(500) DEFAULT NULL,
              `interface_in`               VARCHAR(255) DEFAULT NULL,
              `interface_out`              VARCHAR(255) DEFAULT NULL,
              `comment`                    VARCHAR(500) DEFAULT NULL,
              `enabled`                    TINYINT(1) NOT NULL DEFAULT 1,
              `raw_rule`                   TEXT DEFAULT NULL,
              `rule_hash`                  VARCHAR(32) DEFAULT NULL,
              `date_creation`              TIMESTAMP NULL DEFAULT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_backup` (`plugin_firewall_backups_id`),
              KEY `idx_device` (`plugin_firewall_devices_id`),
              KEY `idx_hash`   (`rule_hash`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        'glpi_plugin_firewall_snmp_macs' => "
            CREATE TABLE `glpi_plugin_firewall_snmp_macs` (
              `id`                         INT NOT NULL AUTO_INCREMENT,
              `plugin_firewall_devices_id` INT NOT NULL,
              `port_name`                  VARCHAR(255) NOT NULL DEFAULT '',
              `port_index`                 INT DEFAULT NULL,
              `mac_address`                VARCHAR(17) NOT NULL DEFAULT '',
              `vlan_id`                    INT DEFAULT NULL,
              `polled_at`                  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
              `glpi_computers_id`          INT DEFAULT NULL,
              `glpi_networkequipments_id`  INT DEFAULT NULL,
              `glpi_item_type`             VARCHAR(100) DEFAULT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_device` (`plugin_firewall_devices_id`),
              KEY `idx_mac`    (`mac_address`),
              KEY `idx_polled` (`polled_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        'glpi_plugin_firewall_interfaces' => "
            CREATE TABLE `glpi_plugin_firewall_interfaces` (
              `id`                         INT NOT NULL AUTO_INCREMENT,
              `plugin_firewall_devices_id` INT NOT NULL,
              `plugin_firewall_backups_id` INT DEFAULT NULL,
              `if_name`                    VARCHAR(128) NOT NULL DEFAULT '',
              `nameif`                     VARCHAR(64) DEFAULT NULL,
              `description`                VARCHAR(255) DEFAULT NULL,
              `ip_address`                 VARCHAR(45) DEFAULT NULL,
              `prefix_len`                 TINYINT DEFAULT NULL,
              `is_active`                  TINYINT(1) NOT NULL DEFAULT 1,
              `is_dhcp`                    TINYINT(1) NOT NULL DEFAULT 0,
              `parent_if`                  VARCHAR(128) DEFAULT NULL,
              `date_creation`              TIMESTAMP NULL DEFAULT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_device` (`plugin_firewall_devices_id`),
              KEY `idx_ip`     (`ip_address`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        'glpi_plugin_firewall_routes' => "
            CREATE TABLE `glpi_plugin_firewall_routes` (
              `id`                         INT NOT NULL AUTO_INCREMENT,
              `plugin_firewall_devices_id` INT NOT NULL,
              `plugin_firewall_backups_id` INT DEFAULT NULL,
              `dst_network`                VARCHAR(45) NOT NULL DEFAULT '0.0.0.0',
              `dst_prefix`                 TINYINT NOT NULL DEFAULT 0,
              `gateway`                    VARCHAR(45) NOT NULL DEFAULT '',
              `metric`                     INT DEFAULT 1,
              `is_default`                 TINYINT(1) NOT NULL DEFAULT 0,
              `is_active`                  TINYINT(1) NOT NULL DEFAULT 1,
              `date_creation`              TIMESTAMP NULL DEFAULT NULL,
              PRIMARY KEY (`id`),
              KEY `idx_device`  (`plugin_firewall_devices_id`),
              KEY `idx_gateway` (`gateway`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

        'glpi_plugin_firewall_config' => "
            CREATE TABLE `glpi_plugin_firewall_config` (
              `id`           INT NOT NULL AUTO_INCREMENT,
              `config_key`   VARCHAR(100) NOT NULL,
              `config_value` TEXT DEFAULT NULL,
              PRIMARY KEY (`id`),
              UNIQUE KEY `config_key` (`config_key`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    ];

    foreach ($tables as $table => $sql) {
        if (!$DB->tableExists($table)) {
            $DB->doQuery($sql);
        }
    }

    // Schema migrations for already-installed versions
    if ($DB->tableExists('glpi_plugin_firewall_devices')) {
        $colsRes = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_firewall_devices`");
        $devCols = [];
        while ($col = $colsRes->fetch_assoc()) $devCols[] = $col['Field'];
        if (!in_array('backup_command', $devCols)) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_firewall_devices` ADD COLUMN `backup_command` TEXT DEFAULT NULL AFTER `snmp_community`");
        }
    }

    if ($DB->tableExists('glpi_plugin_firewall_interfaces')) {
        $existingCols = [];
        $colsRes = $DB->doQuery("SHOW COLUMNS FROM `glpi_plugin_firewall_interfaces`");
        while ($col = $colsRes->fetch_assoc()) {
            $existingCols[] = $col['Field'];
        }
        if (!in_array('is_dhcp', $existingCols)) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_firewall_interfaces` ADD COLUMN `is_dhcp` TINYINT(1) NOT NULL DEFAULT 0 AFTER `is_active`");
        }
        if (!in_array('parent_if', $existingCols)) {
            $DB->doQuery("ALTER TABLE `glpi_plugin_firewall_interfaces` ADD COLUMN `parent_if` VARCHAR(128) DEFAULT NULL AFTER `is_dhcp`");
        }
    }

    // Seed config defaults
    $hasRows = false;
    foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_config', 'LIMIT' => 1]) as $_) {
        $hasRows = true;
    }
    if (!$hasRows) {
        foreach ([
            ['encryption_key',   bin2hex(random_bytes(16))],
            ['backup_keep_days', '90'],
            ['snmp_community',   'public'],
            ['snmp_version',     '2c'],
            ['snmp_timeout',     '5'],
            ['ssh_timeout',      '30'],
            ['telnet_timeout',   '20'],
        ] as $d) {
            $DB->insert('glpi_plugin_firewall_config', ['config_key' => $d[0], 'config_value' => $d[1]]);
        }
    }

    // Registrar tarea cron para backups automáticos
    CronTask::register(
        'PluginFirewallBackup',
        'AutoBackup',
        HOUR_TIMESTAMP,  // GLPI lo evalúa cada hora; la lógica interna decide si corre según schedule del equipo
        [
            'comment' => 'Net Backup: ejecutar backups automáticos según schedule de cada equipo',
            'mode'    => CronTask::MODE_INTERNAL,
        ]
    );

    return true;
}

function plugin_firewall_uninstall() {
    global $DB;
    foreach ([
        'glpi_plugin_firewall_snmp_macs',
        'glpi_plugin_firewall_routes',
        'glpi_plugin_firewall_interfaces',
        'glpi_plugin_firewall_rules',
        'glpi_plugin_firewall_backups',
        'glpi_plugin_firewall_devices',
        'glpi_plugin_firewall_config',
    ] as $table) {
        if ($DB->tableExists($table)) {
            $DB->doQuery("DROP TABLE `$table`");
        }
    }
    return true;
}
