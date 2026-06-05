<?php
/**
 * Network topology map using SNMP MAC address tables
 * Matches switch ports → MAC addresses → GLPI inventory items
 */
class PluginFirewallNetworkMap extends CommonDBTM {

    static $rightname = 'plugin_firewall';

    public static function getTypeName($nb = 0) {
        return 'Network Map';
    }

    /**
     * Poll SNMP MAC address table from a switch
     * Uses bridge MIB: dot1dTpFdbTable (.1.3.6.1.2.1.17.4.3)
     * and ifDescr for port names
     */
    public static function pollDevice(int $deviceId): array {
        global $DB;

        $rows = $DB->request(['FROM' => 'glpi_plugin_firewall_devices', 'WHERE' => ['id' => $deviceId]]);
        $device = null;
        foreach ($rows as $r) { $device = $r; break; }
        if (!$device) return ['error' => 'Dispositivo no encontrado'];

        $community = !empty($device['snmp_community'])
            ? $device['snmp_community']
            : PluginFirewallConfig::get('snmp_community', 'public');
        $version  = PluginFirewallConfig::get('snmp_version', '2c');
        $timeout  = (int) PluginFirewallConfig::get('snmp_timeout', 5);
        $host     = $device['hostname'];

        try {
            // Get port index → port name mapping via ifDescr
            $ifDescr  = self::snmpWalk($host, $community, $version, $timeout, '.1.3.6.1.2.1.2.2.1.2');
            $ifAlias  = self::snmpWalk($host, $community, $version, $timeout, '.1.3.6.1.2.1.31.1.1.1.18');

            // Bridge port → interface index
            $dot1dBpIfIdx = self::snmpWalk($host, $community, $version, $timeout, '.1.3.6.1.2.1.17.1.4.1.2');

            // MAC address → bridge port
            $macTable = self::snmpWalk($host, $community, $version, $timeout, '.1.3.6.1.2.1.17.4.3.1.2');

            // VLAN-aware: also try Q-BRIDGE
            // .1.3.6.1.2.1.17.7.1.2.2.1.2 (dot1qTpFdbPort) — MAC+VLAN → port
            $qMacTable = self::snmpWalk($host, $community, $version, $timeout, '.1.3.6.1.2.1.17.7.1.2.2.1.2');

            // Merge both MAC tables
            $allMacPorts = [];
            foreach ($macTable as $oid => $portIdx) {
                $mac = self::oidToMac($oid);
                if ($mac) $allMacPorts[$mac] = ['port_index' => (int)$portIdx, 'vlan_id' => null];
            }
            foreach ($qMacTable as $oid => $portIdx) {
                [$vlan, $mac] = self::oidToVlanMac($oid);
                if ($mac) $allMacPorts[$mac] = ['port_index' => (int)$portIdx, 'vlan_id' => $vlan];
            }

            // Build port info: bridge_port_idx → ifIndex → ifDescr
            $portInfo = [];
            foreach ($dot1dBpIfIdx as $bpOid => $ifIdx) {
                $bpIdx = (int) substr($bpOid, strrpos($bpOid, '.') + 1);
                $iface = $ifDescr[".1.3.6.1.2.1.2.2.1.2.$ifIdx"] ?? "Port$ifIdx";
                $alias = $ifAlias[".1.3.6.1.2.1.31.1.1.1.18.$ifIdx"] ?? '';
                $portInfo[$bpIdx] = ['if_index' => (int)$ifIdx, 'name' => $iface, 'alias' => $alias];
            }

            // Persist to DB
            $now = date('Y-m-d H:i:s');
            $DB->delete('glpi_plugin_firewall_snmp_macs', ['plugin_firewall_devices_id' => $deviceId]);

            $inserted = 0;
            foreach ($allMacPorts as $mac => $portData) {
                $bpIdx    = $portData['port_index'];
                $port     = $portInfo[$bpIdx] ?? ['name' => "port$bpIdx", 'alias' => '', 'if_index' => $bpIdx];

                // Match MAC to GLPI inventory
                [$glpiType, $glpiId] = self::matchMacToGlpi($mac);

                $DB->insert('glpi_plugin_firewall_snmp_macs', [
                    'plugin_firewall_devices_id' => $deviceId,
                    'port_name'                  => $port['name'],
                    'port_index'                 => $port['if_index'],
                    'mac_address'                => $mac,
                    'vlan_id'                    => $portData['vlan_id'],
                    'polled_at'                  => $now,
                    'glpi_item_type'             => $glpiType,
                    'glpi_computers_id'          => $glpiType === 'Computer' ? $glpiId : null,
                    'glpi_networkequipments_id'  => $glpiType === 'NetworkEquipment' ? $glpiId : null,
                ]);
                $inserted++;
            }

            return ['success' => true, 'mac_count' => $inserted, 'device' => $device['name']];

        } catch (\Throwable $e) {
            return ['error' => $e->getMessage()];
        }
    }

    /**
     * Build topology graph data for D3.js visualization.
     *
     * Three-layer topology logic:
     *
     * L2 (gray):   SNMP MAC table — device appears on a switch port → physical connection
     * L3 (blue):   Shared subnet between interface IPs — direct routed adjacency
     *              Fallback: devices with no static IPs use hostname/32 for subnet comparison
     * Route (orange): Static/default route with gateway matching a known device IP
     *              Only drawn when no L3 subnet edge already exists between the pair
     *
     * Virtual interfaces (VLAN over bridge over physical) are stored with parent_if and
     * is_dhcp flags. Their IPs (static or hostname fallback for DHCP) participate in L3
     * and Route detection just like physical interfaces.
     */
    public static function getGraphData(array $deviceIds = []): array {
        global $DB;

        $devWhere = $deviceIds ? ['id' => $deviceIds] : [];
        $ifWhere  = $deviceIds ? ['plugin_firewall_devices_id' => $deviceIds] : [];
        $macWhere = $ifWhere;

        $allDevices = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_devices', 'WHERE' => $devWhere]) as $d) {
            $allDevices[$d['id']] = $d;
        }

        // Load interfaces per device
        $devIfaces = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_interfaces', 'WHERE' => $ifWhere]) as $iface) {
            $devIfaces[$iface['plugin_firewall_devices_id']][] = $iface;
        }

        // Load static routes per device
        $devRoutes = [];
        foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_routes', 'WHERE' => $ifWhere]) as $route) {
            $devRoutes[$route['plugin_firewall_devices_id']][] = $route;
        }

        $nodes   = [];
        $edges   = [];
        $nodeIds = [];

        // Add device nodes enriched with their interfaces
        foreach ($allDevices as $dev) {
            $nid    = 'sw_' . $dev['id'];
            $ifaces = $devIfaces[$dev['id']] ?? [];

            $ifaceList = [];
            foreach ($ifaces as $if) {
                if ($if['ip_address']) {
                    $ifaceList[] = [
                        'name'   => $if['if_name'],
                        'nameif' => $if['nameif'],
                        'ip'     => $if['ip_address'],
                        'prefix' => $if['prefix_len'],
                        'active' => (bool)$if['is_active'],
                        'dhcp'   => (bool)($if['is_dhcp'] ?? false),
                    ];
                } elseif (!empty($if['is_dhcp'])) {
                    $desc = $if['description'] ?? '';
                    $ifaceList[] = [
                        'name'   => $if['if_name'],
                        'nameif' => $if['nameif'],
                        'ip'     => 'DHCP',
                        'prefix' => null,
                        'active' => (bool)$if['is_active'],
                        'dhcp'   => true,
                        'desc'   => $desc,
                    ];
                }
            }

            $nodes[]      = [
                'id'       => $nid,
                'label'    => $dev['name'],
                'type'     => $dev['device_type'],
                'vendor'   => $dev['vendor'],
                'ip'       => $dev['hostname'],
                'ifaces'   => $ifaceList,
            ];
            $nodeIds[$nid] = true;
        }

        // Build per-device interface list for L3 comparison.
        // For devices with no static IPs, fall back to hostname as /32
        // so they still participate in subnet adjacency detection.
        $devCmpIfaces = [];
        foreach ($allDevices as $devId => $dev) {
            $ifaces = $devIfaces[$devId] ?? [];
            $staticIPs = array_filter($ifaces, fn($i) => $i['ip_address'] && $i['is_active']);
            if (!empty($staticIPs)) {
                $devCmpIfaces[$devId] = array_values($staticIPs);
            } elseif (filter_var($dev['hostname'], FILTER_VALIDATE_IP) !== false) {
                // Synthetic /32 from management hostname
                $devCmpIfaces[$devId] = [[
                    'if_name'    => 'mgmt',
                    'nameif'     => null,
                    'ip_address' => $dev['hostname'],
                    'prefix_len' => 32,
                    'is_active'  => 1,
                    'is_dhcp'    => 1,
                ]];
            }
        }

        // L3 edges: devices sharing a subnet (derived from interface configs)
        $devIds = array_keys($allDevices);
        for ($i = 0; $i < count($devIds); $i++) {
            for ($j = $i + 1; $j < count($devIds); $j++) {
                $dA = $devIds[$i];
                $dB = $devIds[$j];
                $ifacesA = $devCmpIfaces[$dA] ?? [];
                $ifacesB = $devCmpIfaces[$dB] ?? [];

                foreach ($ifacesA as $ifA) {
                    if (!$ifA['ip_address'] || !$ifA['is_active']) continue;
                    foreach ($ifacesB as $ifB) {
                        if (!$ifB['ip_address'] || !$ifB['is_active']) continue;
                        if ($ifA['prefix_len'] < 8 || $ifB['prefix_len'] < 8) continue; // skip /0-/7
                        if (self::sameSubnet($ifA['ip_address'], (int)$ifA['prefix_len'],
                                             $ifB['ip_address'], (int)$ifB['prefix_len'])) {
                            $edgeId = 'sw_' . $dA . '|sw_' . $dB;
                            if (!isset($edges[$edgeId])) {
                                // Use the interface with an actual subnet mask for the label
                                $prefLabel = $ifA['prefix_len'] < 32 ? $ifA['prefix_len'] : $ifB['prefix_len'];
                                $ipLabel   = $prefLabel < 32 ? $ifA['ip_address'] : $ifB['ip_address'];
                                $subnet    = self::networkAddr($ipLabel, (int)$prefLabel) . '/' . $prefLabel;
                                $labelA = ($ifA['nameif'] ?? $ifA['if_name'])
                                        . ' ' . $ifA['ip_address']
                                        . ($ifA['is_dhcp'] ? ' (DHCP)' : '');
                                $labelB = ($ifB['nameif'] ?? $ifB['if_name'])
                                        . ' ' . $ifB['ip_address']
                                        . ($ifB['is_dhcp'] ? ' (DHCP)' : '');
                                $edges[$edgeId] = [
                                    'source' => 'sw_' . $dA,
                                    'target' => 'sw_' . $dB,
                                    'type'   => 'l3',
                                    'label'  => $subnet,
                                    'ifA'    => $labelA,
                                    'ifB'    => $labelB,
                                ];
                            }
                        }
                    }
                }
            }
        }

        // Route edges (L3+): A has static/default route with gateway = B's IP
        // Only add when no direct L3 subnet edge already exists between the pair.
        // Builds a reverse map: known IP → device_id (interfaces + hostnames)
        $ipToDevId = [];
        foreach ($allDevices as $devId => $dev) {
            if (filter_var($dev['hostname'], FILTER_VALIDATE_IP) !== false) {
                $ipToDevId[$dev['hostname']] = $devId;
            }
        }
        foreach ($devIfaces as $devId => $ifaces) {
            foreach ($ifaces as $iface) {
                if ($iface['ip_address']) $ipToDevId[$iface['ip_address']] = $devId;
            }
        }

        foreach ($devRoutes as $srcDevId => $routes) {
            foreach ($routes as $route) {
                if (!$route['is_active']) continue;
                $gwIp = $route['gateway'];
                if (!isset($ipToDevId[$gwIp])) continue;
                $dstDevId = $ipToDevId[$gwIp];
                if ($srcDevId === $dstDevId) continue;

                $edgeId    = 'sw_' . $srcDevId . '|sw_' . $dstDevId;
                $edgeIdRev = 'sw_' . $dstDevId . '|sw_' . $srcDevId;
                if (isset($edges[$edgeId]) || isset($edges[$edgeIdRev])) continue;

                $label = $route['is_default'] ? 'default GW' : $route['dst_network'] . '/' . $route['dst_prefix'];
                $edges[$edgeId] = [
                    'source' => 'sw_' . $srcDevId,
                    'target' => 'sw_' . $dstDevId,
                    'type'   => 'route',
                    'label'  => $label,
                ];
            }
        }

        // L2 edges: SNMP MAC table — device ports → GLPI inventory items
        foreach ($DB->request(['FROM' => 'glpi_plugin_firewall_snmp_macs', 'WHERE' => $macWhere]) as $row) {
            $switchNodeId = 'sw_' . $row['plugin_firewall_devices_id'];
            $itemNodeId   = null;
            $label        = $row['mac_address'];

            if ($row['glpi_item_type'] === 'Computer' && $row['glpi_computers_id']) {
                $itemNodeId = 'comp_' . $row['glpi_computers_id'];
                if (!isset($nodeIds[$itemNodeId])) {
                    foreach ($DB->request(['FROM' => 'glpi_computers', 'WHERE' => ['id' => $row['glpi_computers_id']]]) as $c) {
                        $label = $c['name'];
                    }
                    $nodes[]             = ['id' => $itemNodeId, 'label' => $label, 'type' => 'computer', 'mac' => $row['mac_address'], 'ifaces' => []];
                    $nodeIds[$itemNodeId] = true;
                }
            } elseif ($row['glpi_item_type'] === 'NetworkEquipment' && $row['glpi_networkequipments_id']) {
                $itemNodeId = 'ne_' . $row['glpi_networkequipments_id'];
                if (!isset($nodeIds[$itemNodeId])) {
                    foreach ($DB->request(['FROM' => 'glpi_networkequipments', 'WHERE' => ['id' => $row['glpi_networkequipments_id']]]) as $ne) {
                        $label = $ne['name'];
                    }
                    $nodes[]             = ['id' => $itemNodeId, 'label' => $label, 'type' => 'network', 'mac' => $row['mac_address'], 'ifaces' => []];
                    $nodeIds[$itemNodeId] = true;
                }
            } else {
                $itemNodeId = 'mac_' . str_replace(':', '', $row['mac_address']);
                if (!isset($nodeIds[$itemNodeId])) {
                    $nodes[]             = ['id' => $itemNodeId, 'label' => $row['mac_address'], 'type' => 'unknown', 'mac' => $row['mac_address'], 'ifaces' => []];
                    $nodeIds[$itemNodeId] = true;
                }
            }

            if ($itemNodeId) {
                $edgeId = $switchNodeId . '|' . $itemNodeId;
                if (!isset($edges[$edgeId])) {
                    $edges[$edgeId] = [
                        'source' => $switchNodeId,
                        'target' => $itemNodeId,
                        'type'   => 'l2',
                        'label'  => $row['port_name'],
                        'vlan'   => $row['vlan_id'],
                    ];
                }
            }
        }

        return ['nodes' => array_values($nodes), 'edges' => array_values($edges)];
    }

    private static function sameSubnet(string $ipA, int $prefA, string $ipB, int $prefB): bool {
        $lA = ip2long($ipA);
        $lB = ip2long($ipB);
        if ($lA === false || $lB === false) return false;
        // Use the smaller prefix (larger network) for the check
        $prefix = min($prefA, $prefB);
        $mask   = $prefix > 0 ? ((-1 << (32 - $prefix)) & 0xFFFFFFFF) : 0;
        return ($lA & $mask) === ($lB & $mask);
    }

    private static function networkAddr(string $ip, int $prefix): string {
        $long = ip2long($ip);
        if ($long === false) return $ip;
        $mask = $prefix > 0 ? ((-1 << (32 - $prefix)) & 0xFFFFFFFF) : 0;
        return long2ip($long & $mask);
    }

    private static function matchMacToGlpi(string $mac): array {
        global $DB;

        $macClean = strtolower(str_replace([':', '-', '.'], '', $mac));
        $macFmt   = implode(':', str_split($macClean, 2));

        // Check computers (network ports)
        $rows = $DB->request([
            'FROM'  => 'glpi_networkports',
            'WHERE' => ['mac' => $macFmt],
            'LIMIT' => 1,
        ]);
        foreach ($rows as $r) {
            if ($r['itemtype'] === 'Computer') return ['Computer', $r['items_id']];
            if ($r['itemtype'] === 'NetworkEquipment') return ['NetworkEquipment', $r['items_id']];
            return [$r['itemtype'], $r['items_id']];
        }

        return [null, null];
    }

    private static function snmpWalk(string $host, string $community, string $version, int $timeout, string $oid): array {
        $cmd = sprintf(
            'snmpwalk -v%s -c %s -t %d -r 1 -On %s %s 2>/dev/null',
            escapeshellarg($version),
            escapeshellarg($community),
            $timeout,
            escapeshellarg($host),
            escapeshellarg($oid)
        );

        $output = [];
        exec($cmd, $output);

        $result = [];
        foreach ($output as $line) {
            // .1.3.6.1.2.1.x.y = INTEGER: 5  or  STRING: "eth0"
            if (preg_match('/^(\S+)\s*=\s*(?:[A-Za-z0-9\-]+:\s*)(.+)/', $line, $m)) {
                $result[$m[1]] = trim($m[2], '"');
            }
        }
        return $result;
    }

    private static function oidToMac(string $oid): ?string {
        // OID ends in .a.b.c.d.e.f (6 decimal octets)
        $parts = explode('.', $oid);
        $last6 = array_slice($parts, -6);
        if (count($last6) !== 6) return null;
        foreach ($last6 as $o) {
            if (!is_numeric($o) || (int)$o < 0 || (int)$o > 255) return null;
        }
        return implode(':', array_map(fn($o) => sprintf('%02x', (int)$o), $last6));
    }

    private static function oidToVlanMac(string $oid): array {
        // Q-Bridge: ....<vlan>.<6 mac octets>
        $parts = explode('.', $oid);
        if (count($parts) < 7) return [null, null];
        $mac6 = array_slice($parts, -6);
        $vlan = (int) $parts[count($parts) - 7];
        foreach ($mac6 as $o) {
            if (!is_numeric($o) || (int)$o < 0 || (int)$o > 255) return [null, null];
        }
        $mac = implode(':', array_map(fn($o) => sprintf('%02x', (int)$o), $mac6));
        return [$vlan, $mac];
    }

    public static function renderPage(): void {
        global $DB;

        $devices = iterator_to_array($DB->request([
            'FROM'  => 'glpi_plugin_firewall_devices',
            'WHERE' => ['is_active' => 1],
            'ORDER' => 'name ASC',
        ]));

        $selectedIds = array_map('intval', (array)($_POST['map_devices'] ?? array_column($devices, 'id')));
        $graphData   = self::getGraphData($selectedIds);

        echo '<div class="card mb-3">';
        echo '<div class="card-header d-flex justify-content-between align-items-center">';
        echo '<h3 class="card-title mb-0"><i class="ti ti-topology-star-3 me-2"></i>Mapa de Red Dinámico</h3>';
        echo '<div class="d-flex gap-2">';
        echo '<button class="btn btn-sm btn-outline-success" id="btn-poll-all"><i class="ti ti-refresh me-1"></i>Actualizar SNMP</button>';
        echo '<button class="btn btn-sm btn-outline-secondary" id="btn-fullscreen"><i class="ti ti-maximize me-1"></i>Pantalla completa</button>';
        echo '</div></div>';

        // Device filter
        echo '<div class="card-body border-bottom py-2">';
        echo '<form method="post" class="d-flex flex-wrap gap-2 align-items-center">';
        echo '<input type="hidden" name="_glpi_csrf_token" value="' . Session::getNewCSRFToken() . '">';
        foreach ($devices as $dev) {
            $chk = in_array($dev['id'], $selectedIds) ? 'checked' : '';
            echo "<div class='form-check form-check-inline'>";
            echo "<input class='form-check-input' type='checkbox' name='map_devices[]' value='{$dev['id']}' id='mapdev{$dev['id']}' $chk>";
            echo "<label class='form-check-label small' for='mapdev{$dev['id']}'>" . htmlspecialchars($dev['name']) . "</label>";
            echo "</div>";
        }
        echo '<button type="submit" class="btn btn-sm btn-primary">Filtrar</button>';
        echo '</form>';
        echo '</div>';

        echo '<div class="card-body p-0">';
        echo '<div id="network-map" style="height:600px;background:#f8f9fa;position:relative"></div>';
        echo '</div>';

        // Stats bar
        $nodeCount = count($graphData['nodes']);
        $edgeCount = count($graphData['edges']);
        $unknownCount = count(array_filter($graphData['nodes'], fn($n) => $n['type'] === 'unknown'));
        echo '<div class="card-footer text-muted small d-flex gap-4">';
        echo "<span><i class='ti ti-circles-relation me-1'></i>$nodeCount nodos</span>";
        echo "<span><i class='ti ti-git-branch me-1'></i>$edgeCount conexiones</span>";
        echo "<span class='text-warning'><i class='ti ti-question-mark me-1'></i>$unknownCount sin identificar</span>";
        echo '</div></div>';

        // Tooltip div
        echo '<div id="map-tooltip" style="position:fixed;background:rgba(0,0,0,.8);color:#fff;padding:6px 10px;border-radius:4px;font-size:12px;pointer-events:none;display:none;z-index:9999"></div>';

        $graphJson = json_encode($graphData, JSON_UNESCAPED_UNICODE);
        $csrfName  = 'GLPI_CSRF_TOKEN';

        echo <<<HTML
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <script>
        (function() {
            const graphData = $graphJson;
            const container = document.getElementById('network-map');
            const tooltip   = document.getElementById('map-tooltip');
            const W = container.offsetWidth || 900;
            const H = 600;

            const typeColor = {
                switch:   '#0d6efd', router: '#6610f2', firewall: '#dc3545',
                computer: '#198754', network: '#fd7e14', unknown: '#adb5bd'
            };
            const typeIcon = {
                switch: '⊞', router: '⊕', firewall: '⛨', computer: '⊡', network: '⊟', unknown: '?'
            };

            const svg = d3.select('#network-map')
                .append('svg').attr('width', W).attr('height', H);

            const defs = svg.append('defs');
            ['#999','#0d6efd','#fd7e14'].forEach((col, i) => {
                defs.append('marker')
                    .attr('id', 'arrow'+i).attr('viewBox','0 -5 10 10')
                    .attr('refX',22).attr('refY',0)
                    .attr('markerWidth',5).attr('markerHeight',5)
                    .attr('orient','auto')
                    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill',col);
            });

            const g = svg.append('g');
            svg.call(d3.zoom().scaleExtent([0.2, 4]).on('zoom', e => g.attr('transform', e.transform)));

            const sim = d3.forceSimulation(graphData.nodes)
                .force('link',   d3.forceLink(graphData.edges).id(d => d.id).distance(d => d.type==='l3' ? 150 : 80))
                .force('charge', d3.forceManyBody().strength(-400))
                .force('center', d3.forceCenter(W/2, H/2))
                .force('collide',d3.forceCollide(45));

            const link = g.append('g').selectAll('g').data(graphData.edges).join('g');

            const edgeColor = d => ({l3:'#0d6efd', route:'#fd7e14', l2:'#ccc'})[d.type] || '#ccc';
            const edgeDash  = d => ({l3:'6,3', route:'3,4'})[d.type] || null;
            const edgeArrow = d => ({l3:'url(#arrow1)', route:'url(#arrow2)', l2:'url(#arrow0)'})[d.type];

            const linkLine = link.append('line')
                .attr('stroke', edgeColor)
                .attr('stroke-width', d => d.type==='l2' ? 1.2 : 2.2)
                .attr('stroke-dasharray', edgeDash)
                .attr('marker-end', edgeArrow);

            const linkLabel = link.append('text')
                .attr('font-size','9px').attr('fill', edgeColor)
                .attr('text-anchor','middle').attr('pointer-events','none')
                .text(d => d.label || '');

            const node = g.append('g').selectAll('g').data(graphData.nodes).join('g')
                .attr('cursor','pointer')
                .call(d3.drag()
                    .on('start', (e,d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
                    .on('drag',  (e,d) => { d.fx=e.x; d.fy=e.y; })
                    .on('end',   (e,d) => { if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }))
                .on('mouseover', (e,d) => {
                    let html = '<strong>' + (d.label||d.id) + '</strong>';
                    if (d.vendor) html += '<br><span style="opacity:.7">' + d.vendor + ' · ' + d.type + '</span>';
                    if (d.mac)    html += '<br>MAC: ' + d.mac;
                    if (d.ifaces && d.ifaces.length) {
                        html += '<hr style="margin:4px 0;border-color:#555">';
                        d.ifaces.filter(f=>f.active).forEach(f => {
                            const name = f.nameif ? f.nameif + ' (' + f.name + ')' : f.name;
                            if (f.dhcp && f.ip === 'DHCP') {
                                const desc = f.desc ? ' · ' + f.desc : '';
                                html += '<br><code style="font-size:11px;opacity:.5">DHCP</code>'
                                      + ' <span style="opacity:.5">' + name + desc + '</span>';
                            } else {
                                html += '<br><code style="font-size:11px">' + f.ip + '/' + f.prefix + '</code>'
                                      + ' <span style="opacity:.6">' + name + (f.dhcp ? ' <em>dhcp</em>' : '') + '</span>';
                            }
                        });
                    }
                    tooltip.innerHTML = html;
                    tooltip.style.display = 'block';
                })
                .on('mousemove', e => {
                    tooltip.style.left = (e.clientX + 14) + 'px';
                    tooltip.style.top  = (e.clientY - 32) + 'px';
                })
                .on('mouseout', () => tooltip.style.display = 'none');

            const isNet = d => ['switch','router','firewall'].includes(d.type);
            node.append('circle')
                .attr('r', d => isNet(d) ? 20 : 13)
                .attr('fill', d => typeColor[d.type] || '#adb5bd')
                .attr('stroke','#fff').attr('stroke-width',2.5);

            node.append('text').attr('text-anchor','middle').attr('dy','0.35em')
                .attr('fill','#fff').attr('font-size', d => isNet(d) ? '14px':'10px')
                .attr('pointer-events','none')
                .text(d => typeIcon[d.type] || '?');

            node.append('text').attr('text-anchor','middle').attr('dy','2.4em')
                .attr('font-size','10px').attr('fill','#333').attr('font-weight', d => isNet(d)?'600':'400')
                .attr('pointer-events','none')
                .text(d => d.label.length > 18 ? d.label.substr(0,16)+'…' : d.label);

            sim.on('tick', () => {
                linkLine
                    .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                linkLabel
                    .attr('x', d => (d.source.x + d.target.x) / 2)
                    .attr('y', d => (d.source.y + d.target.y) / 2 - 4);
                node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
            });

            // Legend
            const legend = svg.append('g').attr('transform','translate(12,12)');
            Object.entries(typeColor).forEach(([type,color],i) => {
                const lg = legend.append('g').attr('transform','translate(0,'+(i*18)+')');
                lg.append('circle').attr('r',6).attr('fill',color);
                lg.append('text').attr('x',12).attr('dy','0.35em').attr('font-size','11px').text(type);
            });
            const nTypes = Object.keys(typeColor).length;
            const lgL3 = legend.append('g').attr('transform','translate(0,'+(nTypes*18)+')');
            lgL3.append('line').attr('x1',0).attr('x2',12).attr('stroke','#0d6efd').attr('stroke-width',2).attr('stroke-dasharray','4,2');
            lgL3.append('text').attr('x',16).attr('dy','0.35em').attr('font-size','11px').text('L3 subnet');
            const lgRoute = legend.append('g').attr('transform','translate(0,'+((nTypes+1)*18)+')');
            lgRoute.append('line').attr('x1',0).attr('x2',12).attr('stroke','#fd7e14').attr('stroke-width',2).attr('stroke-dasharray','3,3');
            lgRoute.append('text').attr('x',16).attr('dy','0.35em').attr('font-size','11px').text('ruta estática');

            // Poll all button
            document.getElementById('btn-poll-all').addEventListener('click', function() {
                this.disabled = true;
                this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Actualizando...';
                const ids = [...new Set(graphData.nodes.filter(n=>isNet(n)).map(n=>n.id.replace('sw_','')))];
                Promise.all(ids.map(id =>
                    fetch('../ajax/pollsnmp.php', {
                        method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
                        body:'device_id='+id
                    }).then(r=>r.json())
                )).then(results => {
                    const ok = results.filter(r=>r.success).length;
                    alert('SNMP actualizado: '+ok+'/'+results.length+' dispositivos. Recargando...');
                    location.reload();
                }).catch(() => location.reload());
            });

            document.getElementById('btn-fullscreen').addEventListener('click', function() {
                container.requestFullscreen && container.requestFullscreen();
            });
        })();
        </script>
        HTML;
    }
}
