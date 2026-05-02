# Wormy ML Network Worm v3.0 - API Documentation

## REST API Endpoints

All endpoints are served by both the Armitage Dashboard (port 5001) and Web Dashboard (port 5000).

### Base URLs
- **Armitage Dashboard**: `http://localhost:5001`
- **Web Dashboard**: `http://localhost:5000`

---

### GET /api/status

Returns current worm propagation status.

**Response:**
```json
{
  "running": true,
  "infected_hosts": 5,
  "failed_targets": 2,
  "total_discovered": 10,
  "vulnerabilities": 15,
  "exploit_chains": 8,
  "lateral_movements": "3/5",
  "brute_force": "2/10",
  "credentials": 12,
  "c2_beacons": 25,
  "polymorphic_mutations": 50,
  "start_time": "2024-04-04T14:00:00"
}
```

---

### GET /api/hosts

Returns list of all monitored hosts with detailed information.

**Response:**
```json
[
  {
    "ip": "192.168.1.100",
    "os": "Windows",
    "status": "infected",
    "health": 85.0,
    "detection_risk": 15.0,
    "cpu": 12.5,
    "memory": 45.2,
    "payload_variant": "v1",
    "infected_at": "2024-04-04T14:05:00",
    "last_beacon": "2024-04-04T14:30:00",
    "activities": 15,
    "credentials_found": 3,
    "lateral_movements": 2
  }
]
```

---

### GET /api/activity?limit=50

Returns activity feed with optional limit.

**Query Parameters:**
- `limit` (int, default: 50) - Number of activities to return

**Response:**
```json
[
  {
    "timestamp": "2024-04-04T14:30:00",
    "type": "infection",
    "host_ip": "192.168.1.100",
    "details": "Infected via SSH_BruteForce"
  }
]
```

---

### GET /api/vulnerabilities

Returns all discovered vulnerabilities.

**Response:**
```json
[
  {
    "host": "192.168.1.100",
    "cve": "CVE-2017-0144",
    "name": "EternalBlue",
    "severity": "CRITICAL",
    "cvss": 9.8,
    "description": "SMBv1 remote code execution"
  }
]
```

---

### GET /api/credentials

Returns discovered credentials.

**Response:**
```json
[
  {
    "username": "admin",
    "password": "P@ssw0rd",
    "source": "discovered"
  }
]
```

---

### GET /api/topology

Returns network topology data for visualization.

**Response:**
```json
{
  "nodes": [
    {"id": "192.168.1.100", "label": "192.168.1.100", "status": "infected", "os": "Windows", "ports": [445, 3389]}
  ],
  "edges": [
    {"from": "192.168.1.100", "to": "192.168.1.101", "label": "ssh_pivot", "success": true}
  ]
}
```

---

### GET /api/stats

Returns full statistics including evasion and host monitor data.

**Response:**
```json
{
  "scans": 5,
  "infections": 10,
  "failed_exploits": 3,
  "total_hosts_discovered": 25,
  "host_monitor": {
    "total_hosts": 10,
    "infected": 8,
    "dormant": 1,
    "detected": 1,
    "lost": 0
  },
  "evasion": {
    "traffic_encrypted": 50,
    "packets_fragmented": 25,
    "signatures_avoided": 15,
    "decoys_generated": 100,
    "protocol_mimicked": 30,
    "domain_fronted": 10,
    "current_risk_level": 0.15
  }
}
```

---

### POST /api/command

Send a command to an infected host.

**Request Body:**
```json
{
  "host_ip": "192.168.1.100",
  "command": "whoami"
}
```

**Response:**
```json
{
  "status": "queued",
  "host": "192.168.1.100",
  "command": "whoami"
}
```

---

## Error Responses

All endpoints may return error responses:

```json
{
  "error": "WormCore not available"
}
```

---

## Rate Limiting

- No rate limiting is enforced by the API itself
- The underlying worm engine has its own rate limiting per host
- Recommended: poll `/api/status` every 5 seconds for real-time updates
