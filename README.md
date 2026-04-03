# Wormy — ML Network Worm v3.0

**ML-Driven Autonomous Network Propagation Platform with Real Exploits**

An intelligent network propagation research platform that uses Deep Q-Learning (DQN) to autonomously discover, exploit, and propagate across networks. Features real exploit execution, credential intelligence, lateral movement, and self-healing.

> **⚠️ EDUCATIONAL/AUDIT PURPOSE ONLY** — Only use on systems you own or have explicit written authorization for.

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/yourusername/wormy.git
cd wormy
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run

```bash
# INTERACTIVE MODE — full CLI with all commands
python3 worm_core.py --interactive --profile stealth

# DRY RUN — safe simulation, no real exploits
python3 worm_core.py --dry-run --profile audit

# WITH METASPLOIT — real exploits via RPC
python3 worm_core.py --config configs/config_msf.yaml

# SCAN ONLY — discover hosts without exploiting
python3 worm_core.py --scan-only

# STEALTH PROFILE — slow, careful, with evasion
python3 worm_core.py --profile stealth

# AGGRESSIVE PROFILE — fast, maximum spread
python3 worm_core.py --profile aggressive
```

### 3. Kill Switch

```bash
python3 worm_core.py --kill-switch "EMERGENCY_STOP_2024"
```

---

## The Brain (RL Agent) — How It Works

### Automatic Training

**The worm trains itself automatically on the first run.** No manual training needed.

```
First run:
  1. Checks for pre-trained model → not found
  2. Trains on 5 realistic scenarios (auto-curriculum):
     small_office → enterprise → datacenter → cloud → iot
  3. Saves best model → saved/rl_agent/best_model.h5
  4. Loads trained model → ready for operation

Subsequent runs:
  1. Loads pre-trained model → instant ready
  2. Continues learning during operation (online learning)
```

### Training Scenarios (Realistic, Not Random)

| Scenario | Hosts | Description |
|----------|-------|-------------|
| **Small Office** | 10 | Router, file server, 5 workstations, printer, WiFi AP |
| **Enterprise** | 30 | AD domain, DCs, servers, workstations, DMZ, management |
| **Datacenter** | 50 | Web farms, DB clusters, containers, storage, monitoring |
| **Cloud** | 40 | API gateway, microservices, K8s, managed DBs, CI/CD |
| **IoT/OT** | 25 | SCADA, PLCs, cameras, building automation, sensors |

Each scenario has:
- **Realistic network topology** (subnets, routing, firewalls)
- **Realistic service configurations** (actual port/service combinations)
- **Realistic vulnerability distributions** (servers more vulnerable than workstations)
- **Realistic credential density** (more creds on servers, fewer on workstations)
- **High-value targets** (DCs, DB servers, file servers)

### Manual Training Commands

```bash
# Train on all scenarios (curriculum order)
python3 training/realistic_training.py

# Train on specific scenarios
python3 training/realistic_training.py --scenarios small_office enterprise

# List available scenarios
python3 training/realistic_training.py --list-scenarios

# Check training status
python3 training/realistic_training.py --status

# Train with custom episodes
python3 training/realistic_training.py --episodes 500
```

### How the Brain Makes Decisions

The RL agent sees **15 features per host**:
- Vulnerability score, port count, OS encoding (one-hot)
- Port binary vector (top 20 ports)
- Credential count, exploit history, success rate
- Strategic value, detection risk, hop distance

It learns through:
1. **Curriculum training** — easy scenarios first, then harder
2. **Shaped rewards** — +20 infection, +15 high-value, +3/credential, -10 detection
3. **Online learning** — replays experiences every 10 iterations during operation
4. **Soft target updates** — τ=0.005 for stable learning

---

## Interactive CLI (16 Commands)

```
wormy> scan              # Professional network scan
wormy> status            # Current propagation status
wormy> targets           # List all discovered hosts
wormy> exploit <ip>      # Exploit a specific target
wormy> vulns <ip>        # Show vulnerabilities for a target
wormy> chain <ip>        # Show exploit chain for a target
wormy> pivot <ip>        # Show lateral movement options
wormy> creds             # Show discovered credentials
wormy> graph             # Knowledge graph summary
wormy> hosts             # Host monitoring dashboard (all infected hosts)
wormy> host <ip>         # Detailed info for a specific host
wormy> activity [limit]  # Real-time activity feed
wormy> heal <ip>         # Trigger self-healing on a host
wormy> propagation_map   # Show how infection spread
wormy> run [iterations]  # Start propagation for N iterations
wormy> report            # Generate full audit report
wormy> exit              # Exit
```

---

## Architecture

```
worm_core.py (Orchestrator v3.0)
│
├── Professional Scanner
│   ├── TTL-based OS detection
│   ├── Banner grabbing + version extraction
│   ├── CVE matching + vulnerability scoring
│   ├── Nmap integration (optional)
│   └── Async parallel scanning
│
├── RL Brain (DQN) — AUTO-TRAINED
│   ├── 15 features/host state space
│   ├── Shaped rewards (+20 infection, +15 high-value, +3/cred)
│   ├── Soft target updates (τ=0.005)
│   ├── Realistic scenario training (5 scenarios)
│   └── Online learning during operation
│
├── Credential Intelligence
│   ├── UCB1 bandit ranking
│   ├── Password mutation engine (leet, years, patterns)
│   ├── Password spraying with lockout detection
│   ├── Credential pivoting (auto-reuse discovered creds)
│   └── 1,737+ wordlist entries across 7 files
│
├── Exploit Manager (26 modules, ALL REAL)
│   ├── SMB (impacket: null session, auth, PTH)
│   ├── SSH (paramiko: brute force, key auth)
│   ├── Web (requests: login, SQLi, cmd injection)
│   ├── MySQL, PostgreSQL, MongoDB, Redis (real auth)
│   ├── FTP, Telnet, VNC, SNMP, RDP (real protocols)
│   ├── Docker, Kubernetes, Elasticsearch (API)
│   ├── Jenkins, Tomcat, Log4j, Struts, WebLogic
│   └── Metasploit RPC (25 exploits mapped)
│
├── Payload Deployer
│   ├── SSH payload upload + execution
│   ├── SMB file drop
│   ├── Web shell deployment
│   ├── Reverse shell establishment
│   └── Command execution on infected hosts
│
├── Persistence Engine
│   ├── Linux: cron, systemd, bashrc, SSH keys
│   ├── Windows: Registry Run keys, scheduled tasks
│   └── Cross-platform: web shells
│
├── Lateral Movement Engine
│   ├── SSH pivot (paramiko)
│   ├── Pass-the-Hash (impacket)
│   ├── PSExec (impacket)
│   ├── WMI execution
│   ├── RDP verification
│   └── WinRM (requests)
│
├── Knowledge Graph
│   ├── Hosts, services, credentials, networks
│   ├── BFS path finding for propagation
│   └── Export to JSON
│
├── Host Monitor
│   ├── Per-host system metrics
│   ├── Unique payload per host (mutation)
│   ├── Activity logging + correlation
│   ├── Health monitoring + self-healing
│   └── Continuous background monitoring
│
├── Evasion
│   ├── Polymorphic engine (5 mutation levels)
│   ├── Honeypot detection (7 indicators)
│   ├── IDS detection
│   └── Stealth timing
│
├── C2 Server
│   ├── HTTP/HTTPS/DNS/TCP protocols
│   ├── DGA (Domain Generation Algorithm)
│   └── Multi-protocol fallback
│
├── Async Exploit Dispatcher
│   ├── Parallel exploitation
│   └── Configurable concurrency
│
└── Reporting
    ├── CLI dashboard (real-time terminal)
    ├── Audit reports (JSON + CSV + Text)
    ├── PDF reports (professional)
    └── Topology visualization (ASCII + HTML + PNG)
```

---

## Docker Lab (Safe Testing Environment)

```bash
# Start vulnerable lab environment
cd docker-lab && docker-compose up -d

# Includes:
# - Metasploitable2 (all ports vulnerable)
# - DVWA (Damn Vulnerable Web App)
# - WebGoat
# - MySQL (root:root)
# - PostgreSQL (postgres:postgres)
# - MongoDB (no auth)
# - Redis (no auth, protected-mode off)
# - Elasticsearch (no security)
# - FTP (ftpuser:ftpuser)
# - SSH (admin:password)

# Test against lab
python3 worm_core.py --interactive --config configs/config_test.yaml
```

---

## Config Profiles

| Setting | stealth | aggressive | audit |
|---------|---------|------------|-------|
| Propagation delay | 10s | 0.5s | 3s |
| Max infections | 10 | 100 | 50 |
| Stealth mode | ✅ | ❌ | ✅ |
| IDS detection | ✅ | ❌ | ✅ |
| Honeypot detection | ✅ | ❌ | ✅ |
| Max runtime | 8h | 2h | 4h |
| Pretrained model | ✅ | ❌ | ✅ |

---

## Project Stats

| Metric | Value |
|--------|-------|
| **Python files** | 114 |
| **Lines of code** | 34,000+ |
| **Exploit modules** | 26 (all real) |
| **Wordlist entries** | 1,737+ |
| **Training scenarios** | 5 realistic |
| **CLI commands** | 16 |
| **Simulated exploits** | ZERO |
| **Tests** | 26/26 passing |

---

## License

MIT License — See LICENSE file.

## Ethical Notice

**Only use on systems you own or have explicit written authorization for.** Unauthorized access is illegal.
