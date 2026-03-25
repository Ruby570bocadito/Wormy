# Wormy

**ML-Driven Autonomous Network Propagation Simulator**

An intelligent network propagation research platform that uses Deep Q-Learning (DQN) to simulate autonomous network worm behavior in controlled, educational environments.

> **⚠️ EDUCATIONAL PURPOSE ONLY** — This project is designed for cybersecurity research and academic study of network defense mechanisms. Never use on systems without explicit authorization.

---

## Overview

Wormy demonstrates how machine learning can optimize network propagation strategies through reinforcement learning. The system learns optimal target selection by balancing between:

- **Exploit success probability** — prioritizing vulnerable targets
- **Network reachability** — selecting accessible hosts
- **Detection avoidance** — evading IDS/ honeypots
- **Propagation efficiency** — maximizing spread rate

## Key Features

### 🤖 Machine Learning Engine
- **DQN (Deep Q-Network)** agent with experience replay
- TensorFlow/PyTorch backend support
- Simulated network environment for training
- Real-time decision making for target selection

### 🛠️ Exploitation Framework
- **25+ exploit modules** for various services:
  - Web: Weblogic, Apache Struts, Jenkins, Jira, Confluence, Exchange, GitLab
  - Database: MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch
  - Remote Access: SSH, RDP, VNC, Telnet
  - Enterprise: Docker, Kubernetes, Citrix, SNMP, SMB, FTP

### 🛡️ Evasion Techniques
- IDS/Honeypot detection
- Stealth timing randomization
- EDR bypass primitives
- Anti-forensics capabilities
- Memory-only execution support

### 📡 Command & Control
- Multi-protocol C2 (HTTP, DNS, TCP)
- Domain Generation Algorithm (DGA)
- Encrypted communications

### 🔄 Post-Exploitation
- Persistence mechanisms
- Lateral movement
- Credential dumping
- Data exfiltration

### 📊 Swarm Intelligence
- Multi-agent coordination
- Distributed propagation strategies

---

## Architecture

```
Wormy/
├── core/                      # Core worm logic
│   ├── self_healing.py       # Self-repair mechanisms
│   └── performance_benchmark.py
├── exploits/                  # Exploitation framework
│   ├── modules/              # 25+ service-specific exploits
│   ├── exploit_manager.py    # Exploit orchestration
│   └── exploitation_chain.py # Multi-stage attacks
├── evasion/                   # Stealth & evasion
│   ├── stealth_engine.py     # Timing & behavior evasion
│   ├── ids_detector.py       # IDS/honeypot detection
│   ├── edr_bypass.py         # EDR evasion
│   └── anti_forensics.py     # Anti-forensic techniques
├── post_exploit/              # Post-exploitation
│   ├── persistence.py        # Persistence mechanisms
│   ├── lateral_movement.py  # Lateral spread
│   ├── credential_dumping.py # Credential harvesting
│   └── data_exfiltration.py # Data theft
├── c2/                        # Command & Control
│   ├── server.py             # C2 server
│   ├── client.py             # Implant
│   └── dga.py                # Domain generation
├── rl_engine/                 # ML/RL components
│   └── (DQN agent, training)
├── scanner/                   # Network reconnaissance
├── swarm/                     # Multi-agent coordination
├── payloads/                  # Payload generation
├── monitoring/                # Dashboard & logging
├── ml_models/                 # Trained models
├── training/                  # Training scripts
├── utils/                     # Utilities
├── configs/                   # Configuration
└── worm_core.py              # Main orchestrator
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/wormy.git
cd wormy

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

### Requirements

- Python 3.10+
- TensorFlow 2.x **OR** PyTorch 2.x
- Network access for scanning (with authorization)
- See `requirements.txt` for full dependency list

---

## Quick Start

### Training (Simulation)

```bash
# Train DQN agent in simulated environment
python3 training/progressive_objective_training.py

# Advanced training with multiple objectives
python3 training/advanced_dqn_training.py
```

### Simulation Mode

```bash
# Run with simulated targets
python3 training/full_real_worm_training.py
```

### Real Execution (Requires Authorization)

```bash
# Scan-only mode (no exploitation)
python3 worm_core.py --config configs/config.py --scan-only

# Full propagation (requires explicit authorization)
python3 worm_core.py --config configs/config.py
```

---

## Configuration

Edit `configs/config.py` to customize:

```python
# Network targets
network.target_ranges = ["192.168.1.0/24"]

# Safety limits
safety.max_infections = 100
safety.max_runtime_hours = 24
safety.auto_destruct_time = 0  # 0 = disabled

# ML settings
ml.use_pretrained = True
ml.rl_agent_path = "models/dqn_agent.h5"
ml.online_learning = True

# Evasion
evasion.stealth_mode = True
evasion.detect_ids = True
```

---

## Safety Features

Wormy includes multiple safety mechanisms:

| Feature | Description |
|---------|-------------|
| **Kill Switch** | Emergency stop via code |
| **Max Infections** | Limit total spread |
| **Runtime Limit** | Auto-timeout |
| **Auto-Destruct** | Timed self-destruction |
| **Geofencing** | Restrict to allowed networks |
| **Audit Logging** | Full activity tracking |

---

## Results

Latest training metrics (simulation):

- **Episodes**: 10,800+
- **Objectives Completed**: 6/6
- **Exploit Success Rate**: ~85%
- **Infection Rate**: Up to 100% in isolated networks

Sample execution log:
```
ML NETWORK WORM INITIALIZED
Local IP: 192.168.1.136
Target Ranges: 127.0.0.1/32
Stealth Mode: False
ML Enabled: True
============================================================
Loaded 25 exploit modules
Discovered 1 hosts
ML Decision: RL_Agent - Target: 127.0.0.1 (confidence: 0.50)
Exploit: Web_Exploit on 127.0.0.1 - SUCCESS
Infected: 127.0.0.1 via Default_Credentials
```

---

## Documentation

### RL Engine

The DQN agent uses:
- **State**: Host vulnerability scores, open ports, OS detection
- **Actions**: Target selection from available hosts
- **Rewards**: +10 for infection, +vulnerability_score/5 bonus, -5 for failure

### Exploit Modules

Each module follows the pattern:
```python
class Exploit:
    def check(self, target) -> bool:
        """Verify vulnerability"""
    
    def exploit(self, target) -> dict:
        """Execute exploit"""
```

---

## Limitations

- **Lab Environment**: Designed for isolated networks
- **Service Simulation**: Some exploits use simulated services
- **ML Training**: Requires significant training time for optimal performance
- **Platform**: Linux recommended (some modules platform-specific)

---

## Ethical Notice

This project is provided for **educational and research purposes only**. 

By using this software, you agree to:
1. Only test on systems you own or have explicit written authorization for
2. Not use this code for malicious purposes
3. Study defensive countermeasures against autonomous threats

**Unauthorized access to computer systems is illegal and unethical.**

---

## License

MIT License — See LICENSE file for details.

---

## Acknowledgments

- Network security research community
- Reinforcement learning literature (DQN, Rainbow DQN)
- Open source security tools that inspired this project
