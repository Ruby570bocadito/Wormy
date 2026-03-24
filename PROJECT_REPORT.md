# Wormy - ML Network Worm

## Project Overview
Educational cybersecurity research project demonstrating machine learning (DQN) for automated network propagation.

## Modules

### 1. Scanner (`scanner/`)
- Network discovery
- Port scanning  
- Service identification
- OS detection

### 2. Exploits (`exploits/`)
- 25+ exploit modules
- HTTP/HTTPS, FTP, SSH, SMB
- MySQL, PostgreSQL, Redis, MongoDB
- Jenkins, Kubernetes, Docker
- Web vulnerabilities (Log4j, Struts, etc.)

### 3. Evasion (`evasion/`)
- Stealth mode
- IDS detection
- EDR bypass
- Anti-forensics

### 4. Post-Exploitation (`post_exploit/`)
- Persistence mechanisms
- Lateral movement
- Credential dumping
- Data exfiltration

### 5. C2 (`c2/`)
- HTTP/DNS beacons
- Command execution
- Payload delivery
- DGA (Domain Generation Algorithm)

### 6. RL Engine (`rl_engine/`)
- DQN agent (TensorFlow/PyTorch)
- Experience replay
- Target selection learning

## Training Scripts

| Script | Description |
|--------|-------------|
| `progressive_objective_training.py` | Simulation-based with 6 objectives |
| `full_real_worm_training.py` | Real exploitation attempts |
| `comprehensive_real_training.py` | All modules integrated |

## Docker Labs

Available targets for training:
- 192.168.200.10:80 (HTTP - exploitable)
- 192.168.200.11:21 (FTP)
- 192.168.200.12:22 (SSH)
- 192.168.200.13:3306 (MySQL)

## Results

- Episodes: 10,800
- Objectives: 6/6 completed
- Real exploits: Working on HTTP only

## Usage

```bash
# Run training
python3 training/progressive_objective_training.py

# Test real exploits
python3 training/full_real_worm_training.py
```

## Educational Purpose

This project is for **educational and research purposes only**. It demonstrates how ML can be used for automated network propagation in a controlled lab environment.