# Wormy - ML Network Worm

Cybersecurity research project demonstrating DQN-based network propagation.

## Quick Start

```bash
# Run simulation training
python3 training/progressive_objective_training.py

# Run real exploitation training  
python3 training/full_real_worm_training.py
```

## Project Structure

```
Wormy/
├── training/           # Training scripts
│   ├── progressive_objective_training.py
│   └── full_real_worm_training.py
├── exploits/          # 25+ exploit modules
├── evasion/           # Stealth techniques
├── post_exploit/      # Persistence, lateral movement
├── c2/                # Command & Control
├── rl_engine/         # DQN agent
└── models/            # Saved models
```

## Results

- Episodes: 10,800
- Objectives: 6/6 completed
- Real exploits: Working on HTTP

## ⚠️ Educational Purpose Only