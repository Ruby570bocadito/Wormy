#!/usr/bin/env python3
"""
PROGRESSIVE OBJECTIVE-BASED WORM TRAINING
=========================================
- Progressive difficulty levels
- Objectives to complete
- All worm modules integrated
- Adaptive learning
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import Config
except ImportError:
    from configs.config import Config

import numpy as np
import random
import socket
import time
import json
from rl_engine import PropagationAgent


class ObjectiveTraining:
    """
    Sistema de entrenamiento con objetivos progresivos
    """
    
    OBJECTIVES = {
        'level_1': {
            'name': 'Network Discovery',
            'description': 'Discover all available hosts and ports',
            'targets': ['scan_network', 'identify_services'],
            'reward': 50,
            'difficulty': 0.2,
        },
        'level_2': {
            'name': 'Initial Access',
            'description': 'Successfully exploit at least 1 target',
            'targets': ['exploit_any'],
            'reward': 100,
            'difficulty': 0.3,
        },
        'level_3': {
            'name': 'Persistence',
            'description': 'Achieve persistence on infected host',
            'targets': ['persistence', 'maintain_access'],
            'reward': 150,
            'difficulty': 0.5,
        },
        'level_4': {
            'name': 'Lateral Movement',
            'description': 'Spread to at least 2 more hosts',
            'targets': ['move_lateral', 'infect_new'],
            'reward': 200,
            'difficulty': 0.7,
        },
        'level_5': {
            'name': 'Data Exfiltration',
            'description': 'Extract sensitive data from targets',
            'targets': ['dump_creds', 'exfil_data'],
            'reward': 250,
            'difficulty': 0.8,
        },
        'level_6': {
            'name': 'Complete Chain',
            'description': 'Full attack chain: infect → persist → spread → exfil',
            'targets': ['full_chain'],
            'reward': 500,
            'difficulty': 1.0,
        },
    }


class ProgressiveWormTrainer:
    """
    Entrenador con dificultad progresiva y objetivos
    """
    
    def __init__(self, state_size=60, action_size=30):
        self.state_size = state_size
        self.action_size = action_size
        
        # DQN Agent
        self.agent = PropagationAgent(state_size, action_size, use_dqn=True)
        
        # Progressive Labs - mapped to Docker Lab Network (192.168.100.0/24)
        self.labs = {
            # Level 1: Easy (difficulty 0.2)
            0: {'ip': '192.168.100.10', 'name': 'Redis_Easy', 'level': 1, 'difficulty': 0.2, 'ports': [6379], 'default_creds': True, 'known_creds': ['redis123']},
            1: {'ip': '192.168.100.11', 'name': 'MySQL_Easy', 'level': 1, 'difficulty': 0.2, 'ports': [3306], 'default_creds': True, 'known_creds': ['root', '']},
            
            # Level 2: Medium (difficulty 0.4)
            2: {'ip': '192.168.100.12', 'name': 'PostgreSQL_Med', 'level': 2, 'difficulty': 0.4, 'ports': [5432], 'known_creds': ['admin', 'admin123']},
            3: {'ip': '192.168.100.13', 'name': 'MongoDB_Med', 'level': 2, 'difficulty': 0.4, 'ports': [27017], 'known_creds': ['admin', 'admin123']},
            
            # Level 3: Hard (difficulty 0.6)
            4: {'ip': '192.168.100.14', 'name': 'MSSQL_Hard', 'level': 3, 'difficulty': 0.6, 'ports': [1433], 'known_creds': ['sa', 'SqlPassword123!']},
            5: {'ip': '192.168.100.30', 'name': 'Jenkins_Hard', 'level': 3, 'difficulty': 0.6, 'ports': [8080], 'requires_enum': True},
            
            # Level 4: Expert (difficulty 0.8)
            6: {'ip': '192.168.100.20', 'name': 'RabbitMQ_Expert', 'level': 4, 'difficulty': 0.8, 'ports': [5672], 'auth_required': True, 'known_creds': ['guest', 'guest']},
            7: {'ip': '192.168.100.60', 'name': 'Elastic_Expert', 'level': 4, 'difficulty': 0.8, 'ports': [9200], 'firewalled': True},
            
            # Level 5: Impossible (difficulty 1.0)
            8: {'ip': '192.168.100.40', 'name': 'DVWA_Impossible', 'level': 5, 'difficulty': 1.0, 'ports': [8081], 'vulnerable': True},
            9: {'ip': '192.168.100.50', 'name': 'JuiceShop_Impossible', 'level': 5, 'difficulty': 1.0, 'ports': [8082], 'firewalled': True},
        }
        
        # Extended actions (30 total)
        self.actions = [
            # Scanner (5 actions)
            'scan_port', 'scan_service', 'os_detect', 'vuln_scan', 'enum_users',
            
            # Exploits (10 actions)
            'exploit_http', 'exploit_https', 'exploit_ftp', 'exploit_ssh', 'exploit_smb',
            'exploit_mysql', 'exploit_postgres', 'exploit_redis', 'exploit_jenkins', 'exploit_mongodb',
            
            # Evasion (5 actions)
            'enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs', 'encrypt_traffic',
            
            # Post-Exploit (5 actions)
            'persistence', 'priv_esc', 'lateral_move', 'dump_creds', 'install_backdoor',
            
            # C2 (5 actions)
            'setup_http_c2', 'setup_dns_c2', 'beacon', 'execute_cmd', 'upload_payload',
        ]
        
        # System state
        self.state = {
            'infected': [], 'discovered': [], 'stealth': False,
            'persistence': [], 'lateral': [], 'creds': [],
            'c2_sessions': [], 'objectives_completed': [],
        }
        
        # Metrics
        self.metrics = {
            'scans': 0, 'exploits': 0, 'exploit_success': 0,
            'evasion': 0, 'evasion_success': 0,
            'persistence': 0, 'lateral': 0, 'creds_dump': 0,
            'c2': 0, 'total_reward': 0,
        }
        
        # Training state
        self.current_objective = 'level_1'
        self.objective_progress = {}
        self.difficulty_level = 1
        
        # History
        self.history = {k: [] for k in [
            'episodes', 'rewards', 'epsilon', 'infections', 'objectives',
            'scans', 'evasion', 'persistence', 'lateral', 'creds', 'c2'
        ]}
        
        self.best_reward = float('-inf')
        
        # Epsilon settings
        self.agent.epsilon = 1.0
        self.agent.epsilon_min = 0.001
        self.agent.epsilon_decay = 0.97
        
        self.available_labs = []
    
    def check_port(self, ip, port, timeout=1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_target(self, ip, thorough=False):
        """Scan with difficulty factor"""
        ports_found = []
        
        # Basic ports
        basic_ports = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 8081, 27017]
        
        # Advanced ports for thorough scan
        if thorough:
            basic_ports.extend([23, 25, 110, 143, 445, 3389, 5900, 9200])
        
        for port in basic_ports:
            if self.check_port(ip, port):
                ports_found.append(port)
                self.metrics['scans'] += 1
        
        return ports_found
    
    def calculate_exploit_success(self, lab, action):
        """Calculate success based on difficulty and action"""
        base_difficulty = lab['difficulty']
        
        # Action effectiveness mapping
        action_effectiveness = {
            'exploit_http': 0.7, 'exploit_https': 0.6, 'exploit_ftp': 0.5,
            'exploit_ssh': 0.4, 'exploit_smb': 0.3, 'exploit_mysql': 0.5,
            'exploit_postgres': 0.5, 'exploit_redis': 0.6, 'exploit_jenkins': 0.4,
            'exploit_mongodb': 0.4,
        }
        
        effectiveness = action_effectiveness.get(action, 0.3)
        
        # Success probability
        success_prob = effectiveness * (1 - base_difficulty * 0.5)
        
        # Epsilon exploration bonus
        if random.random() < self.agent.epsilon:
            success_prob += 0.2
        
        return random.random() < success_prob
    
    def simulate_module(self, action, lab, infected):
        """Simulate any worm module"""
        reward = 0
        success = False
        
        # Scanner actions
        if action in ['scan_port', 'scan_service', 'os_detect', 'vuln_scan', 'enum_users']:
            reward = 5
            success = True
        
        # Exploit actions
        elif action.startswith('exploit_'):
            if self.calculate_exploit_success(lab, action):
                success = True
                reward = 100
                self.metrics['exploit_success'] += 1
            else:
                reward = -5
            self.metrics['exploits'] += 1
        
        # Evasion actions
        elif action in ['enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs', 'encrypt_traffic']:
            if random.random() > (lab['difficulty'] * 0.5):
                success = True
                reward = 30
                self.state['stealth'] = True
                self.metrics['evasion_success'] += 1
            else:
                reward = -5
            self.metrics['evasion'] += 1
        
        # Post-exploit actions (require infection)
        elif action in ['persistence', 'priv_esc', 'lateral_move', 'dump_creds', 'install_backdoor']:
            # Increase probability - make it easier to learn
            if infected and random.random() > (lab['difficulty'] * 0.2):
                success = True
                if action == 'persistence':
                    self.metrics['persistence'] += 1
                    self.state['persistence'].append(lab['ip'])
                    reward = 50
                elif action == 'lateral_move':
                    self.metrics['lateral'] += 1
                    self.state['lateral'].append(lab['ip'])
                    reward = 75
                elif action == 'dump_creds':
                    self.metrics['creds_dump'] += 1
                    reward = 40
            else:
                reward = -2
        
        # C2 actions (require infection)
        elif action in ['setup_http_c2', 'setup_dns_c2', 'beacon', 'execute_cmd', 'upload_payload']:
            if infected and random.random() > (lab['difficulty'] * 0.2):
                success = True
                self.metrics['c2'] += 1
                self.state['c2_sessions'].append(lab['ip'])
                reward = 60
            else:
                reward = -2
        
        return success, reward
    
    def check_objectives(self):
        """Check which objectives are completed"""
        completed = []
        
        # Level 1: Network Discovery
        if self.metrics['scans'] >= 10:
            completed.append('level_1')
        
        # Level 2: Initial Access
        if self.metrics['exploit_success'] >= 1:
            completed.append('level_2')
        
        # Level 3: Persistence
        if self.metrics['persistence'] >= 1:
            completed.append('level_3')
        
        # Level 4: Lateral Movement
        if self.metrics['lateral'] >= 1:
            completed.append('level_4')
        
        # Level 5: Data Exfiltration
        if self.metrics['creds_dump'] >= 1:
            completed.append('level_5')
        
        # Level 6: Complete Chain
        if len(completed) >= 5:
            completed.append('level_6')
        
        return completed
    
    def create_state(self, lab, open_ports, episode):
        """Create comprehensive state vector"""
        state = np.zeros(self.state_size)
        
        # Ports (0-9)
        port_map = {21: 0, 22: 1, 80: 2, 443: 3, 3306: 4, 5432: 5, 
                   6379: 6, 8080: 7, 8081: 8, 27017: 9}
        for p in open_ports:
            if p in port_map:
                state[port_map[p]] = 1.0
        
        # Lab info (10-13)
        state[10] = lab['level'] / 5.0
        state[11] = lab['difficulty']
        state[12] = len(open_ports) / 10.0
        state[13] = 1.0 if lab.get('default_creds') else 0.0
        
        # System state (14-20)
        infected_count = len(self.state.get('infected', []))
        discovered_count = len(self.state.get('discovered', []))
        stealth_val = 1.0 if self.state.get('stealth', False) else 0.0
        persistence_count = len(self.state.get('persistence', []))
        lateral_count = len(self.state.get('lateral', []))
        creds_count = len(self.state.get('creds', []))
        c2_count = len(self.state.get('c2_sessions', []))
        
        state[14] = infected_count / 10.0
        state[15] = discovered_count / 20.0
        state[16] = stealth_val
        state[17] = persistence_count / 5.0
        state[18] = lateral_count / 5.0
        state[19] = creds_count / 10.0
        state[20] = c2_count / 5.0
        
        # Metrics (21-30)
        state[21] = self.metrics['scans'] / 100.0
        state[22] = self.metrics['exploit_success'] / max(1, self.metrics['exploits'])
        state[23] = self.metrics['evasion_success'] / max(1, self.metrics['evasion'])
        state[24] = self.metrics['persistence'] / 5.0
        state[25] = self.metrics['lateral'] / 5.0
        state[26] = self.metrics['creds_dump'] / 5.0
        state[27] = self.metrics['c2'] / 5.0
        
        # Current objective progress (28-35)
        objectives = list(ObjectiveTraining.OBJECTIVES.keys())
        for i, obj in enumerate(objectives[:8]):
            state[28 + i] = 1.0 if obj in self.state['objectives_completed'] else 0.0
        
        # Episode/epsilon (36-37)
        state[36] = episode / 100.0
        state[37] = self.agent.epsilon
        
        # Difficulty level (38)
        state[38] = self.difficulty_level / 5.0
        
        return state.tolist()
    
    def get_reward(self, infected, evasion, post_exp, c2, attempts, objectives_complete):
        """Calculate comprehensive reward"""
        reward = 0
        
        # Base infection reward
        if infected:
            reward += 100
        
        # Evasion reward
        if evasion:
            reward += 30
        
        # Post-exploit rewards
        if post_exp:
            reward += 50
        
        # C2 rewards
        if c2:
            reward += 60
        
        # Objective completion bonus
        current_objectives = self.state.get('objectives_completed', [])
        new_objectives = len(objectives_complete) - len(current_objectives)
        if new_objectives > 0:
            reward += new_objectives * 100
        
        # Efficiency bonus
        if infected and attempts <= 3:
            reward += 30
        
        # Difficulty scaling
        reward *= (1 + self.difficulty_level * 0.1)
        
        # Penalty for excessive attempts
        if attempts > 10:
            reward -= 20
        
        return reward
    
    def check_available_labs(self):
        """Scan for available labs"""
        print("\n" + "="*60)
        print("  DETECTING AVAILABLE LABS")
        print("="*60)
        
        self.available_labs = []
        
        for lab_id, lab in self.labs.items():
            ports = self.scan_target(lab['ip'], thorough=(self.difficulty_level >= 3))
            if ports:
                self.available_labs.append(lab_id)
                level_name = ['Easy', 'Medium', 'Hard', 'Expert', 'Impossible'][lab['level']-1]
                print(f"  ✓ Lab {lab_id}: {lab['name']:<20} Level {lab['level']} ({level_name}) Ports: {ports}")
            else:
                print(f"  ✗ Lab {lab_id}: {lab['name']:<20} - Not reachable")
        
        return self.available_labs
    
    def train_on_lab(self, lab_id, episodes=20):
        """Train on specific lab"""
        lab = self.labs[lab_id]
        
        print(f"\n{'='*60}")
        level_name = ['Easy', 'Medium', 'Hard', 'Expert', 'Impossible'][lab['level']-1]
        print(f"  LAB {lab_id}: {lab['name']} | Level {lab['level']} ({level_name})")
        print(f"{'='*60}")
        
        lab_rewards = []
        lab_infections = 0
        
        for ep in range(episodes):
            # Scan
            open_ports = self.scan_target(lab['ip'], thorough=True)
            
            if not open_ports:
                continue
            
            # State
            state = self.create_state(lab, open_ports, ep)
            
            episode_reward = 0
            attempts = 0
            max_attempts = 12
            infected = False
            evasion_done = False
            post_exp_done = False
            c2_done = False
            
            # Action loop - continue after infection to allow post-exploit actions
            while attempts < max_attempts:
                action_idx = self.agent.act(state, list(range(len(self.actions))))
                action = self.actions[action_idx]
                
                # Execute action through modules
                success, reward = self.simulate_module(action, lab, infected)
                
                if action.startswith('exploit_') and success:
                    infected = True
                    self.state['infected'].append(lab['ip'])
                    lab_infections += 1
                
                if action in ['enable_stealth', 'detect_ids', 'bypass_firewall']:
                    evasion_done = True
                
                if action in ['persistence', 'lateral_move', 'dump_creds']:
                    post_exp_done = True
                
                if action in ['setup_http_c2', 'beacon', 'execute_cmd']:
                    c2_done = True
                
                episode_reward += reward
                
                # Check objectives
                objectives_complete = self.check_objectives()
                
                # Store experience
                next_state = self.create_state(lab, open_ports, ep + 1)
                done = attempts >= max_attempts - 1
                
                self.agent.remember(state, action_idx, reward, next_state, done)
                
                if len(self.agent.memory) >= 32:
                    self.agent.replay(batch_size=32)
                
                state = next_state
                attempts += 1
                
                # Check if we should end (after enough post-exploit actions or max attempts)
                if infected and post_exp_done and c2_done:
                    break
            
            # Epsilon decay
            if self.agent.epsilon > self.agent.epsilon_min:
                self.agent.epsilon *= self.agent.epsilon_decay
            
            # Update objectives
            self.state['objectives_completed'] = self.check_objectives()
            
            # Calculate final reward with objectives
            final_reward = self.get_reward(infected, evasion_done, post_exp_done, c2_done, 
                                          attempts, self.state['objectives_completed'])
            episode_reward += final_reward
            self.metrics['total_reward'] += final_reward
            
            # Record history
            lab_rewards.append(episode_reward)
            self.history['rewards'].append(episode_reward)
            self.history['epsilon'].append(self.agent.epsilon)
            self.history['infections'].append(len(self.state['infected']))
            self.history['objectives'].append(len(self.state['objectives_completed']))
            self.history['scans'].append(self.metrics['scans'])
            self.history['evasion'].append(self.metrics['evasion_success'])
            self.history['persistence'].append(self.metrics['persistence'])
            self.history['lateral'].append(self.metrics['lateral'])
            self.history['creds'].append(self.metrics['creds_dump'])
            self.history['c2'].append(self.metrics['c2'])
            self.history['episodes'].append(len(self.history['episodes']) + 1)
            
            # Save best
            if episode_reward > self.best_reward:
                self.best_reward = episode_reward
                os.makedirs("models", exist_ok=True)
                self.agent.save("models/progressive_worm_model.pt")
            
            print(f"  Ep {ep+1}: R={episode_reward:6.1f} | "
                  f"Inf={infected} | Ev={evasion_done} | "
                  f"Pst={post_exp_done} | C2={c2_done} | "
                  f"Obj={len(self.state['objectives_completed'])}/6 | "
                  f"ε={self.agent.epsilon:.3f}")
        
        print(f"\n  📊 Lab {lab_id} Summary: Infections={lab_infections}, "
              f"Avg Reward={sum(lab_rewards)/len(lab_rewards):.1f}")
        
        return lab_infections
    
    def train(self, total_episodes=300, num_rounds=20):
        """Main training loop with progressive difficulty"""
        print("="*70)
        print("  PROGRESSIVE OBJECTIVE-BASED WORM TRAINING")
        print(f"  Rounds: {num_rounds} | Target: Complete all objectives")
        print("="*70)
        
        # Initial scan
        self.check_available_labs()
        
        if not self.available_labs:
            print("\n⚠️ No labs available! Run create_progressive_labs.sh")
            return self.history
        
        # Progressive difficulty: start easy, increase
        episodes_per_lab = max(10, total_episodes // len(self.available_labs))
        
        for round_num in range(num_rounds):
            # Adjust difficulty based on progress
            if round_num > 0:
                self.difficulty_level = min(5, 1 + round_num // 4)
            
            best_val = self.best_reward if self.best_reward != float('-inf') else 0
            print(f"\n{'='*70}")
            print(f"  ROUND {round_num + 1}/{num_rounds}")
            print(f"  Difficulty: Level {self.difficulty_level}")
            print(f"  Epsilon: {self.agent.epsilon:.4f} | Best: {best_val:.1f}")
            print(f"  Objectives: {len(self.state.get('objectives_completed', []))}/6 completed")
            print(f"{'='*70}")
            
            # Show current objectives
            print("\n  Current Objectives:")
            for obj_id, obj in ObjectiveTraining.OBJECTIVES.items():
                status = "✓" if obj_id in self.state['objectives_completed'] else "○"
                print(f"    {status} {obj['name']}: {obj['description']}")
            
            # Train on available labs
            random.shuffle(self.available_labs)
            
            for lab_id in self.available_labs:
                # Skip higher difficulty labs until ready
                if self.labs[lab_id]['level'] > self.difficulty_level + 1:
                    continue
                
                self.train_on_lab(lab_id, episodes_per_lab)
                self.agent.update_target_model()
            
            # Check level completion
            if len(self.state['objectives_completed']) >= 3 and self.difficulty_level < 5:
                self.difficulty_level += 1
                print(f"\n  🔼 Difficulty increased to Level {self.difficulty_level}")
            
            # Save checkpoint
            os.makedirs("models", exist_ok=True)
            self.agent.save(f"models/progressive_round_{round_num+1}.pt")
            
            print(f"\n  📈 Round {round_num+1} Summary:")
            print(f"     Episodes: {len(self.history['rewards'])}")
            print(f"     Infections: {len(self.state['infected'])}")
            print(f"     Objectives: {len(self.state['objectives_completed'])}/6")
            print(f"     Scans: {self.metrics['scans']}, Exploits: {self.metrics['exploit_success']}")
            print(f"     Evasion: {self.metrics['evasion_success']}, Persistence: {self.metrics['persistence']}")
            print(f"     Lateral: {self.metrics['lateral']}, C2: {self.metrics['c2']}")
        
        # Final summary
        print("\n" + "="*70)
        print("  TRAINING COMPLETE - PROGRESSIVE WORM")
        print("="*70)
        print(f"  Total Episodes: {len(self.history['rewards'])}")
        print(f"  Infections: {len(self.state['infected'])}")
        print(f"  Objectives Completed: {len(self.state['objectives_completed'])}/6")
        print(f"  Scans: {self.metrics['scans']}")
        print(f"  Exploits: {self.metrics['exploit_success']}/{self.metrics['exploits']}")
        print(f"  Evasion Success: {self.metrics['evasion_success']}")
        print(f"  Persistence: {self.metrics['persistence']}")
        print(f"  Lateral Movement: {self.metrics['lateral']}")
        print(f"  Credential Dumps: {self.metrics['creds_dump']}")
        print(f"  C2 Sessions: {self.metrics['c2']}")
        
        # Save final model
        self.agent.save("models/progressive_worm_final.pt")
        
        # Save history
        with open("training_history_progressive.json", 'w') as f:
            json.dump({
                'history': self.history,
                'state': self.state,
                'metrics': self.metrics,
            }, f, indent=2)
        
        return self.history


def main():
    print("="*70)
    print("  PROGRESSIVE OBJECTIVE-BASED WORM TRAINING")
    print("  Difficulty: Easy → Impossible")
    print("  Objectives: Network Discovery → Full Attack Chain")
    print("="*70)
    
    trainer = ProgressiveWormTrainer(state_size=60, action_size=30)
    history = trainer.train(total_episodes=300, num_rounds=20)
    
    print("\n✅ Progressive Training Complete!")
    print("Models: models/progressive_*.pt")
    print("History: training_history_progressive.json")


if __name__ == "__main__":
    main()