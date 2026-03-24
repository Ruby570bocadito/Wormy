#!/usr/bin/env python3
"""
REAL WORM TRAINING - Uses actual exploits against Docker labs
Trains the model on REAL network exploitation attempts
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
from exploits.exploit_manager import ExploitManager


class RealWormTrainer:
    """Trains worm using REAL exploitation attempts"""
    
    ACTIONS = [
        'scan_port', 'scan_service', 'os_detect',
        'exploit_http', 'exploit_ftp', 'exploit_ssh', 'exploit_mysql',
        'exploit_redis', 'exploit_jenkins', 'exploit_mongodb',
        'enable_stealth', 'detect_ids', 'bypass_firewall',
        'persistence', 'lateral_move', 'dump_creds',
        'setup_http_c2', 'beacon', 'execute_cmd',
    ]
    
    def __init__(self, state_size=40, action_size=20):
        self.state_size = state_size
        self.action_size = action_size
        self.agent = PropagationAgent(state_size, action_size, use_dqn=True)
        
        self.exploit_manager = ExploitManager(Config())
        
        self.labs = {
            0: {'ip': '192.168.200.10', 'ports': [80], 'name': 'HTTP'},
            1: {'ip': '192.168.200.11', 'ports': [21], 'name': 'FTP'},
            2: {'ip': '192.168.200.12', 'ports': [22], 'name': 'SSH'},
            3: {'ip': '192.168.200.13', 'ports': [3306], 'name': 'MySQL'},
            4: {'ip': '192.168.200.18', 'ports': [8080], 'name': 'Jenkins'},
            5: {'ip': '192.168.200.19', 'ports': [27017], 'name': 'Mongo'},
        }
        
        self.state = {
            'infected': [], 'discovered': [], 'persistence': [],
            'lateral': [], 'creds': [], 'c2_sessions': [],
        }
        
        self.metrics = {
            'scans': 0, 'exploits': 0, 'exploit_success': 0,
            'evasion': 0, 'evasion_success': 0,
            'persistence': 0, 'lateral': 0, 'creds_dump': 0,
            'c2': 0, 'total_reward': 0,
            'real_success': 0, 'real_fail': 0,
        }
        
        self.agent.epsilon = 1.0
        self.agent.epsilon_min = 0.001
        self.agent.epsilon_decay = 0.98
        
        self.available_labs = []
        self.best_reward = float('-inf')
    
    def scan_target(self, ip, thorough=False):
        """Real port scanning"""
        ports = []
        common_ports = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 27017]
        
        for port in common_ports:
            if self.check_port(ip, port):
                ports.append(port)
        
        if ports:
            self.metrics['scans'] += 1
        
        return ports
    
    def check_port(self, ip, port, timeout=2):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def try_real_exploit(self, action, lab):
        """Attempt REAL exploitation"""
        ip = lab['ip']
        open_ports = self.scan_target(ip)
        
        target = {
            'ip': ip,
            'open_ports': open_ports,
            'services': {}
        }
        
        success = False
        reward = -5
        
        if action == 'exploit_http' and 80 in open_ports:
            result = self.exploit_manager.exploit_target(target)
            success = result[0]
            if success:
                reward = 200
                self.metrics['real_success'] += 1
            else:
                self.metrics['real_fail'] += 1
                
        elif action == 'exploit_ftp' and 21 in open_ports:
            success = self._try_ftp_default(ip)
            reward = 200 if success else -5
            if success:
                self.metrics['real_success'] += 1
            else:
                self.metrics['real_fail'] += 1
                
        elif action == 'exploit_ssh' and 22 in open_ports:
            success = self._try_ssh_default(ip)
            if success:
                self.metrics['real_success'] += 1
            else:
                self.metrics['real_fail'] += 1
            reward = 200 if success else -5
                
        elif action == 'exploit_mysql' and 3306 in open_ports:
            success = self._try_mysql_default(ip)
            if success:
                self.metrics['real_success'] += 1
            else:
                self.metrics['real_fail'] += 1
            reward = 200 if success else -5
                
        elif action == 'exploit_redis' and 6379 in open_ports:
            success = self._try_redis(ip)
            if success:
                self.metrics['real_success'] += 1
            else:
                self.metrics['real_fail'] += 1
            reward = 200 if success else -5
                
        elif action == 'exploit_jenkins' and 8080 in open_ports:
            success = self._try_jenkins(ip)
            if success:
                self.metrics['real_success'] += 1
            else:
                self.metrics['real_fail'] += 1
            reward = 200 if success else -5
                
        elif action == 'exploit_mongodb' and 27017 in open_ports:
            success = self._try_mongodb(ip)
            if success:
                self.metrics['real_success'] += 1
            else:
                self.metrics['real_fail'] += 1
            reward = 200 if success else -5
        
        self.metrics['exploits'] += 1
        if success:
            self.metrics['exploit_success'] += 1
        
        return success, reward
    
    def _try_ftp_default(self, ip):
        """Try FTP with default credentials"""
        try:
            from ftplib import FTP
            ftp = FTP(ip, timeout=3)
            try:
                ftp.login()
                ftp.quit()
                return True
            except:
                try:
                    ftp.login('anonymous', 'anonymous@')
                    ftp.quit()
                    return True
                except:
                    return False
        except:
            return False
    
    def _try_ssh_default(self, ip):
        """Try SSH with common credentials - returns False (no creds)"""
        return False
    
    def _try_mysql_default(self, ip):
        """Try MySQL with default credentials"""
        try:
            import pymysql
            conn = pymysql.connect(host=ip, user='root', password='', connect_timeout=3)
            conn.close()
            return True
        except:
            try:
                import pymysql
                conn = pymysql.connect(host=ip, user='root', password='mysql123', connect_timeout=3)
                conn.close()
                return True
            except:
                return False
    
    def _try_redis(self, ip):
        """Try Redis unauthenticated access"""
        try:
            import redis
            r = redis.Redis(host=ip, port=6379, socket_timeout=3)
            r.ping()
            return True
        except:
            return False
    
    def _try_jenkins(self, ip):
        """Try Jenkins with default credentials"""
        import requests
        try:
            r = requests.get(f'http://{ip}:8080/api/json', timeout=3)
            if r.status_code == 200:
                return True
        except:
            pass
        return False
    
    def _try_mongodb(self, ip):
        """Try MongoDB unauthenticated"""
        try:
            from pymongo import MongoClient
            client = MongoClient(host=ip, port=27017, serverSelectionTimeoutMS=3000)
            client.server_info()
            return True
        except:
            return False
    
    def create_state(self, lab, open_ports, episode):
        """Create state vector from real scan"""
        state = np.zeros(self.state_size)
        
        port_map = {21: 0, 22: 1, 80: 2, 443: 3, 3306: 4, 6379: 5, 8080: 6, 27017: 7}
        for p in open_ports:
            if p in port_map:
                state[port_map[p]] = 1.0
        
        state[8] = len(self.state['infected']) / 5.0
        state[9] = self.metrics['exploit_success'] / max(1, self.metrics['exploits'])
        state[10] = episode / 100.0
        state[11] = self.agent.epsilon
        
        for i in range(min(10, len(open_ports))):
            state[12 + i] = open_ports[i] / 10000.0
        
        return state.tolist()
    
    def train_on_lab(self, lab_id, episodes=30):
        """Train on specific lab with REAL exploits"""
        lab = self.labs[lab_id]
        
        print(f"\n{'='*50}")
        print(f"  LAB {lab_id}: {lab['name']} ({lab['ip']})")
        print(f"{'='*50}")
        
        lab_infections = 0
        
        for ep in range(episodes):
            open_ports = self.scan_target(lab['ip'])
            
            if not open_ports:
                print(f"  Ep {ep+1}: No ports found")
                continue
            
            state = self.create_state(lab, open_ports, ep)
            episode_reward = 0
            attempts = 0
            max_attempts = 10
            infected = False
            post_exp_done = False
            c2_done = False
            
            while attempts < max_attempts:
                action_idx = self.agent.act(state, list(range(len(self.ACTIONS))))
                action = self.ACTIONS[action_idx]
                
                if action.startswith('exploit_'):
                    success, reward = self.try_real_exploit(action, lab)
                    if success:
                        infected = True
                        self.state['infected'].append(lab['ip'])
                        lab_infections += 1
                elif action in ['scan_port', 'scan_service', 'os_detect']:
                    success = True
                    reward = 5
                    self.metrics['scans'] += 1
                elif action in ['enable_stealth', 'detect_ids', 'bypass_firewall']:
                    success = True
                    reward = 10
                    self.metrics['evasion_success'] += 1
                elif action in ['persistence', 'lateral_move', 'dump_creds']:
                    if infected:
                        success = True
                        reward = 30
                        post_exp_done = True
                        if action == 'persistence':
                            self.metrics['persistence'] += 1
                    else:
                        success = False
                        reward = -2
                elif action in ['setup_http_c2', 'beacon']:
                    if infected:
                        success = True
                        reward = 40
                        c2_done = True
                        self.metrics['c2'] += 1
                    else:
                        success = False
                        reward = -2
                else:
                    success = True
                    reward = 1
                
                episode_reward += reward
                
                next_state = self.create_state(lab, open_ports, ep + 1)
                done = attempts >= max_attempts - 1
                
                self.agent.remember(state, action_idx, reward, next_state, done)
                
                if len(self.agent.memory) >= 32:
                    self.agent.replay(batch_size=32)
                
                state = next_state
                attempts += 1
                
                if infected and post_exp_done and c2_done:
                    break
            
            if self.agent.epsilon > self.agent.epsilon_min:
                self.agent.epsilon *= self.agent.epsilon_decay
            
            if episode_reward > self.best_reward:
                self.best_reward = episode_reward
            
            print(f"  Ep {ep+1}: R={episode_reward:6.1f} | Inf={infected} | "
                  f"Pst={post_exp_done} | C2={c2_done} | ε={self.agent.epsilon:.3f}")
        
        print(f"\n  Lab {lab_id} Summary: Infections={lab_infections}")
        return lab_infections
    
    def train(self, total_episodes=300, num_rounds=10):
        """Main training loop"""
        print("="*60)
        print("  REAL WORM TRAINING - Live Exploitation")
        print("="*60)
        
        self.check_available_labs()
        
        if not self.available_labs:
            print("No labs available!")
            return
        
        for round_num in range(num_rounds):
            print(f"\n{'='*60}")
            print(f"  ROUND {round_num + 1}/{num_rounds}")
            print(f"{'='*60}")
            
            total_infections = 0
            
            for lab_id in self.available_labs:
                infections = self.train_on_lab(lab_id, episodes=total_episodes // num_rounds // len(self.available_labs))
                total_infections += infections
            
            print(f"\n  Round {round_num + 1} Summary:")
            print(f"    Infections: {total_infections}")
            print(f"    Real Success: {self.metrics['real_success']}")
            print(f"    Real Fail: {self.metrics['real_fail']}")
            print(f"    Epsilon: {self.agent.epsilon:.4f}")
        
        print(f"\n{'='*60}")
        print("  TRAINING COMPLETE")
        print(f"{'='*60}")
        print(f"  Total Episodes: {total_episodes}")
        print(f"  Infections: {sum(len(x) for x in [self.state['infected']])}")
        print(f"  Real Exploits: {self.metrics['real_success']} success, {self.metrics['real_fail']} fail")
        
        os.makedirs("models", exist_ok=True)
        self.agent.save("models/real_worm_model.pt")
        print("  Model saved: models/real_worm_model.pt")
    
    def check_available_labs(self):
        """Check which labs are reachable"""
        print("\n  Detecting available labs...")
        
        self.available_labs = []
        
        for lab_id, lab in self.labs.items():
            ports = self.scan_target(lab['ip'])
            if ports:
                self.available_labs.append(lab_id)
                print(f"  ✓ Lab {lab_id}: {lab['name']} ({lab['ip']}) - Ports: {ports}")
            else:
                print(f"  ✗ Lab {lab_id}: {lab['name']} ({lab['ip']}) - Not reachable")


if __name__ == "__main__":
    import sys
    trainer = RealWormTrainer()
    trainer.train(total_episodes=300, num_rounds=10)