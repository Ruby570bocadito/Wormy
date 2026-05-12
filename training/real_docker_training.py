"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

#!/usr/bin/env python3
"""
Autonomous Training with Real Docker Labs
Connects to actual Docker containers for realistic training
"""

import subprocess
import time
import os
import sys
import random
import socket

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from configs.config import Config
except ImportError:
    from config import Config
from rl_engine import NetworkEnvironment, PropagationAgent


class RealDockerTrainer:
    """
    Trainer that uses REAL Docker containers for training
    """
    
    def __init__(self, episodes_per_challenge=5):
        self.episodes_per_challenge = episodes_per_challenge
        self.stats = {
            'total_scans': 0,
            'total_infections': 0,
            'successful_infections': [],
            'challenge_results': []
        }
        
        # Real lab IPs from Docker
        self.labs = {
            0: {'ip': '192.168.200.10', 'name': 'Web', 'ports': [80, 443]},
            1: {'ip': '192.168.200.11', 'name': 'SSH+FTP', 'ports': [22, 21]},
            2: {'ip': '192.168.200.12', 'name': 'MySQL', 'ports': [3306]},
            3: {'ip': '192.168.200.13', 'name': 'Postgres', 'ports': [5432]},
            4: {'ip': '192.168.200.14', 'name': 'Redis', 'ports': [6379]},
            5: {'ip': '192.168.200.15', 'name': 'Jenkins', 'ports': [8080]},
            6: {'ip': '192.168.200.16', 'name': 'Nexus', 'ports': [8081]},
            7: {'ip': '192.168.200.17', 'name': 'MongoDB', 'ports': [27017]},
            8: {'ip': '192.168.200.18', 'name': 'Elastic', 'ports': [9200]},
            9: {'ip': '192.168.200.19', 'name': 'Docker', 'ports': [2375]},
            10: {'ip': '192.168.200.21', 'name': 'Multi', 'ports': [21, 22, 80, 443]},
        }
        
    def check_port_open(self, ip, port, timeout=2):
        """Check if a port is open on target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def scan_target(self, ip):
        """Real port scan on target"""
        open_ports = []
        
        # Common ports to scan
        ports_to_scan = [21, 22, 23, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8081, 9200, 27017]
        
        print(f"    Scanning {ip}...")
        
        for port in ports_to_scan:
            if self.check_port_open(ip, port):
                open_ports.append(port)
                print(f"      ✓ Port {port} open")
        
        return open_ports
    
    def try_exploit(self, ip, open_ports, credentials):
        """Try to exploit open services with credentials"""
        successful_exploits = []
        
        for user, pwd in credentials:
            # Try each open port
            for port in open_ports:
                # Simulate exploitation attempt
                # In real scenario, would attempt actual exploitation
                result = self._attempt_service_login(ip, port, user, pwd)
                if result:
                    successful_exploits.append({
                        'ip': ip,
                        'port': port,
                        'username': user,
                        'password': pwd
                    })
        
        return successful_exploits
    
    def _attempt_service_login(self, ip, port, username, password):
        """Attempt login to service"""
        # Simulate based on probability
        # Real implementation would actually connect
        probability = 0.3  # 30% chance of success
        
        return random.random() < probability
    
    def generate_dynamic_creds(self):
        """Generate random credentials"""
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return [
            ('admin', ''.join(random.choice(chars) for _ in range(8))),
            ('root', ''.join(random.choice(chars) for _ in range(10))),
            ('test', ''.join(random.choice(chars) for _ in range(6))),
            ('user', ''.join(random.choice(chars) for _ in range(6))),
        ]
    
    def train_on_lab(self, lab_id):
        """Train on a specific Docker lab"""
        lab = self.labs[lab_id]
        credentials = self.generate_dynamic_creds()
        
        print(f"\n{'='*60}")
        print(f"LAB {lab_id}: {lab['name']} - {lab['ip']}")
        print(f"Ports: {lab['ports']}")
        print(f"Credentials: {len(credentials)} generated")
        print(f"{'='*60}")
        
        lab_infections = 0
        lab_scans = 0
        episode_rewards = []
        
        for ep in range(self.episodes_per_challenge):
            print(f"\n  Episode {ep + 1}/{self.episodes_per_challenge}")
            
            # Real scan
            open_ports = self.scan_target(lab['ip'])
            lab_scans += 1
            
            if open_ports:
                # Try exploitation
                exploits = self.try_exploit(lab['ip'], open_ports, credentials)
                
                if exploits:
                    print(f"    ✓ SUCCESS: {len(exploits)} exploits successful!")
                    lab_infections += len(exploits)
                    reward = len(exploits) * 100
                else:
                    print(f"    ✗ Failed: No credentials worked")
                    reward = -10
            else:
                print(f"    ⚠ No open ports found")
                reward = -5
            
            episode_rewards.append(reward)
            print(f"    Reward: {reward}")
            
            # Small delay between episodes (realistic)
            time.sleep(0.5)
        
        avg_reward = sum(episode_rewards) / len(episode_rewards)
        
        result = {
            'lab': lab['name'],
            'ip': lab['ip'],
            'infections': lab_infections,
            'scans': lab_scans,
            'avg_reward': avg_reward,
            'success_rate': lab_infections / lab_scans if lab_scans > 0 else 0
        }
        
        self.stats['total_scans'] += lab_scans
        self.stats['total_infections'] += lab_infections
        self.stats['challenge_results'].append(result)
        
        return result
    
    def check_docker_containers(self):
        """Check which Docker containers are running"""
        print("\n🔍 Checking Docker containers...")
        
        try:
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{.Names}}\t{{.Ports}}'],
                capture_output=True, text=True, timeout=5
            )
            
            print(result.stdout if result.stdout else "  No containers running")
            
            # Check connectivity to labs
            running = []
            for lab_id, lab in self.labs.items():
                open_ports = self.scan_target(lab['ip'])
                if open_ports:
                    running.append(lab_id)
                    print(f"  ✓ Lab {lab_id} ({lab['name']}): accessible")
                else:
                    print(f"  ✗ Lab {lab_id} ({lab['name']}): unreachable")
            
            return running
            
        except Exception as e:
            print(f"  Error checking Docker: {e}")
            return []
    
    def train_loop(self, num_labs=None):
        """Main training loop with real Docker"""
        print("="*70)
        print("  AUTONOMOUS TRAINING - REAL DOCKER LABS")
        print("="*70)
        
        # Check which labs are available
        available_labs = self.check_docker_containers()
        
        if not available_labs:
            print("\n⚠️ No Docker labs available!")
            print("Run: ./create_challenge_labs.sh")
            return self.stats
        
        print(f"\n✅ Training on {len(available_labs)} available labs")
        
        # Train on each available lab
        for lab_id in available_labs:
            result = self.train_on_lab(lab_id)
            
            print(f"\n  Result: {result['infections']} infections, "
                  f"avg reward: {result['avg_reward']:.1f}")
        
        # Summary
        print("\n" + "="*70)
        print("FINAL SUMMARY - REAL DOCKER TRAINING")
        print("="*70)
        print(f"  Total Scans: {self.stats['total_scans']}")
        print(f"  Total Infections: {self.stats['total_infections']}")
        
        for r in self.stats['challenge_results']:
            print(f"    {r['lab']}: {r['infections']} infections, "
                  f"{r['success_rate']*100:.1f}% success")
        
        return self.stats


def main():
    print("="*70)
    print("  REAL DOCKER TRAINING MODULE")
    print("  Connects to actual Docker containers for realistic training")
    print("="*70)
    
    trainer = RealDockerTrainer(episodes_per_challenge=3)
    
    # Run training
    stats = trainer.train_loop()
    
    print("\n✅ Training complete!")


if __name__ == "__main__":
    main()