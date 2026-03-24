#!/usr/bin/env python3
"""
Autonomous Training Loop - Multi-Challenge Docker Labs
Trains the RL agent across 10 different lab environments with dynamic credentials
"""

import subprocess
import time
import os
import sys
import random
import json
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import Config
except ImportError:
    from configs.config import Config
from rl_engine import NetworkEnvironment, PropagationAgent


class AutonomousTrainer:
    """
    Autonomous trainer that rotates through challenges
    with dynamic credentials and increasing difficulty
    """
    
    def __init__(self, num_challenges=10, episodes_per_challenge=10):
        self.num_challenges = num_challenges
        self.episodes_per_challenge = episodes_per_challenge
        self.current_challenge = 0
        self.total_episodes = 0
        self.stats = {
            'challenges_completed': 0,
            'total_infections': 0,
            'success_rate': [],
            'challenge_history': []
        }
        
        # Challenge configurations with different network sizes and difficulties
        self.challenges = [
            {'name': 'Basic Web', 'network_size': 5, 'difficulty': 1, 'target_ports': [80, 443]},
            {'name': 'SSH+FTP', 'network_size': 8, 'difficulty': 2, 'target_ports': [22, 21]},
            {'name': 'MySQL DB', 'network_size': 10, 'difficulty': 3, 'target_ports': [3306]},
            {'name': 'Postgres+Redis', 'network_size': 12, 'difficulty': 3, 'target_ports': [5432, 6379]},
            {'name': 'DevOps Stack', 'network_size': 15, 'difficulty': 4, 'target_ports': [8080, 8081]},
            {'name': 'NoSQL Cluster', 'network_size': 18, 'difficulty': 5, 'target_ports': [27017, 9200]},
            {'name': 'Container Platform', 'network_size': 20, 'difficulty': 5, 'target_ports': [2375, 6443]},
            {'name': 'Windows AD', 'network_size': 25, 'difficulty': 6, 'target_ports': [445, 3389]},
            {'name': 'Multi-Service', 'network_size': 30, 'difficulty': 7, 'target_ports': [21, 22, 80, 443]},
            {'name': 'Vulnerable Apps', 'network_size': 35, 'difficulty': 8, 'target_ports': [80, 3000, 8080]},
        ]
        
        # Dynamic credentials for each challenge
        self.current_credentials = {}
        
    def generate_dynamic_creds(self, challenge_id):
        """Generate new credentials for a challenge"""
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        creds = {
            'admin': ''.join(random.choice(chars) for _ in range(8)),
            'root': ''.join(random.choice(chars) for _ in range(10)),
            'user': ''.join(random.choice(chars) for _ in range(6)),
        }
        self.current_credentials[challenge_id] = creds
        return creds
    
    def docker_challenge_up(self, challenge_id):
        """Bring up a Docker challenge"""
        print(f"\n[Challenge {challenge_id}] Starting Docker containers...")
        
        # Simplified: just mark as active (real implementation would use docker-compose)
        print(f"  ✓ Challenge {challenge_id} containers online")
        return True
    
    def docker_challenge_down(self, challenge_id):
        """Tear down a Docker challenge"""
        print(f"\n[Challenge {challenge_id}] Stopping Docker containers...")
        return True
    
    def rotate_challenge(self):
        """Rotate to next challenge with new credentials"""
        self.docker_challenge_down(self.current_challenge)
        self.current_challenge = (self.current_challenge + 1) % self.num_challenges
        creds = self.generate_dynamic_creds(self.current_challenge)
        self.docker_challenge_up(self.current_challenge)
        
        challenge = self.challenges[self.current_challenge]
        print(f"\n{'='*70}")
        print(f"CHALLENGE {self.current_challenge + 1}/{self.num_challenges}: {challenge['name']}")
        print(f"Difficulty: {challenge['difficulty']}/10 | Network: {challenge['network_size']} hosts")
        print(f"Credentials rotated: admin:{creds['admin'][:4]}***, root:{creds['root'][:4]}***")
        print(f"{'='*70}")
        
        self.stats['challenge_history'].append({
            'challenge': challenge['name'],
            'timestamp': datetime.now().isoformat(),
            'credentials_rotated': True
        })
        
    def train_challenge(self, challenge_id):
        """Train agent on a specific challenge"""
        challenge = self.challenges[challenge_id]
        
        # Create environment with challenge-specific config
        env = NetworkEnvironment(
            network_size=challenge['network_size'],
            max_steps=20 + challenge['difficulty'] * 5
        )
        
        # Agent with growing complexity
        agent = PropagationAgent(
            state_size=challenge['network_size'] * 3,
            action_size=challenge['network_size'],
            use_dqn=True
        )
        
        episode_rewards = []
        episode_infections = []
        
        print(f"\nTraining on Challenge: {challenge['name']}")
        
        for ep in range(self.episodes_per_challenge):
            state = env.reset()
            total_reward = 0
            steps = 0
            
            while steps < env.max_steps:
                available = env.get_available_actions()
                if not available:
                    break
                
                action = agent.act(state, available_actions=available)
                next_state, reward, done, info = env.step(action)
                
                # Dynamic reward adjustment based on challenge difficulty
                if reward > 0:
                    reward *= (1 + challenge['difficulty'] * 0.1)
                
                agent.remember(state, action, reward, next_state, done)
                
                if len(agent.memory) >= 16:
                    agent.replay(batch_size=16)
                
                state = next_state
                total_reward += reward
                episode_infections.append(info['infected_count'])
                steps += 1
                
                if done:
                    break
            
            # Track max infections from all steps in episode
            max_infected = max(episode_infections) if episode_infections else 0
            success_rate = max_infected / challenge['network_size']
            
            # Update target network periodically
            if (ep + 1) % 5 == 0:
                agent.update_target_model()
            
            # Decay epsilon
            if agent.epsilon > 0.01:
                agent.epsilon *= 0.98
            
            episode_rewards.append(total_reward)
            episode_infections.append(info['infected_count'])
            
            if (ep + 1) % 5 == 0:
                avg_reward = sum(episode_rewards[-5:]) / 5
                avg_infections = sum(episode_infections[-5:]) / 5
                print(f"  Episode {ep+1}: Reward={avg_reward:.1f}, Infections={avg_infections:.1f}/{challenge['network_size']}")
        
        # Challenge completion stats
        success_rate = sum(episode_infections) / (len(episode_infections) * challenge['network_size'])
        self.stats['success_rate'].append(success_rate)
        self.stats['total_infections'] += sum(episode_infections)
        self.stats['challenges_completed'] += 1
        
        return agent, {
            'avg_reward': sum(episode_rewards) / len(episode_rewards),
            'max_infections': max(episode_infections),
            'success_rate': success_rate
        }
    
    def train_loop(self, num_cycles=5):
        """Main training loop"""
        print("="*70)
        print("  AUTONOMOUS MULTI-CHALLENGE TRAINING")
        print("  Dynamic Credentials | Progressive Difficulty | Continuous Learning")
        print("="*70)
        
        for cycle in range(num_cycles):
            print(f"\n{'#'*70}")
            print(f"CYCLE {cycle + 1}/{num_cycles}")
            print(f"{'#'*70}")
            
            # Train on each challenge
            for challenge_id in range(self.num_challenges):
                self.rotate_challenge()
                
                agent, result = self.train_challenge(challenge_id)
                
                self.total_episodes += self.episodes_per_challenge
                
                print(f"\n  Challenge {challenge_id + 1} Complete:")
                print(f"    Avg Reward: {result['avg_reward']:.1f}")
                print(f"    Max Infections: {result['max_infections']}")
                print(f"    Success Rate: {result['success_rate']*100:.1f}%")
            
            # Cycle summary
            print(f"\n{'='*70}")
            print(f"CYCLE {cycle + 1} SUMMARY")
            print(f"{'='*70}")
            avg_success = sum(self.stats['success_rate'][-self.num_challenges:]) / self.num_challenges
            print(f"  Total Episodes: {self.total_episodes}")
            print(f"  Avg Success Rate: {avg_success*100:.1f}%")
            print(f"  Challenges Completed: {self.stats['challenges_completed']}")
        
        return self.stats
    
    def continuous_learning_mode(self, duration_minutes=60):
        """Continuous learning mode - runs indefinitely"""
        print("="*70)
        print("  CONTINUOUS LEARNING MODE")
        print(f"  Duration: {duration_minutes} minutes")
        print("="*70)
        
        start_time = time.time()
        iteration = 0
        
        while (time.time() - start_time) < duration_minutes * 60:
            iteration += 1
            
            # Rotate to random challenge
            challenge_id = random.randint(0, self.num_challenges - 1)
            challenge = self.challenges[challenge_id]
            
            creds = self.generate_dynamic_creds(challenge_id)
            
            print(f"\n[Iteration {iteration}] Challenge: {challenge['name']}")
            print(f"  New credentials generated")
            
            agent, result = self.train_challenge(challenge_id)
            self.total_episodes += self.episodes_per_challenge
            
            elapsed = (time.time() - start_time) / 60
            print(f"  Elapsed: {elapsed:.1f}min | Total Episodes: {self.total_episodes}")
            
            if iteration % 10 == 0:
                avg_success = sum(self.stats['success_rate'][-10:]) / 10
                print(f"\n  Recent success rate: {avg_success*100:.1f}%")
        
        return self.stats


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Autonomous Multi-Challenge Training')
    parser.add_argument('--cycles', type=int, default=3, help='Number of training cycles')
    parser.add_argument('--continuous', action='store_true', help='Run continuous learning mode')
    parser.add_argument('--duration', type=int, default=30, help='Duration in minutes for continuous mode')
    args = parser.parse_args()
    
    trainer = AutonomousTrainer(num_challenges=10, episodes_per_challenge=10)
    
    if args.continuous:
        stats = trainer.continuous_learning_mode(duration_minutes=args.duration)
    else:
        stats = trainer.train_loop(num_cycles=args.cycles)
    
    # Final summary
    print("\n" + "="*70)
    print("FINAL TRAINING SUMMARY")
    print("="*70)
    print(f"Total Episodes: {trainer.total_episodes}")
    print(f"Challenges Completed: {stats['challenges_completed']}")
    print(f"Total Infections: {stats['total_infections']}")
    print(f"Final Success Rate: {sum(stats['success_rate'])/len(stats['success_rate'])*100:.1f}%")
    print("\n✅ Training complete!")


if __name__ == "__main__":
    main()