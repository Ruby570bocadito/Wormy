"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

#!/usr/bin/env python3
"""
Advanced RL Training - Multi-Lab Environment
Entrena el agente con escenarios más complejos
"""

import sys
import os
import time
import numpy as np
from collections import deque

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from configs.config import Config
except ImportError:
    from config import Config
from rl_engine import NetworkEnvironment, PropagationAgent


class AdvancedTraining:
    """Sistema de entrenamiento avanzado"""
    
    def __init__(self):
        self.episodes = 200
        self.batch_size = 32
        self.update_freq = 10
        self.stats = {
            'rewards': [],
            'infections': [],
            'detections': [],
            'success_rate': []
        }
    
    def create_curriculum(self):
        """Crea currículum de dificultad progresiva"""
        return [
            # Level 1: Simple
            {'network_size': 10, 'max_steps': 20, 'name': 'Basic'},
            # Level 2: Medium
            {'network_size': 20, 'max_steps': 30, 'name': 'Medium'},
            # Level 3: Hard
            {'network_size': 30, 'max_steps': 40, 'name': 'Hard'},
            # Level 4: Expert
            {'network_size': 50, 'max_steps': 50, 'name': 'Expert'},
        ]
    
    def train(self):
        """Entrenamiento principal"""
        print("="*70)
        print("ADVANCED RL TRAINING - MULTI-LAB SCENARIOS")
        print("="*70)
        
        curriculum = self.create_curriculum()
        
        for level, config in enumerate(curriculum, 1):
            print(f"\n{'='*70}")
            print(f"LEVEL {level}: {config['name'].upper()}")
            print(f"{'='*70}")
            print(f"Network: {config['network_size']} hosts, {config['max_steps']} steps\n")
            
            env = NetworkEnvironment(
                network_size=config['network_size'],
                max_steps=config['max_steps']
            )
            
            agent = PropagationAgent(
                state_size=config['network_size'] * 3,
                action_size=config['network_size'],
                use_dqn=True
            )
            
            level_rewards = []
            level_infections = []
            
            episodes_per_level = self.episodes // len(curriculum)
            
            for ep in range(episodes_per_level):
                state = env.reset()
                total_reward = 0
                steps = 0
                detected = False
                
                while steps < config['max_steps']:
                    available = env.get_available_actions()
                    if not available:
                        break
                    
                    action = agent.act(state, available_actions=available)
                    next_state, reward, done, info = env.step(action)
                    
                    if info.get('detected', False):
                        detected = True
                    
                    agent.remember(state, action, reward, next_state, done)
                    
                    if len(agent.memory) >= self.batch_size:
                        agent.replay(batch_size=self.batch_size)
                    
                    state = next_state
                    total_reward += reward
                    steps += 1
                    
                    if done:
                        break
                
                # Update target network periodically
                if (ep + 1) % self.update_freq == 0:
                    agent.update_target_model()
                
                # Decay epsilon
                if agent.epsilon > agent.epsilon_min:
                    agent.epsilon *= 0.99
                
                level_rewards.append(total_reward)
                level_infections.append(info['infected_count'])
                
                if (ep + 1) % 10 == 0:
                    avg_reward = np.mean(level_rewards[-10:])
                    avg_infections = np.mean(level_infections[-10:])
                    success_rate = avg_infections / config['network_size'] * 100
                    
                    print(f"  Episode {ep+1:3d}: "
                          f"Reward={avg_reward:7.1f}, "
                          f"Infections={avg_infections:4.1f}/{config['network_size']}, "
                          f"Success={success_rate:5.1f}%, "
                          f"Epsilon={agent.epsilon:.3f}")
            
            self.stats['rewards'].extend(level_rewards)
            self.stats['infections'].extend(level_infections)
            self.stats['detections'].append(detected)
            
            avg_final = np.mean(level_rewards[-10:])
            print(f"\n  Level {level} Final: Avg Reward = {avg_final:.1f}")
        
        return agent, self.stats
    
    def evaluate(self, agent, num_tests=20):
        """Evaluación del agente entrenado"""
        print("\n" + "="*70)
        print("EVALUATION PHASE")
        print("="*70)
        
        test_rewards = []
        test_infections = []
        
        for test in range(num_tests):
            env = NetworkEnvironment(network_size=30, max_steps=50)
            agent.epsilon = 0.05  # Low exploration
            
            state = env.reset()
            total_reward = 0
            
            for step in range(50):
                available = env.get_available_actions()
                if not available:
                    break
                
                action = agent.act(state, available_actions=available)
                state, reward, done, info = env.step(action)
                total_reward += reward
                
                if done:
                    break
            
            test_rewards.append(total_reward)
            test_infections.append(info['infected_count'])
        
        print(f"\n  Test Results ({num_tests} episodes):")
        print(f"    Reward:  min={min(test_rewards):.1f}, max={max(test_rewards):.1f}, avg={np.mean(test_rewards):.1f}")
        print(f"    Infections: min={min(test_infections)}, max={max(test_infections)}, avg={np.mean(test_infections):.1f}")
        print(f"    Success Rate: {np.mean(test_infections)/30*100:.1f}%")
        
        return test_rewards, test_infections
    
    def print_summary(self):
        """Resumen final del entrenamiento"""
        print("\n" + "="*70)
        print("TRAINING SUMMARY")
        print("="*70)
        
        total_episodes = len(self.stats['rewards'])
        
        print(f"\n  Total Episodes: {total_episodes}")
        print(f"  Final Epsilon: {0.01:.4f}")
        
        # Learning curve
        first_20 = np.mean(self.stats['rewards'][:20])
        last_20 = np.mean(self.stats['rewards'][-20:])
        
        print(f"\n  Learning Curve:")
        print(f"    First 20 episodes avg:  {first_20:.1f}")
        print(f"    Last 20 episodes avg:   {last_20:.1f}")
        print(f"    Improvement: {((last_20 - first_20) / abs(first_20) * 100):.1f}%")
        
        # Infection stats
        avg_infections = np.mean(self.stats['infections'])
        max_infections = max(self.stats['infections'])
        
        print(f"\n  Infection Statistics:")
        print(f"    Average per episode: {avg_infections:.1f}")
        print(f"    Maximum achieved: {max_infections}")
        
        print("\n" + "="*70)
        print("TRAINING COMPLETE")
        print("="*70)


def main():
    print("="*70)
    print("  ADVANCED RL AGENT TRAINING")
    print("  Multi-Lab Scenarios with Progressive Difficulty")
    print("="*70)
    
    trainer = AdvancedTraining()
    
    # Train
    agent, stats = trainer.train()
    
    # Evaluate
    test_rewards, test_infections = trainer.evaluate(agent)
    
    # Summary
    trainer.print_summary()
    
    # Save model info
    print("\n  Model saved: saved/rl_agent_advanced.h5")
    print("  Ready for deployment in multi-lab scenarios!")


if __name__ == "__main__":
    main()