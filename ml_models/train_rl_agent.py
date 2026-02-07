"""
Train RL Agent for Network Propagation
Trains DQN agent in simulated environment
"""

import sys
import os
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rl_engine.environment import NetworkEnvironment
from rl_engine.propagation_agent import PropagationAgent


def train_agent(episodes: int = 1000, network_size: int = 20, save_path: str = "saved/rl_agent.zip"):
    """
    Train RL agent in simulated environment
    
    Args:
        episodes: Number of training episodes
        network_size: Size of simulated network
        save_path: Path to save trained model
    """
    print("="*60)
    print("RL AGENT TRAINING")
    print("="*60)
    print(f"Episodes: {episodes}")
    print(f"Network Size: {network_size}")
    print(f"Save Path: {save_path}")
    print("="*60 + "\n")
    
    # Create environment
    env = NetworkEnvironment(network_size=network_size, max_steps=100)
    
    # Create agent
    state_size = network_size * 3
    action_size = network_size
    agent = PropagationAgent(state_size, action_size, use_dqn=True)
    
    # Training metrics
    rewards_history = []
    infections_history = []
    detection_history = []
    epsilon_history = []
    
    # Training loop
    for episode in range(episodes):
        state = env.reset()
        total_reward = 0
        done = False
        step = 0
        
        while not done:
            # Get available targets
            available = env.get_available_targets()
            
            # Select action
            if available:
                action = agent.act(state, available_actions=available)
            else:
                action = agent.act(state)
            
            # Execute action
            next_state, reward, done, info = env.step(action)
            
            # Store experience
            agent.remember(state, action, reward, next_state, done)
            
            # Train agent
            agent.replay()
            
            state = next_state
            total_reward += reward
            step += 1
        
        # Record metrics
        rewards_history.append(total_reward)
        infections_history.append(info['infected_count'])
        detection_history.append(1 if env.detected else 0)
        epsilon_history.append(agent.epsilon)
        
        # Update target network every 10 episodes
        if episode % 10 == 0:
            agent.update_target_model()
        
        # Print progress
        if episode % 50 == 0:
            avg_reward = np.mean(rewards_history[-50:]) if len(rewards_history) >= 50 else np.mean(rewards_history)
            avg_infections = np.mean(infections_history[-50:]) if len(infections_history) >= 50 else np.mean(infections_history)
            detection_rate = np.mean(detection_history[-50:]) if len(detection_history) >= 50 else np.mean(detection_history)
            
            print(f"Episode {episode}/{episodes}")
            print(f"  Avg Reward (50): {avg_reward:.2f}")
            print(f"  Avg Infections (50): {avg_infections:.1f}/{network_size}")
            print(f"  Detection Rate (50): {detection_rate*100:.1f}%")
            print(f"  Epsilon: {agent.epsilon:.3f}")
            print(f"  Memory Size: {len(agent.memory)}")
            print()
    
    # Save trained model
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    agent.save(save_path)
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    print(f"Model saved to: {save_path}")
    print(f"Final epsilon: {agent.epsilon:.3f}")
    print(f"Final avg reward: {np.mean(rewards_history[-100:]):.2f}")
    print(f"Final avg infections: {np.mean(infections_history[-100:]):.1f}/{network_size}")
    print("="*60 + "\n")
    
    # Plot training metrics
    plot_training_metrics(rewards_history, infections_history, detection_history, epsilon_history)
    
    return agent


def plot_training_metrics(rewards, infections, detections, epsilons):
    """Plot training metrics"""
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    # Rewards
    axes[0, 0].plot(rewards, alpha=0.3, label='Raw')
    axes[0, 0].plot(moving_average(rewards, 50), label='MA(50)')
    axes[0, 0].set_title('Total Reward per Episode')
    axes[0, 0].set_xlabel('Episode')
    axes[0, 0].set_ylabel('Reward')
    axes[0, 0].legend()
    axes[0, 0].grid(True)
    
    # Infections
    axes[0, 1].plot(infections, alpha=0.3, label='Raw')
    axes[0, 1].plot(moving_average(infections, 50), label='MA(50)')
    axes[0, 1].set_title('Infections per Episode')
    axes[0, 1].set_xlabel('Episode')
    axes[0, 1].set_ylabel('Infected Hosts')
    axes[0, 1].legend()
    axes[0, 1].grid(True)
    
    # Detection Rate
    detection_rate = [np.mean(detections[max(0, i-50):i+1]) for i in range(len(detections))]
    axes[1, 0].plot(detection_rate)
    axes[1, 0].set_title('Detection Rate (MA 50)')
    axes[1, 0].set_xlabel('Episode')
    axes[1, 0].set_ylabel('Detection Rate')
    axes[1, 0].grid(True)
    
    # Epsilon
    axes[1, 1].plot(epsilons)
    axes[1, 1].set_title('Exploration Rate (Epsilon)')
    axes[1, 1].set_xlabel('Episode')
    axes[1, 1].set_ylabel('Epsilon')
    axes[1, 1].grid(True)
    
    plt.tight_layout()
    
    # Save plot
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    plot_path = f"saved/training_metrics_{timestamp}.png"
    os.makedirs("saved", exist_ok=True)
    plt.savefig(plot_path)
    print(f"Training metrics plot saved to: {plot_path}")
    
    plt.show()


def moving_average(data, window):
    """Calculate moving average"""
    if len(data) < window:
        return data
    
    ma = []
    for i in range(len(data)):
        if i < window:
            ma.append(np.mean(data[:i+1]))
        else:
            ma.append(np.mean(data[i-window+1:i+1]))
    
    return ma


def evaluate_agent(agent_path: str, episodes: int = 100, network_size: int = 20):
    """
    Evaluate trained agent
    
    Args:
        agent_path: Path to saved agent
        episodes: Number of evaluation episodes
        network_size: Size of test network
    """
    print("\n" + "="*60)
    print("AGENT EVALUATION")
    print("="*60)
    
    # Create environment
    env = NetworkEnvironment(network_size=network_size, max_steps=100)
    
    # Load agent
    state_size = network_size * 3
    action_size = network_size
    agent = PropagationAgent(state_size, action_size, use_dqn=True)
    agent.load(agent_path)
    
    # Disable exploration for evaluation
    agent.epsilon = 0.0
    
    # Evaluation metrics
    total_rewards = []
    total_infections = []
    total_detections = 0
    
    for episode in range(episodes):
        state = env.reset()
        done = False
        episode_reward = 0
        
        while not done:
            available = env.get_available_targets()
            action = agent.act(state, available_actions=available)
            next_state, reward, done, info = env.step(action)
            
            state = next_state
            episode_reward += reward
        
        total_rewards.append(episode_reward)
        total_infections.append(info['infected_count'])
        if env.detected:
            total_detections += 1
    
    # Print results
    print(f"\nEvaluation Results ({episodes} episodes):")
    print(f"  Avg Reward: {np.mean(total_rewards):.2f} ± {np.std(total_rewards):.2f}")
    print(f"  Avg Infections: {np.mean(total_infections):.1f} ± {np.std(total_infections):.1f}")
    print(f"  Detection Rate: {total_detections/episodes*100:.1f}%")
    print(f"  Coverage: {np.mean(total_infections)/network_size*100:.1f}%")
    print("="*60 + "\n")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Train RL Agent")
    parser.add_argument('--episodes', type=int, default=1000, help='Number of training episodes')
    parser.add_argument('--network-size', type=int, default=20, help='Size of simulated network')
    parser.add_argument('--save-path', type=str, default='saved/rl_agent.h5', help='Path to save model')
    parser.add_argument('--evaluate', type=str, help='Path to agent to evaluate')
    parser.add_argument('--eval-episodes', type=int, default=100, help='Number of evaluation episodes')
    
    args = parser.parse_args()
    
    if args.evaluate:
        # Evaluate existing agent
        evaluate_agent(args.evaluate, args.eval_episodes, args.network_size)
    else:
        # Train new agent
        agent = train_agent(args.episodes, args.network_size, args.save_path)
        
        # Evaluate trained agent
        print("\nEvaluating trained agent...")
        evaluate_agent(args.save_path, args.eval_episodes, args.network_size)
