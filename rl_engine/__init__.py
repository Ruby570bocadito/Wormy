"""
RL Engine - Reinforcement Learning for Network Propagation
Implements DQN agent for intelligent target selection
"""

import random
import numpy as np
from collections import deque
from typing import List, Dict, Optional, Tuple


class PropagationAgent:
    """
    DQN Agent for network propagation
    Learns optimal target selection strategy
    """
    
    def __init__(self, state_size: int, action_size: int, use_dqn: bool = True):
        self.state_size = state_size
        self.action_size = action_size
        self.use_dqn = use_dqn
        
        self.memory = deque(maxlen=10000)
        self.gamma = 0.95
        self.epsilon = 1.0
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        
        self.q_network = None
        self.target_network = None
        
        self._build_model()
    
    def _build_model(self):
        """Build neural network for Q-learning"""
        try:
            import tensorflow as tf
            from tensorflow import keras
            from tensorflow.keras import layers
            
            model = keras.Sequential([
                layers.Dense(64, activation='relu', input_shape=(self.state_size,)),
                layers.Dense(64, activation='relu'),
                layers.Dense(32, activation='relu'),
                layers.Dense(self.action_size, activation='linear')
            ])
            
            model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
                loss='mse'
            )
            
            self.q_network = model
            self.target_network = keras.models.clone_model(model)
            self.target_network.build()
            
        except ImportError:
            try:
                import torch
                import torch.nn as nn
                import torch.optim as optim
                
                class DQNNetwork(nn.Module):
                    def __init__(self, state_size, action_size):
                        super().__init__()
                        self.fc = nn.Sequential(
                            nn.Linear(state_size, 64),
                            nn.ReLU(),
                            nn.Linear(64, 64),
                            nn.ReLU(),
                            nn.Linear(64, 32),
                            nn.ReLU(),
                            nn.Linear(32, action_size)
                        )
                    
                    def forward(self, x):
                        return self.fc(x)
                
                self.q_network = DQNNetwork(self.state_size, self.action_size)
                self.target_network = DQNNetwork(self.state_size, self.action_size)
                self.target_network.load_state_dict(self.q_network.state_dict())
                self.optimizer = optim.Adam(self.q_network.parameters(), lr=self.learning_rate)
                self.criterion = nn.MSELoss()
                self.use_torch = True
                self._torch = torch
                
            except ImportError:
                self.q_network = None
                self.target_network = None
    
    def act(self, state: List[float], available_actions: List[int] = None) -> int:
        """
        Choose action using epsilon-greedy policy
        
        Args:
            state: Current state representation
            available_actions: List of valid action indices
            
        Returns:
            Selected action index
        """
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
            return max(available_actions, key=lambda x: state[x] if x < len(state) else 0)
        
        return 0
    
    def remember(self, state, action, reward, next_state, done):
        """Store experience in replay memory"""
        self.memory.append((state, action, reward, next_state, done))
    
    def replay(self, batch_size: int = 32):
        """Train on batch of experiences"""
        if len(self.memory) < batch_size or self.q_network is None:
            return
        
        batch = random.sample(self.memory, batch_size)
        
        states = np.array([exp[0] for exp in batch])
        next_states = np.array([exp[3] for exp in batch])
        
        if hasattr(self, 'use_torch') and self.use_torch:
            states_tensor = self._torch.FloatTensor(states)
            next_states_tensor = self._torch.FloatTensor(next_states)
            
            with self._torch.no_grad():
                next_q = self.target_network(next_states_tensor).detach().numpy()
            
            current_q = self.q_network(states_tensor).detach().numpy()
            
            for i, (state, action, reward, next_state, done) in enumerate(batch):
                if done:
                    current_q[i][action] = reward
                else:
                    current_q[i][action] = reward + self.gamma * np.max(next_q[i])
            
            self.optimizer.zero_grad()
            output = self.q_network(states_tensor)
            loss = self.criterion(output, self._torch.FloatTensor(current_q))
            loss.backward()
            self.optimizer.step()
        else:
            current_q = self.q_network.predict(states, verbose=0)
            next_q = self.target_network.predict(next_states, verbose=0)
            
            for i, (state, action, reward, next_state, done) in enumerate(batch):
                if done:
                    current_q[i][action] = reward
                else:
                    current_q[i][action] = reward + self.gamma * np.max(next_q[i])
            
            self.q_network.fit(states, current_q, epochs=1, verbose=0)
        
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
    
    def update_target_model(self):
        """Update target network weights"""
        if self.target_network is not None and self.q_network is not None:
            if hasattr(self, 'use_torch') and self.use_torch:
                self.target_network.load_state_dict(self.q_network.state_dict())
            else:
                self.target_network.set_weights(self.q_network.get_weights())
    
    def save(self, path: str):
        """Save trained model"""
        if self.q_network is not None:
            if hasattr(self, 'use_torch') and self.use_torch:
                self._torch.save(self.q_network.state_dict(), path)
            else:
                self.q_network.save(path)
    
    def load(self, path: str):
        """Load trained model"""
        if self.q_network is not None:
            if hasattr(self, 'use_torch') and self.use_torch:
                self.q_network.load_state_dict(self._torch.load(path))
            else:
                self.q_network.load_weights(path)


class NetworkEnvironment:
    """
    Simulated network environment for RL training
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
        """Generate simulated network"""
        for i in range(self.network_size):
            host = {
                'id': i,
                'ip': f'192.168.1.{i+10}',
                'vulnerability': random.randint(20, 100),
                'difficulty': random.randint(1, 10),
                'reachable': random.random() > 0.2
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
        """Get current state representation"""
        state = []
        
        for host in self.hosts:
            state.extend([
                host['vulnerability'] / 100.0,
                host['difficulty'] / 10.0,
                1.0 if host.get('infected', False) else 0.0
            ])
        
        while len(state) < self.network_size * 3:
            state.append(0.0)
        
        return np.array(state[:self.network_size * 3])
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict]:
        """Execute action and return result"""
        self.current_step += 1
        
        if action >= len(self.hosts):
            return self._get_state(), -1, True, {'infected_count': len(self.infected)}
        
        target = self.hosts[action]
        
        if target.get('infected', False):
            return self._get_state(), -2, False, {'infected_count': len(self.infected)}
        
        success_prob = (target['vulnerability'] / 100.0) * (1 - target['difficulty'] / 20.0)
        
        if random.random() < success_prob:
            target['infected'] = True
            self.infected.append(action)
            reward = 10 + target['vulnerability'] / 5
            
            if random.random() < 0.1:
                self.detected = True
                reward -= 5
        else:
            reward = -5
        
        done = self.current_step >= self.max_steps or len(self.infected) >= self.network_size
        
        return self._get_state(), reward, done, {
            'infected_count': len(self.infected),
            'detected': self.detected
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
        """Build state representation from targets"""
        state = []
        
        for target in targets[:self.action_size]:
            state.extend([
                target.get('vulnerability_score', 50) / 100.0,
                len(target.get('open_ports', [])) / 20.0,
                1.0 if target.get('os_guess') == 'Windows' else 0.0
            ])
        
        while len(state) < self.action_size * 3:
            state.append(0.0)
        
        return state[:self.action_size * 3]
    
    def provide_feedback(self, target: Dict, success: bool, reward: float):
        """Provide feedback to agent for learning"""
        pass


if __name__ == "__main__":
    env = NetworkEnvironment(network_size=20, max_steps=100)
    agent = PropagationAgent(state_size=60, action_size=20, use_dqn=True)
    
    print("Testing RL Agent...")
    
    for episode in range(3):
        state = env.reset()
        total_reward = 0
        
        for step in range(10):
            available = env.get_available_actions()
            action = agent.act(state, available_actions=available)
            next_state, reward, done, info = env.step(action)
            
            agent.remember(state, action, reward, next_state, done)
            agent.replay(batch_size=8)
            
            state = next_state
            total_reward += reward
            
            if done:
                break
        
        print(f"Episode {episode + 1}: Reward = {total_reward}, Infected = {info['infected_count']}")
    
    print("RL Agent test complete")