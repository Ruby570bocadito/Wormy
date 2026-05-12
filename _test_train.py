import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
print("path added", flush=True)
sys.stdout.flush()

from rl_engine import NetworkEnvironment, PropagationAgent
print("imports ok", flush=True)

env = NetworkEnvironment(network_size=5, max_steps=10)
state = env.reset()
print(f"state size: {len(state)}", flush=True)

agent = PropagationAgent(state_size=5*15, action_size=5, use_dqn=True)
print(f"agent created, q_network={agent.q_network}", flush=True)

action = agent.act(state)
print(f"action: {action}", flush=True)

next_state, reward, done, info = env.step(action)
print(f"done: {done}, reward: {reward}", flush=True)
print("ALL OK", flush=True)
