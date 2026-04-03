"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Nmap Integration Module
Professional network scanning using python-nmap
"""



import os
import sys
from typing import Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not installed: pip install python-nmap")


class NmapScanner:
    """
    Professional nmap-based scanner
    
    Features:
    - SYN stealth scan
    - Service version detection
    - OS detection
    - NSE script scanning
    - Vulnerability scanning
    - Output parsing
    """

    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None

    def scan_host(self, ip: str, ports: str = "1-1024",
                  arguments: str = "-sV -O -sC") -> Dict:
        """
        Scan a single host with nmap
        
        Args:
            ip: Target IP
            ports: Port range (e.g., "1-1024", "22,80,443")
            arguments: Nmap arguments
        
        Returns:
            Scan result dict
        """
        if not self.nm:
            return {'error': 'python-nmap not available'}

        try:
            self.nm.scan(ip, ports, arguments)

            if ip not in self.nm.all_hosts():
                return {'error': f'Host {ip} not found'}

            host = self.nm[ip]
            result = {
                'ip': ip,
                'hostname': host.hostname(),
                'status': host.state(),
                'open_ports': [],
                'services': {},
                'os_guess': '',
                'vulnerabilities': [],
            }

            for proto in host.all_protocols():
                ports_dict = host[proto]
                for port, port_info in ports_dict.items():
                    if port_info['state'] == 'open':
                        result['open_ports'].append(port)
                        service = port_info.get('name', 'unknown')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')

                        service_str = product
                        if version:
                            service_str += f" {version}"
                        elif service != 'unknown':
                            service_str += f" ({service})"

                        result['services'][str(port)] = service_str if service_str else service

            # OS detection
            if 'osmatch' in host:
                os_matches = host['osmatch']
                if os_matches:
                    result['os_guess'] = os_matches[0]['name']

            # NSE script results
            if 'hostscript' in host:
                for script in host['hostscript']:
                    result['vulnerabilities'].append({
                        'id': script.get('id', ''),
                        'output': script.get('output', ''),
                    })

            return result

        except Exception as e:
            logger.error(f"Nmap scan failed for {ip}: {e}")
            return {'error': str(e)}

    def scan_network(self, targets: str, ports: str = "1-1024",
                     arguments: str = "-sV -O") -> List[Dict]:
        """
        Scan network range
        
        Args:
            targets: CIDR or range (e.g., "192.168.1.0/24")
            ports: Port range
            arguments: Nmap arguments
        
        Returns:
            List of host results
        """
        if not self.nm:
            return [{'error': 'python-nmap not available'}]

        try:
            self.nm.scan(targets, ports, arguments)

            results = []
            for ip in self.nm.all_hosts():
                host = self.nm[ip]
                result = {
                    'ip': ip,
                    'hostname': host.hostname(),
                    'status': host.state(),
                    'open_ports': [],
                    'services': {},
                    'os_guess': '',
                }

                for proto in host.all_protocols():
                    for port, port_info in host[proto].items():
                        if port_info['state'] == 'open':
                            result['open_ports'].append(port)
                            service = port_info.get('name', 'unknown')
                            product = port_info.get('product', '')
                            version = port_info.get('version', '')
                            svc_str = f"{product} {version}".strip() if product or version else service
                            result['services'][str(port)] = svc_str

                if 'osmatch' in host and host['osmatch']:
                    result['os_guess'] = host['osmatch'][0]['name']

                results.append(result)

            return results

        except Exception as e:
            logger.error(f"Nmap network scan failed: {e}")
            return [{'error': str(e)}]

    def syn_scan(self, ip: str, ports: str = "1-1024") -> Dict:
        """SYN stealth scan"""
        return self.scan_host(ip, ports, "-sS -sV")

    def aggressive_scan(self, ip: str, ports: str = "1-65535") -> Dict:
        """Aggressive scan with all detections"""
        return self.scan_host(ip, ports, "-A -T4")

    def vuln_scan(self, ip: str, ports: str = "1-1024") -> Dict:
        """Vulnerability scan using NSE scripts"""
        return self.scan_host(ip, ports, "-sV --script vuln")

    def quick_scan(self, ip: str) -> Dict:
        """Quick scan of top 100 ports"""
        return self.scan_host(ip, "1-100", "-sV -F")
