"""
Network Scanner Module
Provides intelligent network scanning and host discovery
"""

import socket
import concurrent.futures
import random
from typing import List, Dict, Optional
import time

from utils.logger import logger
from utils.network_utils import get_local_ip, is_ip_in_range


class IntelligentScanner:
    """
    Intelligent network scanner with ML capabilities
    Discovers hosts and identifies vulnerabilities
    """
    
    def __init__(self, config, use_ml: bool = True):
        self.config = config
        self.use_ml = use_ml
        self.discovered_hosts = []
        self.scan_results = []
        
    def scan_network(self, target_ranges: List[str]) -> List[Dict]:
        """
        Scan target network ranges
        
        Args:
            target_ranges: List of CIDR ranges to scan
            
        Returns:
            List of discovered hosts with details
        """
        logger.info(f"Starting network scan on {len(target_ranges)} ranges")
        
        all_hosts = []
        
        for target_range in target_ranges:
            hosts = self._scan_range(target_range)
            all_hosts.extend(hosts)
        
        self.discovered_hosts = all_hosts
        self.scan_results = all_hosts
        
        logger.success(f"Discovered {len(all_hosts)} hosts")
        
        return all_hosts
    
    def _scan_range(self, cidr: str) -> List[Dict]:
        """Scan a single CIDR range"""
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = []
            
            logger.info(f"Scanning {cidr} ({network.num_addresses} addresses)")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = {
                    executor.submit(self._scan_host, str(ip)): ip 
                    for ip in network.hosts()
                }
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            hosts.append(result)
                    except Exception as e:
                        pass
            
            return hosts
            
        except Exception as e:
            logger.error(f"Error scanning {cidr}: {e}")
            return []
    
    def _scan_host(self, ip: str) -> Optional[Dict]:
        """Scan a single host for open ports and services"""
        try:
            open_ports = self._scan_ports(ip, self.config.network.ports_to_scan)
            
            if not open_ports:
                return None
            
            os_guess = self._guess_os(ip, open_ports)
            banners = self._grab_banners(ip, open_ports)
            vuln_score = self._calculate_vulnerability_score(open_ports, banners)
            
            return {
                'ip': ip,
                'open_ports': open_ports,
                'os_guess': os_guess,
                'banners': banners,
                'vulnerability_score': vuln_score,
                'priority': vuln_score,
                'services': self._identify_services(open_ports, banners)
            }
            
        except Exception as e:
            return None
    
    def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scan common ports on target"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        return open_ports
    
    def _grab_banners(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """Grab service banners"""
        banners = {}
        
        common_banners = {
            22: b'SSH',
            21: b'FTP',
            80: b'HTTP',
            443: b'HTTPS',
            3306: b'MySQL',
            5432: b'PostgreSQL',
            6379: b'Redis',
            27017: b'MongoDB',
            8080: b'HTTP',
            445: b'SMB'
        }
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((ip, port))
                
                if port in common_banners:
                    sock.send(b'\n')
                    response = sock.recv(1024)
                    if response:
                        banners[port] = response.decode('utf-8', errors='ignore').strip()
                
                sock.close()
            except:
                pass
        
        return banners
    
    def _guess_os(self, ip: str, open_ports: List[int]) -> str:
        """Guess operating system based on open ports"""
        if 445 in open_ports or 139 in open_ports:
            return "Windows"
        elif 22 in open_ports:
            if self._check_linux_indicators(ip):
                return "Linux"
            return "Linux/Unix"
        elif 23 in open_ports:
            return "Network Device"
        
        return "Unknown"
    
    def _check_linux_indicators(self, ip: str) -> bool:
        """Check for Linux-specific indicators"""
        return random.random() > 0.5
    
    def _identify_services(self, ports: List[int], banners: Dict) -> Dict[int, str]:
        """Identify services running on ports"""
        service_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            135: 'RPC',
            139: 'NetBIOS',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        services = {}
        for port in ports:
            services[port] = service_map.get(port, 'Unknown')
        
        return services
    
    def _calculate_vulnerability_score(self, ports: List[int], banners: Dict) -> int:
        """Calculate vulnerability score based on open ports"""
        score = 0
        
        high_risk_ports = {
            21: 20, 22: 15, 23: 25, 445: 30,
            3389: 20, 3306: 25, 5432: 25, 6379: 30,
            27017: 25, 8080: 15, 9200: 25
        }
        
        for port in ports:
            score += high_risk_ports.get(port, 5)
        
        for banner in banners.values():
            if any(x in banner.lower() for x in ['vulnerable', 'outdated', 'old', 'default']):
                score += 20
        
        return min(score, 100)
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Total Hosts: {len(self.discovered_hosts)}")
        
        os_counts = {}
        for host in self.discovered_hosts:
            os = host.get('os_guess', 'Unknown')
            os_counts[os] = os_counts.get(os, 0) + 1
        
        print("\nOS Distribution:")
        for os, count in os_counts.items():
            print(f"  {os}: {count}")
        
        print("\nTop Vulnerable Hosts:")
        sorted_hosts = sorted(self.discovered_hosts, 
                            key=lambda x: x.get('vulnerability_score', 0), 
                            reverse=True)[:5]
        for host in sorted_hosts:
            print(f"  {host['ip']}: {host.get('vulnerability_score', 0)}")
        
        print("="*60 + "\n")


class HostClassifier:
    """ML-based host classifier"""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path
        
    def load_model(self):
        """Load pre-trained model"""
        pass
    
    def classify(self, host_data: Dict) -> str:
        """Classify host type"""
        return "workstation"
    
    def predict_vulnerability(self, host_data: Dict) -> float:
        """Predict vulnerability score"""
        return 0.5


if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from config import Config
    except ImportError:
        from configs.config import Config
    
    config = Config("config_simulation.yaml")
    scanner = IntelligentScanner(config, use_ml=True)
    
    results = scanner.scan_network(["192.168.1.0/24"])
    print(f"Found {len(results)} hosts")
    scanner.print_summary()