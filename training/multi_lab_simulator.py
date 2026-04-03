#!/usr/bin/env python3
"""
Advanced Multi-Lab Simulator
Simula múltiples laboratorios para testing avanzado
"""

import socket
import threading
import time
import random
import logging
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('MultiLab')


class LabHost:
    """Simula un host en un laboratorio"""
    
    def __init__(self, ip: str, name: str, os: str, services: Dict[int, str]):
        self.ip = ip
        self.name = name
        self.os = os
        self.services = services  # {port: service_name}
        self.vulnerable = True
        self.credentials = self._generate_creds()
    
    def _generate_creds(self) -> List[tuple]:
        """Genera credenciales débiles para testing"""
        return [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('root', 'password'),
            ('user', 'user'),
            ('test', 'test'),
        ]


class MultiLabSimulator:
    """
    Simulador de múltiples laboratorios
    """
    
    def __init__(self):
        self.labs = {}
        self.services = []
        
    def add_lab(self, name: str, hosts: List[LabHost]):
        """Añade un laboratorio"""
        self.labs[name] = hosts
        logger.info(f"Lab '{name}' added with {len(hosts)} hosts")
    
    def start_all(self):
        """Inicia todos los servicios simulados"""
        print("="*70)
        print("STARTING MULTI-LAB ENVIRONMENT")
        print("="*70)
        
        for lab_name, hosts in self.labs.items():
            print(f"\n[{lab_name}]")
            for host in hosts:
                port = list(host.services.keys())[0] if host.services else 8000
                logger.info(f"  Starting {host.name} at {host.ip}:{port}")
        
        # Start network listeners
        self._start_listeners()
        
        print("\n" + "="*70)
        print("LAB SUMMARY")
        print("="*70)
        
        total_services = sum(len(h.services) for h in sum(self.labs.values(), []))
        print(f"Total Labs: {len(self.labs)}")
        print(f"Total Hosts: {sum(len(h) for h in self.labs.values())}")
        print(f"Total Services: {total_services}")
        
    def _start_listeners(self):
        """Inicia listeners para servicios clave"""
        # Simple listener for demo purposes
        pass


def create_all_labs() -> MultiLabSimulator:
    """Crea todos los laboratorios"""
    
    simulator = MultiLabSimulator()
    
    # Lab 1: Web Servers
    web_hosts = [
        LabHost('192.168.100.10', 'apache-web-1', 'Linux', {80: 'HTTP', 443: 'HTTPS', 22: 'SSH'}),
        LabHost('192.168.100.11', 'nginx-web-1', 'Linux', {80: 'HTTP', 22: 'SSH', 8080: 'HTTP-Alt'}),
        LabHost('192.168.100.12', 'tomcat-server', 'Linux', {8080: 'HTTP', 8009: 'AJP', 22: 'SSH'}),
    ]
    simulator.add_lab("Web Servers", web_hosts)
    
    # Lab 2: Databases
    db_hosts = [
        LabHost('192.168.100.20', 'mysql-primary', 'Linux', {3306: 'MySQL', 22: 'SSH'}),
        LabHost('192.168.100.21', 'postgres-server', 'Linux', {5432: 'PostgreSQL', 22: 'SSH'}),
        LabHost('192.168.100.22', 'mongodb-prod', 'Linux', {27017: 'MongoDB', 22: 'SSH'}),
        LabHost('192.168.100.23', 'redis-cache', 'Linux', {6379: 'Redis', 22: 'SSH'}),
    ]
    simulator.add_lab("Databases", db_hosts)
    
    # Lab 3: DevOps
    dev_hosts = [
        LabHost('192.168.100.30', 'jenkins-master', 'Linux', {8080: 'HTTP', 22: 'SSH'}),
        LabHost('192.168.100.31', 'gitlab-ee', 'Linux', {22: 'SSH', 80: 'HTTP'}),
        LabHost('192.168.100.32', 'nexus-repository', 'Linux', {8081: 'HTTP', 22: 'SSH'}),
    ]
    simulator.add_lab("DevOps", dev_hosts)
    
    # Lab 4: Infrastructure
    infra_hosts = [
        LabHost('192.168.100.40', 'docker-registry', 'Linux', {5000: 'Docker', 22: 'SSH'}),
        LabHost('192.168.100.41', 'k8s-master', 'Linux', {6443: 'Kubernetes', 22: 'SSH'}),
        LabHost('192.168.100.42', 'rabbitmq-node', 'Linux', {5672: 'AMQP', 15672: 'HTTP'}),
    ]
    simulator.add_lab("Infrastructure", infra_hosts)
    
    # Lab 5: Vulnerable Apps
    vuln_hosts = [
        LabHost('192.168.100.50', 'dvwa-pentest', 'Linux', {80: 'HTTP'}),
        LabHost('192.168.100.51', 'juice-shop', 'Linux', {3000: 'HTTP', 22: 'SSH'}),
        LabHost('192.168.100.52', 'webgoat', 'Linux', {8080: 'HTTP'}),
    ]
    simulator.add_lab("Vulnerable Apps", vuln_hosts)
    
    # Lab 6: Windows Targets (Simulation)
    win_hosts = [
        LabHost('192.168.100.60', 'win-server-2019', 'Windows', {445: 'SMB', 3389: 'RDP', 80: 'HTTP'}),
        LabHost('192.168.100.61', 'win-workstation', 'Windows', {445: 'SMB', 3389: 'RDP'}),
    ]
    simulator.add_lab("Windows Targets", win_hosts)
    
    return simulator


if __name__ == "__main__":
    labs = create_all_labs()
    labs.start_all()
    
    print("\n" + "="*70)
    print("LAB NETWORK MAP")
    print("="*70)
    
    for lab_name, hosts in labs.labs.items():
        print(f"\n{lab_name}:")
        for host in hosts:
            services = ', '.join([f"{p}/{s}" for p, s in host.services.items()])
            print(f"  {host.ip:18} {host.name:20} ({host.os}) [{services}]")