#!/usr/bin/env python3
"""
Vulnerable Services Simulator
Simula servicios vulnerables para testing sin necesidad de Docker
Uso: python simulate_services.py [start|stop]
"""

import socket
import threading
import time
import logging
import os
import sys
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Simulator')


class VulnerableService:
    """Base class para servicios simulados"""
    
    def __init__(self, name, port, ip='0.0.0.0'):
        self.name = name
        self.port = port
        self.ip = ip
        self.running = False
        self.thread = None
        self.socket = None
        
    def start(self):
        if self.running:
            logger.warning(f"{self.name} ya está corriendo")
            return
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.ip, self.port))
            self.socket.listen(5)
            self.socket.settimeout(1)
            
            self.running = True
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()
            
            logger.info(f"✓ {self.name} iniciado en puerto {self.port}")
        except Exception as e:
            logger.error(f"Error iniciando {self.name}: {e}")
    
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info(f"✓ {self.name} detenido")
    
    def _run(self):
        while self.running:
            try:
                client, addr = self.socket.accept()
                threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error en {self.name}: {e}")
    
    def handle_client(self, client, addr):
        """Override en subclasses"""
        pass


class SSHSimulator(VulnerableService):
    """Simulador de SSH con credenciales débiles"""
    
    def handle_client(self, client, addr):
        try:
            client.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu2\r\n")
            time.sleep(0.5)
            
            client.send(b"login: ")
            username = client.recv(1024).decode().strip()
            
            client.send(b"Password: ")
            password = client.recv(1024).decode().strip()
            
            # Credenciales débiles para testing
            weak_creds = [('root', 'password'), ('admin', 'admin'), ('user', 'user')]
            
            if (username, password) in weak_creds:
                client.send(b"Welcome to Ubuntu 20.04\r\n# ")
                logger.info(f"[SSH] Login exitoso: {username}:{password} desde {addr}")
            else:
                client.send(b"Login failed\r\n")
                logger.info(f"[SSH] Login fallido: {username}:{password} desde {addr}")
            
            client.close()
        except:
            pass


class FTPSimulator(VulnerableService):
    """Simulador de FTP con anonymous enabled"""
    
    def handle_client(self, client, addr):
        try:
            client.send(b"220 (vsFTPd 3.0.3)\r\n")
            
            while True:
                client.send(b"ftp> ")
                cmd = client.recv(1024).decode().strip().upper()
                
                if not cmd:
                    break
                elif cmd.startswith("USER"):
                    client.send(b"331 Please specify the password.\r\n")
                elif cmd.startswith("PASS"):
                    client.send(b"230 Login successful.\r\n")
                    logger.info(f"[FTP] Login exitoso desde {addr}")
                elif cmd.startswith("QUIT"):
                    client.send(b"221 Goodbye.\r\n")
                    break
                else:
                    client.send(b"530 Please login with USER and PASS.\r\n")
                    
            client.close()
        except:
            pass


class HTTPSimulator(VulnerableService):
    """Simulador de HTTP con directory listing"""
    
    def handle_client(self, client, addr):
        try:
            request = client.recv(4096).decode()
            
            if "GET" in request:
                response = """HTTP/1.1 200 OK
Server: Apache/2.4.41
Content-Type: text/html

<!DOCTYPE html>
<html>
<head><title>Test Server</title></head>
<body>
<h1>Welcome to Test Server</h1>
<p>Apache/2.4.41 (Ubuntu) Server at 192.168.100.16 Port 80</p>
</body>
</html>
"""
                client.send(response.encode())
                logger.info(f"[HTTP] GET request desde {addr}")
            
            client.close()
        except:
            pass


class TelnetSimulator(VulnerableService):
    """Simulador de Telnet"""
    
    def handle_client(self, client, addr):
        try:
            client.send(b"\r\nUbuntu 20.04 LTS\r\nlogin: ")
            username = client.recv(1024).decode().strip()
            
            client.send(b"Password: ")
            password = client.recv(1024).decode().strip()
            
            weak_creds = [('admin', 'admin'), ('root', 'root'), ('user', 'user')]
            
            if (username, password) in weak_creds:
                client.send(b"\r\nWelcome to Ubuntu 20.04\r\n$ ")
                logger.info(f"[Telnet] Login exitoso: {username}:{password}")
            else:
                client.send(b"Login incorrect\r\n")
            
            client.close()
        except:
            pass


class RedisSimulator(VulnerableService):
    """Simulador de Redis sin auth"""
    
    def handle_client(self, client, addr):
        try:
            client.send(b"+OK\r\n")
            data = client.recv(4096).decode()
            
            if "PING" in data:
                client.send(b"+PONG\r\n")
                logger.info(f"[Redis] PING desde {addr}")
            
            client.close()
        except:
            pass


class SMBSimulator(VulnerableService):
    """Simulador de SMB"""
    
    def __init__(self):
        super().__init__("SMB", 445)
    
    def _run(self):
        while self.running:
            try:
                client, addr = self.socket.accept()
                # SMB negotiation
                client.send(b"\x00\x00\x00\x10\xff\x53\x4d\x42\x72\x00\x00\x00\x00")
                logger.info(f"[SMB] Conexión desde {addr}")
                client.close()
            except socket.timeout:
                continue
            except:
                pass


class RDPSimulator(VulnerableService):
    """Simulador de RDP"""
    
    def __init__(self):
        super().__init__("RDP", 3389)
    
    def handle_client(self, client, addr):
        try:
            # RDP T.119 connection
            client.send(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00")
            logger.info(f"[RDP] Conexión desde {addr}")
            time.sleep(1)
            client.close()
        except:
            pass


class MockService(VulnerableService):
    """Servicio que solo acepta conexiones"""
    
    def __init__(self, name, port, banner):
        super().__init__(name, port)
        self.banner = banner
    
    def handle_client(self, client, addr):
        try:
            time.sleep(0.2)
            client.send(self.banner.encode())
            logger.info(f"[{self.name}] Conexión desde {addr}")
            time.sleep(0.5)
            client.close()
        except:
            pass


def start_all_services():
    """Inicia todos los servicios simulados"""
    
    services = [
        SSHSimulator("SSH", 2222, "0.0.0.0"),
        FTPSimulator("FTP", 2121, "0.0.0.0"),
        HTTPSimulator("HTTP", 8080, "0.0.0.0"),
        TelnetSimulator("Telnet", 2323, "0.0.0.0"),
        RedisSimulator("Redis", 6379, "0.0.0.0"),
        SMBSimulator(),
        RDPSimulator(),
        MockService("MySQL", 3306, "\x00\x00\x00\xffJ\x00\x00\x00\x000.8.0"),
        MockService("PostgreSQL", 5432, "PostgreSQL 14.5"),
        MockService("MongoDB", 27017, "MongoDB"),
    ]
    
    print("="*60)
    print("INICIANDO SERVICIOS SIMULADOS")
    print("="*60)
    print("\nDirecciones IPs asignadas:\n")
    
    base_ip = "192.168.100."
    ips = [f"{base_ip}{i+10}" for i in range(len(services))]
    
    for i, (service, ip) in enumerate(zip(services, ips)):
        print(f"  [{i+1}] {service.name:15} {ip}:{service.port}")
        service.start()
    
    print("\n" + "="*60)
    print("Credenciales de prueba:")
    print("  SSH/Telnet: admin:admin, root:root, user:user")
    print("  FTP: anonymous:anything")
    print("="*60)
    print("\nPresiona Ctrl+C para detener todos los servicios\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nDeteniendo servicios...")
        for service in services:
            service.stop()


def stop_all_services():
    """Detiene todos los servicios"""
    print("Los servicios simulados se detienen al salir del script")
    print("Ejecuta 'pkill -f simulate_services.py' si es necesario")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "stop":
        stop_all_services()
    else:
        start_all_services()