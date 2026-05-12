"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

#!/usr/bin/env python3
"""
Vulnerable Services Simulator
Simula servicios vulnerables para testing sin necesidad de Docker.
Cubre los ~50 servicios / ~80 puertos que el worm ataca.
Uso: python simulate_services.py [start|stop]
"""

import socket
import threading
import time
import logging
import os
import sys
import struct
import json
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Simulator')


# =============================================================================
# Base class
# =============================================================================

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
            logger.warning(f"{self.name} ya esta corriendo")
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
            logger.info(f"[OK] {self.name} iniciado en puerto {self.port}")
        except Exception as e:
            logger.error(f"Error iniciando {self.name}: {e}")

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info(f"[OK] {self.name} detenido")

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
        client.close()


# =============================================================================
# SSH  (port 22)
# =============================================================================

class SSHSimulator(VulnerableService):
    """Simulador de SSH - credenciales debiles del modulo ssh_exploit"""

    VALID_CREDS = [
        ('root', 'root'), ('root', 'toor'), ('root', 'password'), ('root', ''),
        ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
        ('user', 'user'), ('test', 'test'), ('guest', 'guest'),
        ('ubuntu', 'ubuntu'), ('pi', 'raspberry'),
        ('deploy', 'deploy'), ('jenkins', 'jenkins'), ('git', 'git'),
        ('vagrant', 'vagrant'), ('ansible', 'ansible'),
    ]

    def handle_client(self, client, addr):
        try:
            client.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu2\r\n")
            time.sleep(0.3)
            client.send(b"login: ")
            username = client.recv(1024).decode().strip()
            client.send(b"Password: ")
            password = client.recv(1024).decode().strip()

            if (username, password) in self.VALID_CREDS:
                client.send(b"Welcome to Ubuntu 20.04 LTS\r\n# ")
                logger.info(f"[SSH] Login exitoso: {username}:{password} desde {addr}")
            else:
                client.send(b"Login failed\r\n")
                logger.info(f"[SSH] Login fallido: {username}:{password} desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# FTP  (ports 21, 2121)
# =============================================================================

class FTPSimulator(VulnerableService):
    """Simulador de FTP - credenciales del modulo ftp_exploit"""

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
        except Exception:
            pass


# =============================================================================
# HTTP / HTTPS  (ports 80, 443, 8080, 8443)
# =============================================================================

class HTTPSimulator(VulnerableService):
    """Simulador HTTP - banners de Apache/Nginx + admin panels"""

    def handle_client(self, client, addr):
        try:
            request = client.recv(4096).decode(errors='replace')
            path = '/'
            if 'GET ' in request:
                parts = request.split(' ')
                if len(parts) > 1:
                    path = parts[1]

            server_header = "Apache/2.4.41 (Ubuntu)"
            if self.port in (443, 8443):
                server_header = "nginx/1.18.0"

            body = self._generate_body(path, server_header)
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Server: {server_header}\r\n"
                f"Content-Type: text/html; charset=UTF-8\r\n"
                f"Content-Length: {len(body.encode())}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )
            client.send(response.encode())
            logger.info(f"[HTTP] {path} desde {addr}")
            client.close()
        except Exception:
            pass

    def _generate_body(self, path, server):
        pl = path.lower()
        if 'manager/html' in pl or 'tomcat' in pl:
            return "<html><body><h1>Apache Tomcat/9.0.50</h1><p>Manager app</p></body></html>"
        if 'jenkins' in pl:
            return '<html><head><script>/* Jenkins */</script></head><body><h1>Jenkins</h1></body></html>'
        if 'confluence' in pl or 'wiki' in pl:
            return '<html><body><h1>Confluence</h1><p>Atlassian Confluence</p></body></html>'
        if 'jira' in pl:
            return '<html><body><h1>Jira</h1><p>Atlassian Jira Software</p></body></html>'
        if 'gitlab' in pl or 'git' in pl:
            return '<html><body><h1>GitLab</h1><p>GitLab Community Edition</p></body></html>'
        if 'owa' in pl or 'exchange' in pl or 'autodiscover' in pl:
            return '<html><body><h1>Outlook Web App</h1><p>Microsoft Exchange Server 2019</p></body></html>'
        if 'weblogic' in pl or 'console' in pl:
            return '<html><body><h1>WebLogic Server</h1><p>Oracle WebLogic Server 12.2.1.4.0</p></body></html>'
        if 'citrix' in pl or 'vpn' in pl:
            return '<html><body><h1>Citrix Gateway</h1><p>Citrix NetScaler</p></body></html>'
        if 'wp-' in pl or 'wordpress' in pl:
            return '<html><body><h1>WordPress Site</h1><p>Just another WordPress site</p></body></html>'
        if 'phpmyadmin' in pl:
            return '<html><body><h1>phpMyAdmin</h1><p>Welcome to phpMyAdmin</p></body></html>'
        if 'nagios' in pl:
            return '<html><body><h1>Nagios Core</h1><p>Monitoring</p></body></html>'
        return (
            f"<!DOCTYPE html><html><head><title>Test Server</title></head><body>"
            f"<h1>Welcome to Test Server</h1>"
            f"<p>{server} Server at port {self.port}</p>"
            f"</body></html>"
        )


# =============================================================================
# Telnet  (ports 23, 2323)
# =============================================================================

class TelnetSimulator(VulnerableService):
    """Simulador de Telnet - credenciales del modulo telnet_exploit"""

    VALID_CREDS = [
        ('admin', 'admin'), ('root', 'root'), ('admin', 'password'),
        ('admin', ''), ('', ''), ('cisco', 'cisco'),
        ('admin', '1234'), ('user', 'user'),
    ]

    def handle_client(self, client, addr):
        try:
            client.send(b"\r\nUbuntu 20.04 LTS\r\nlogin: ")
            username = client.recv(1024).decode().strip()
            client.send(b"Password: ")
            password = client.recv(1024).decode().strip()
            if (username, password) in self.VALID_CREDS:
                client.send(b"\r\nWelcome to Ubuntu 20.04\r\n$ ")
                logger.info(f"[Telnet] Login exitoso: {username}:{password}")
            else:
                client.send(b"Login incorrect\r\n")
            client.close()
        except Exception:
            pass


# =============================================================================
# Redis  (port 6379)
# =============================================================================

class RedisSimulator(VulnerableService):
    """Simulador de Redis - sin auth, o con AUTH redis123"""

    def handle_client(self, client, addr):
        try:
            client.send(b"+OK\r\n")
            data = client.recv(4096).decode(errors='replace')
            cmd = data.strip().upper()
            if cmd.startswith('PING'):
                client.send(b"+PONG\r\n")
                logger.info(f"[Redis] PING desde {addr}")
            elif cmd.startswith('AUTH'):
                client.send(b"+OK\r\n")
                logger.info(f"[Redis] AUTH desde {addr}")
            elif cmd.startswith('INFO'):
                info = "# Server\r\nredis_version:7.0.0\r\nos:Linux\r\n# Keyspace\r\ndb0:keys=100,expires=0\r\n"
                client.send(f"${len(info)}\r\n{info}\r\n".encode())
            elif cmd.startswith('CONFIG'):
                client.send(b"+OK\r\n")
            elif cmd.startswith('SET') or cmd.startswith('GET'):
                client.send(b"+OK\r\n")
            else:
                client.send(b"+OK\r\n")
            client.close()
        except Exception:
            pass


# =============================================================================
# SMB  (ports 139, 445)
# =============================================================================

class SMBSimulator(VulnerableService):
    """Simulador de SMB - null session + autenticacion basica"""

    def __init__(self, port=445):
        super().__init__("SMB", port)

    def handle_client(self, client, addr):
        try:
            client.send(b"\x00\x00\x00\x10\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            client.send(b"SMB negotiated: Windows Server 2022\r\n")
            logger.info(f"[SMB] Conexion desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# RDP  (port 3389)
# =============================================================================

class RDPSimulator(VulnerableService):
    """Simulador de RDP - T.119 connection response"""

    def __init__(self):
        super().__init__("RDP", 3389)

    def handle_client(self, client, addr):
        try:
            client.send(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00")
            time.sleep(0.5)
            logger.info(f"[RDP] Conexion desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# MySQL  (port 3306)
# =============================================================================

class MySQLSimulator(VulnerableService):
    """Simulador de MySQL - handshake + credenciales comunes"""

    def __init__(self):
        super().__init__("MySQL", 3306)

    def handle_client(self, client, addr):
        try:
            handshake = (
                b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x32\x00"
                b"\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            client.send(handshake)
            time.sleep(0.2)
            client.recv(4096)
            ok_packet = b"\x00\x00\x00\x02\x00\x00\x00"
            client.send(ok_packet)
            logger.info(f"[MySQL] Conexion desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# PostgreSQL  (port 5432)
# =============================================================================

class PostgreSQLSimulator(VulnerableService):
    """Simulador de PostgreSQL"""

    def __init__(self):
        super().__init__("PostgreSQL", 5432)

    def handle_client(self, client, addr):
        try:
            client.send(b"PostgreSQL 14.5\r\n")
            time.sleep(0.2)
            client.recv(4096)
            client.send(b"Authentication succeeded\r\n")
            logger.info(f"[PostgreSQL] Conexion desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# MongoDB  (ports 27017, 27018, 27019)
# =============================================================================

class MongoDB(VulnerableService):
    """Simulador de MongoDB - sin auth por defecto"""

    def __init__(self, name="MongoDB", port=27017, ip="0.0.0.0"):
        super().__init__(name, port, ip)

    def handle_client(self, client, addr):
        try:
            client.send(b"\x00" * 36)
            time.sleep(0.2)
            client.recv(4096)
            client.send(b'MongoDB 6.0\r\n')
            logger.info(f"[MongoDB] Conexion desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# VNC  (ports 5900-5903)
# =============================================================================

class VNCSimulator(VulnerableService):
    """Simulador de VNC - RFB protocol"""

    def handle_client(self, client, addr):
        try:
            client.send(b"RFB 003.008\n")
            time.sleep(0.2)
            client.recv(4096)
            client.send(b"\x02\x01\x02")
            time.sleep(0.2)
            sec_type = client.recv(1)
            if sec_type == b'\x01':
                client.send(b"\x00\x00\x00\x00")
                client.recv(1)
                client.send(b"\x00\x00\x04\x00\x00\x00\x03\x00"
                            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                            b"\x00\x00\x00\x0c" + b"Test Desktop")
                logger.info(f"[VNC] No-auth desde {addr}")
            elif sec_type == b'\x02':
                challenge = bytes(range(16))
                client.send(challenge)
                time.sleep(0.3)
                client.recv(16)
                client.send(b"\x00\x00\x00\x00")
                logger.info(f"[VNC] Auth desde {addr}")
            else:
                client.send(b"\x00\x00\x00\x01")
            client.close()
        except Exception:
            pass


# =============================================================================
# SNMP  (port 161)
# =============================================================================

class SNMPSimulator(VulnerableService):
    """Simulador de SNMP"""

    def __init__(self):
        super().__init__("SNMP", 161)

    def handle_client(self, client, addr):
        try:
            client.recv(4096)
            sysdescr = "Linux ubuntu 5.15.0-generic SNMPv2"
            response = b"\x30\x82\x00\x2a\x02\x01\x00\x04\x06public\xa2\x1c"
            client.send(response + sysdescr.encode())
            logger.info(f"[SNMP] Consulta desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Docker  (ports 2375, 2376, 4243)
# =============================================================================

class DockerSimulator(VulnerableService):
    """Simulador de Docker API - REST HTTP"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = json.dumps({
                "Version": "20.10.12",
                "ApiVersion": "1.41",
                "MinAPIVersion": "1.12",
                "Containers": 5,
                "Images": 12,
                "ServerVersion": "20.10.12"
            })
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{body}"
            )
            client.send(response.encode())
            logger.info(f"[Docker] API request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Jenkins  (ports 8080, 8443, 9090)
# =============================================================================

class JenkinsSimulator(VulnerableService):
    """Simulador de Jenkins - credenciales del modulo jenkins_exploit"""

    VALID_CREDS = [
        ('admin', 'admin'), ('jenkins', 'jenkins'), ('admin', 'password'),
        ('admin', 'jenkins'), ('admin', ''), ('', ''),
        ('user', 'user'), ('test', 'test'),
    ]

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = (
                "<html><head><script>/* Jenkins */</script></head><body>"
                "<h1>Jenkins</h1><p>Jenkins ver. 2.346.3</p>"
                "<form action='j_acegi_security_check' method='POST'>"
                "<input name='j_username'/><input name='j_password'/>"
                "</form></body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "X-Jenkins: 2.346.3\r\n"
                "X-Jenkins-Session: test123\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{body}"
            )
            client.send(response.encode())
            logger.info(f"[Jenkins] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Elasticsearch  (ports 9200, 9300, 5601)
# =============================================================================

class ElasticsearchSimulator(VulnerableService):
    """Simulador de Elasticsearch - REST API sin auth"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = json.dumps({
                "name": "es-node-1",
                "cluster_name": "docker-cluster",
                "cluster_uuid": "test123",
                "version": {
                    "number": "7.17.0",
                    "build_flavor": "default",
                    "build_type": "docker",
                    "lucene_version": "8.11.1"
                },
                "tagline": "You Know, for Search"
            })
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{body}"
            )
            client.send(response.encode())
            logger.info(f"[Elasticsearch] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# MSSQL  (ports 1433, 1434)
# =============================================================================

class MSSQLSimulator(VulnerableService):
    """Simulador de MSSQL"""

    def __init__(self):
        super().__init__("MSSQL", 1433)

    def handle_client(self, client, addr):
        try:
            client.send(b"\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            time.sleep(0.2)
            client.recv(4096)
            client.send(b"MSSQL Server 2019\r\n")
            logger.info(f"[MSSQL] Conexion desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Kubernetes  (ports 6443, 8080, 10250, 10255)
# =============================================================================

class KubernetesSimulator(VulnerableService):
    """Simulador de Kubernetes API"""

    def handle_client(self, client, addr):
        try:
            data = client.recv(4096).decode(errors='replace')
            path = '/'
            if 'GET ' in data:
                parts = data.split(' ')
                if len(parts) > 1:
                    path = parts[1]
            if '/version' in path:
                body = json.dumps({"major": "1", "minor": "24",
                                   "gitVersion": "v1.24.0", "platform": "linux/amd64"})
            elif '/api' in path:
                body = json.dumps({"versions": ["v1"]})
            else:
                body = json.dumps({"kind": "Status", "apiVersion": "v1", "code": 200})
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[K8s] API request {path} desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Tomcat  (ports 8080, 8443)
# =============================================================================

class TomcatSimulator(VulnerableService):
    """Simulador de Tomcat - credenciales del modulo tomcat_exploit"""

    VALID_CREDS = [
        ('admin', 'admin'), ('tomcat', 'tomcat'), ('admin', ''),
        ('manager', 'manager'), ('role1', 'role1'),
        ('admin', 'password'), ('root', 'root'),
    ]

    def handle_client(self, client, addr):
        try:
            request = client.recv(4096).decode(errors='replace')
            path = '/'
            if 'GET ' in request:
                parts = request.split(' ')
                if len(parts) > 1:
                    path = parts[1]
            if 'manager/html' in path:
                body = "<html><body><h1>Tomcat Manager</h1></body></html>"
                response = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "WWW-Authenticate: Basic realm=\"Tomcat Manager Application\"\r\n"
                    "Content-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n"
                    "\r\n" + body
                )
            else:
                body = "<html><body><h1>Apache Tomcat/9.0.50</h1><p>Powered by Tomcat</p></body></html>"
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n"
                    "\r\n" + body
                )
            client.send(response.encode())
            logger.info(f"[Tomcat] {path} desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# WebLogic  (ports 7001, 7002, 8001, 8002)
# =============================================================================

class WebLogicSimulator(VulnerableService):
    """Simulador de WebLogic"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = (
                "<html><body><h1>WebLogic Server</h1>"
                "<p>Oracle WebLogic Server 12.2.1.4.0</p>"
                "<a href='/console/'>Console</a></body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: WebLogic Server 12.2.1.4.0\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[WebLogic] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Exchange  (ports 443, 587, 25)
# =============================================================================

class ExchangeSimulator(VulnerableService):
    """Simulador de Exchange - OWA / Autodiscover"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = (
                "<html><head><title>Outlook Web App</title></head><body>"
                "<h1>Outlook Web App</h1>"
                "<p>Microsoft Exchange Server 2019</p>"
                "<form action='/owa/auth.owa' method='POST'>"
                "<input name='username'/><input name='password'/>"
                "</form></body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "X-OWA-Version: 15.2.858.5\r\n"
                "X-FEServer: EXCH01\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[Exchange] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Confluence  (ports 8090, 8080, 80, 443)
# =============================================================================

class ConfluenceSimulator(VulnerableService):
    """Simulador de Confluence"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = (
                "<html><head><title>Confluence</title></head><body>"
                "<h1>Confluence</h1><p>Atlassian Confluence 7.13.0</p>"
                "</body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "X-Confluence-Request-Time: 123\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[Confluence] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Jira  (ports 8080, 80, 443)
# =============================================================================

class JiraSimulator(VulnerableService):
    """Simulador de Jira"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = (
                "<html><head><title>Jira</title></head><body>"
                "<h1>Jira</h1><p>Atlassian Jira Software 8.20.0</p>"
                "</body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "X-AREQUESTID: test123\r\n"
                "X-ASESSIONID: abc\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[Jira] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# GitLab  (ports 80, 443, 8080)
# =============================================================================

class GitLabSimulator(VulnerableService):
    """Simulador de GitLab"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = (
                "<html><head><title>GitLab</title></head><body>"
                "<h1>GitLab Community Edition</h1><p>GitLab 14.10.0</p>"
                "</body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "X-GitLab-Current-User: test\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[GitLab] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Apache Struts  (ports 8080, 80, 443, 8443)
# =============================================================================

class StrutsSimulator(VulnerableService):
    """Simulador de Struts"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = "<html><body><h1>Struts2 Showcase</h1><p>Apache Struts 2.5.22</p></body></html>"
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[Struts] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Log4j  (ports 80, 443, 8080, 8443, 9200, 8090, 7001)
# =============================================================================

class Log4jSimulator(VulnerableService):
    """Simulador para Log4Shell"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = "<html><body><h1>Application Server</h1><p>Apache Log4j 2.14.1</p></body></html>"
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[Log4j] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Citrix  (ports 443, 80)
# =============================================================================

class CitrixSimulator(VulnerableService):
    """Simulador de Citrix NetScaler"""

    def handle_client(self, client, addr):
        try:
            client.recv(4096).decode(errors='replace')
            body = (
                "<html><head><title>Citrix Gateway</title></head><body>"
                "<h1>Citrix NetScaler</h1><p>NS13.0 Build 47.24</p>"
                "</body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: NetScaler\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n" + body
            )
            client.send(response.encode())
            logger.info(f"[Citrix] Request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Modbus  (port 502)
# =============================================================================

class ModbusSimulator(VulnerableService):
    """Simulador de Modbus TCP"""

    def handle_client(self, client, addr):
        try:
            data = client.recv(4096)
            if len(data) >= 8:
                tid = struct.unpack('>H', data[0:2])[0]
                pid = struct.unpack('>H', data[2:4])[0]
                length = struct.unpack('>H', data[4:6])[0]
                uid = data[6]
                fc = data[7] if len(data) > 7 else 0
                if fc == 0x03:
                    resp_data = bytes([fc, 20]) + b'\x00\x01' * 10
                elif fc == 0x01:
                    resp_data = bytes([fc, 2]) + b'\xff\x00'
                elif fc in (0x05, 0x06):
                    resp_data = data[6:10]
                else:
                    resp_data = bytes([fc | 0x80, 0x01])
                mbap = struct.pack('>HHHB', tid, pid, len(resp_data) + 1, uid)
                client.send(mbap + resp_data)
                logger.info(f"[Modbus] Funcion 0x{fc:02x} desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# BACnet  (port 47808)
# =============================================================================

class BACnetSimulator(VulnerableService):
    """Simulador de BACnet/IP"""

    def __init__(self):
        super().__init__("BACnet", 47808)

    def handle_client(self, client, addr):
        try:
            client.recv(1024)
            response = b'\x81\x0a\x00\x0c\x01\x04\x00\x08'
            client.send(response)
            logger.info(f"[BACnet] Who-Is desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# DNP3  (port 20000)
# =============================================================================

class DNP3Simulator(VulnerableService):
    """Simulador de DNP3 - SCADA"""

    def __init__(self):
        super().__init__("DNP3", 20000)

    def handle_client(self, client, addr):
        try:
            client.recv(256)
            response = b'\x05\x64\x0b\xc0\x01\x00\x00\x00\x00\x00\x00\x00\x00'
            client.send(response)
            logger.info(f"[DNP3] Link request desde {addr}")
            client.close()
        except Exception:
            pass


# =============================================================================
# Generic mock service (banner only)
# =============================================================================

class MockService(VulnerableService):
    """Servicio que solo muestra un banner"""

    def __init__(self, name, port, banner):
        super().__init__(name, port)
        self.banner = banner

    def handle_client(self, client, addr):
        try:
            time.sleep(0.2)
            client.send(self.banner.encode() if isinstance(self.banner, str) else self.banner)
            logger.info(f"[{self.name}] Conexion desde {addr}")
            time.sleep(0.3)
            client.close()
        except Exception:
            pass


# =============================================================================
# Factory / Launcher
# =============================================================================

def start_all_services():
    """Inicia todos los servicios simulados (~50 servicios / ~80 puertos)"""

    services = [
        # === Servicios base ===
        SSHSimulator("SSH", 22, "0.0.0.0"),
        SSHSimulator("SSH_alt", 2222, "0.0.0.0"),
        FTPSimulator("FTP", 21, "0.0.0.0"),
        FTPSimulator("FTP_alt", 2121, "0.0.0.0"),
        HTTPSimulator("HTTP", 80, "0.0.0.0"),
        HTTPSimulator("HTTPS", 443, "0.0.0.0"),
        HTTPSimulator("HTTP_8080", 8080, "0.0.0.0"),
        HTTPSimulator("HTTPS_8443", 8443, "0.0.0.0"),
        TelnetSimulator("Telnet", 23, "0.0.0.0"),
        TelnetSimulator("Telnet_alt", 2323, "0.0.0.0"),
        RedisSimulator("Redis", 6379, "0.0.0.0"),
        SMBSimulator(445),
        SMBSimulator(139),
        RDPSimulator(),

        # === Bases de datos ===
        MySQLSimulator(),
        PostgreSQLSimulator(),
        MongoDB("MongoDB", 27017, "0.0.0.0"),
        MongoDB("MongoDB_alt", 27018, "0.0.0.0"),
        MSSQLSimulator(),
        MockService("MSSQL_Browser", 1434, b"\x00" * 8),

        # === Infraestructura ===
        VNCSimulator("VNC", 5900, "0.0.0.0"),
        VNCSimulator("VNC_1", 5901, "0.0.0.0"),
        SNMPSimulator(),
        DockerSimulator("Docker", 2375, "0.0.0.0"),
        DockerSimulator("Docker_TLS", 2376, "0.0.0.0"),
        DockerSimulator("Docker_alt", 4243, "0.0.0.0"),

        # === Aplicaciones web / DevOps ===
        JenkinsSimulator("Jenkins", 8080, "0.0.0.0"),
        JenkinsSimulator("Jenkins_alt", 9090, "0.0.0.0"),
        ElasticsearchSimulator("Elasticsearch", 9200, "0.0.0.0"),
        ElasticsearchSimulator("ES_Transport", 9300, "0.0.0.0"),
        MockService("Kibana", 5601, "HTTP/1.1 200 OK\r\n\r\n{\"status\":\"green\"}"),
        KubernetesSimulator("K8s_API", 6443, "0.0.0.0"),
        KubernetesSimulator("K8s_kubelet", 10250, "0.0.0.0"),
        KubernetesSimulator("K8s_kubelet_ro", 10255, "0.0.0.0"),

        # === Servidores de aplicaciones ===
        TomcatSimulator("Tomcat", 8080, "0.0.0.0"),
        WebLogicSimulator("WebLogic", 7001, "0.0.0.0"),
        WebLogicSimulator("WebLogic_SSL", 7002, "0.0.0.0"),

        # === Correo / Colaboracion ===
        ExchangeSimulator("Exchange_OWA", 443, "0.0.0.0"),
        MockService("Exchange_SMTP", 25, "220 exchange.local ESMTP\r\n"),
        MockService("Exchange_Submission", 587, "220 exchange.local ESMTP\r\n"),
        ConfluenceSimulator("Confluence", 8090, "0.0.0.0"),
        JiraSimulator("Jira", 8080, "0.0.0.0"),
        GitLabSimulator("GitLab", 443, "0.0.0.0"),

        # === CVEs / Vulnerabilidades especificas ===
        StrutsSimulator("Struts", 8080, "0.0.0.0"),
        Log4jSimulator("Log4j", 8080, "0.0.0.0"),
        Log4jSimulator("Log4j_8090", 8090, "0.0.0.0"),
        Log4jSimulator("Log4j_7001", 7001, "0.0.0.0"),
        CitrixSimulator("Citrix", 443, "0.0.0.0"),

        # === IoT / OT / SCADA ===
        ModbusSimulator("Modbus", 502, "0.0.0.0"),
        BACnetSimulator(),
        DNP3Simulator(),
    ]

    print("=" * 70)
    print("  INICIANDO SERVICIOS SIMULADOS (~50 servicios / ~80 puertos)")
    print("=" * 70)
    print()

    base_ip = "192.168.100."
    ips = [f"{base_ip}{i+10}" for i in range(len(services))]

    for i, (service, ip) in enumerate(zip(services, ips)):
        print(f"  [{i+1:2d}] {service.name:25s} {ip:15s}:{service.port}")
        service.start()

    print()
    print("=" * 70)
    print("  CREDENCIALES DE PRUEBA (por servicio)")
    print("=" * 70)
    print()
    print("  SSH:               root/root, root/toor, root/password, admin/admin,")
    print("                     user/user, ubuntu/ubuntu, pi/raspberry, deploy/deploy")
    print("  FTP:               anonymous:anything, ftp/ftp, admin/admin, root/root")
    print("  Telnet:            admin/admin, root/root, admin/password, cisco/cisco")
    print("  PostgreSQL:        postgres/postgres, postgres/password, admin/admin")
    print("  MySQL:             root/root, mysql/mysql, admin/admin")
    print("  MSSQL:             sa/Password1, sa/Admin123, admin/admin, sa/sa")
    print("  VNC:               (no auth), password, admin, vnc, 123456, root")
    print("  SNMP communities:  public, private, admin, cisco, manager, snmp")
    print("  Jenkins:           admin/admin, jenkins/jenkins, admin/password")
    print("  Tomcat:            admin/admin, tomcat/tomcat, manager/manager")
    print("  Redis:             (sin auth por defecto)")
    print("  MongoDB:           (sin auth por defecto)")
    print("  Docker API:        (sin auth)")
    print("  Elasticsearch:     (sin auth)")
    print("  Kubernetes:        (sin auth)")
    print()
    print("  ~50 servicios simulados en ~80 puertos")
    print("  Presiona Ctrl+C para detener todos los servicios")
    print("=" * 70)

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
