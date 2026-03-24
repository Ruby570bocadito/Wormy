#!/bin/bash
# Test Environment Setup - Levanta servicios vulnerables para testing
# Uso: ./setup_test_environment.sh [start|stop|status]

set -e

NETWORK_NAME="wormy_test_net"
SUBNET="192.168.100.0/24"

start_services() {
    echo "=== Creating test network ==="
    docker network create --subnet=$SUBNET $NETWORK_NAME 2>/dev/null || true
    
    echo "=== Starting vulnerable services ==="
    
    # SSH Server
    echo "[1/8] Starting SSH server..."
    docker run -d --name wormy_ssh --network $NETWORK_NAME --ip 192.168.100.10 \
        -p 2222:22 -e ROOT_PASSWORD=password rastasheep/ubuntu-sshd:latest
    
    # FTP Server
    echo "[2/8] Starting FTP server..."
    docker run -d --name wormy_ftp --network $NETWORK_NAME --ip 192.168.100.11 \
        -p 2121:21 -e FTP_USER=test -e FTP_PASS=test fauria/vsftpd:latest
    
    # MySQL
    echo "[3/8] Starting MySQL..."
    docker run -d --name wormy_mysql --network $NETWORK_NAME --ip 192.168.100.12 \
        -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root mysql:5.7
    
    # PostgreSQL
    echo "[4/8] Starting PostgreSQL..."
    docker run -d --name wormy_postgres --network $NETWORK_NAME --ip 192.168.100.13 \
        -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:14
    
    # Redis
    echo "[5/8] Starting Redis..."
    docker run -d --name wormy_redis --network $NETWORK_NAME --ip 192.168.100.14 \
        -p 6379:6379 redis:7
    
    # MongoDB
    echo "[6/8] Starting MongoDB..."
    docker run -d --name wormy_mongo --network $NETWORK_NAME --ip 192.168.100.15 \
        -p 27017:27017 mongo:6
    
    # HTTP Server (Apache)
    echo "[7/8] Starting HTTP server..."
    docker run -d --name wormy_http --network $NETWORK_NAME --ip 192.168.100.16 \
        -p 8080:80 httpd:2.4
    
    # Telnet (simulado con netcat)
    echo "[8/8] Starting Telnet simulation..."
    docker run -d --name wormy_telnet --network $NETWORK_NAME --ip 192.168.100.17 \
        -p 2323:23 ubuntu:22.04 tail -f /dev/null
    
    echo ""
    echo "=== Test Services Started ==="
    echo "SSH:    192.168.100.10:22 (user: root, pass: password)"
    echo "FTP:    192.168.100.11:21 (user: test, pass: test)"
    echo "MySQL:  192.168.100.12:3306 (user: root, pass: root)"
    echo "PostgreSQL: 192.168.100.13:5432 (pass: postgres)"
    echo "Redis:  192.168.100.14:6379"
    echo "MongoDB: 192.168.100.15:27017"
    echo "HTTP:   192.168.100.16:80"
    echo "Telnet: 192.168.100.17:23"
    echo ""
    echo "Mapped ports: 2222, 2121, 3306, 5432, 6379, 27017, 8080, 2323"
}

stop_services() {
    echo "=== Stopping test services ==="
    docker rm -f wormy_ssh wormy_ftp wormy_mysql wormy_postgres wormy_redis wormy_mongo wormy_http wormy_telnet 2>/dev/null || true
    docker network rm $NETWORK_NAME 2>/dev/null || true
    echo "=== Services stopped ==="
}

status_services() {
    echo "=== Service Status ==="
    docker ps --filter "name=wormy_" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

case "$1" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    status)
        status_services
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac