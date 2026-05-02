#!/bin/bash
# Advanced Multi-Challenge Docker Labs
# Creates 10 different lab environments with dynamic credentials

set -e

NETWORK_NAME="wormy_challenge_net"
SUBNET="192.168.200.0/24"

echo "======================================================================"
echo "  CREATING 10 CHALLENGE LABS WITH DYNAMIC CREDENTIALS"
echo "======================================================================"

# Cleanup first
echo "[Cleanup] Removing old networks and containers..."
docker network rm ${NETWORK_NAME} 2>/dev/null || true
docker ps -a --filter "name=challenge" -q | xargs docker rm -f 2>/dev/null || true

# Create network
echo "[Network] Creating challenge network..."
docker network create --subnet=$SUBNET $NETWORK_NAME 2>/dev/null || docker network create --subnet=$SUBNET $NETWORK_NAME

# Generate dynamic credentials for each lab
GEN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
DB_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
ADMIN_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)

# Lab 1: Basic Web Server (Easy)
echo "[Lab 1/10] Starting Basic Web Server..."
docker run -d --name challenge_1_web \
  --network $NETWORK_NAME --ip 192.168.200.10 \
  -p 8010:80 \
  -e FTP_USER=admin -e FTP_PASS=$ADMIN_PASS \
  httpd:2.4

# Lab 2: SSH + FTP (Medium)
echo "[Lab 2/10] Starting SSH+FTP Server..."
docker run -d --name challenge_2_ssh \
  --network $NETWORK_NAME --ip 192.168.200.11 \
  -p 8011:22 -p 8012:21 \
  -e ROOT_PASSWORD=$GEN_PASS \
  rastasheep/ubuntu-sshd:latest

# Lab 3: Database Server (Hard)
echo "[Lab 3/10] Starting Database Server..."
docker run -d --name challenge_3_db \
  --network $NETWORK_NAME --ip 192.168.200.12 \
  -p 8013:3306 \
  -e MYSQL_ROOT_PASSWORD=$DB_PASS \
  mysql:5.7

# Lab 4: PostgreSQL + Redis
echo "[Lab 4/10] Starting PostGIS+Redis..."
docker run -d --name challenge_4_postgis \
  --network $NETWORK_NAME --ip 192.168.200.13 \
  -p 8014:5432 \
  -e POSTGRES_PASSWORD=$DB_PASS \
  postgres:14

docker run -d --name challenge_4_redis \
  --network $NETWORK_NAME --ip 192.168.200.14 \
  -p 8015:6379 \
  redis:7-alpine

# Lab 5: Jenkins + Nexus
echo "[Lab 5/10] Starting DevOps Stack..."
docker run -d --name challenge_5_jenkins \
  --network $NETWORK_NAME --ip 192.168.200.15 \
  -p 8016:8080 \
  jenkins/jenkins:lts

docker run -d --name challenge_5_nexus \
  --network $NETWORK_NAME --ip 192.168.200.16 \
  -p 8017:8081 \
  sonatype/nexus3:latest

# Lab 6: MongoDB + Elasticsearch
echo "[Lab 6/10] Starting NoSQL Stack..."
docker run -d --name challenge_6_mongo \
  --network $NETWORK_NAME --ip 192.168.200.17 \
  -p 8018:27017 \
  mongo:6

docker run -d --name challenge_6_elastic \
  --network $NETWORK_NAME --ip 192.168.200.18 \
  -p 8019:9200 \
  elasticsearch:7.17.0

# Lab 7: Docker + Kubernetes
echo "[Lab 7/10] Starting Container Platform..."
docker run -d --name challenge_7_dind \
  --network $NETWORK_NAME --ip 192.168.200.19 \
  -p 8020:2375 \
  --privileged docker:dind

# Lab 8: Windows Simulation (SMB/RDP)
echo "[Lab 8/10] Starting Windows Targets..."
docker run -d --name challenge_8_smb \
  --network $NETWORK_NAME --ip 192.168.200.20 \
  -p 8021:445 \
  --cap-add SYS_ADMIN \
  ubuntu:22.04 bash -c "apt-get update && apt-get install -y samba && tail -f /dev/null"

# Lab 9: Multiple Services
echo "[Lab 9/10] Starting Multi-Service..."
docker run -d --name challenge_9_multi \
  --network $NETWORK_NAME --ip 192.168.200.21 \
  -p 8022:21 -p 8023:22 -p 8024:80 -p 8025:443 \
  ubuntu:22.04 bash -c "apt-get update && apt-get install -y vsftpd openssh-server apache2 && mkdir -p /var/run/sshd && tail -f /dev/null"

# Lab 10: Vulnerable Apps (DVWA, etc)
echo "[Lab 10/10] Starting Vulnerable Apps..."
docker run -d --name challenge_10_dvwa \
  --network $NETWORK_NAME --ip 192.168.200.22 \
  -p 8026:80 \
  vulnerable/dvwa

sleep 5

echo ""
echo "======================================================================"
echo "  CHALLENGE LABS SUMMARY"
echo "======================================================================"
echo ""
docker ps --filter "name=challenge" --format "table {{.Names}}\t{{.Ports}}\t{{.Networks}}"

echo ""
echo "  Lab 1: 192.168.200.10 (Web)         - Port 80"
echo "  Lab 2: 192.168.200.11 (SSH/FTP)    - Ports 22, 21"
echo "  Lab 3: 192.168.200.12 (MySQL)       - Port 3306"
echo "  Lab 4: 192.168.200.13-14 (Postgres+Redis)"
echo "  Lab 5: 192.168.200.15-16 (Jenkins+Nexus)"
echo "  Lab 6: 192.168.200.17-18 (Mongo+Elastic)"
echo "  Lab 7: 192.168.200.19 (Docker)"
echo "  Lab 8: 192.168.200.20 (SMB)"
echo "  Lab 9: 192.168.200.21 (Multi-service)"
echo "  Lab 10: 192.168.200.22 (DVWA)"
echo ""
echo "  Credentials for this round:"
echo "    Admin: admin:$ADMIN_PASS"
echo "    Root: root:$GEN_PASS"
echo "    DB: root:$DB_PASS"
echo "======================================================================"
echo ""

# Save credentials to file for training
mkdir -p lab_credentials
echo "admin:$ADMIN_PASS" > lab_credentials/lab1.txt
echo "root:$GEN_PASS" > lab_credentials/lab2.txt
echo "root:$DB_PASS" > lab_credentials/lab3.txt

echo "Credentials saved to lab_credentials/"
echo "Challenge environment ready!"