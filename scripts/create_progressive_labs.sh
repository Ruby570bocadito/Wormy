#!/bin/bash
# Progressive Difficulty Docker Labs
# Uses existing network: wormy_challenge_net (192.168.200.0/24)

set -e

NETWORK_NAME="wormy_challenge_net"

echo "======================================================================"
echo "  CREATING PROGRESSIVE DIFFICULTY LABS"
echo "  Level 1 (Easy) → Level 5 (Expert)"
echo "======================================================================"

# Ensure network exists
docker network inspect $NETWORK_NAME >/dev/null 2>&1 || docker network create --subnet=192.168.200.0/24 --driver=bridge $NETWORK_NAME

# Cleanup old labs
docker ps -a --filter "name=wormy_lab" -q | xargs docker rm -f 2>/dev/null || true
docker ps -a --filter "name=challenge_" -q | xargs docker rm -f 2>/dev/null || true

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  LEVEL 1: EASY - Basic Services with Default Credentials"
echo "══════════════════════════════════════════════════════════════════════"

# Level 1: Easy - Web with basic auth
docker run -d --name wormy_lab_01 \
  --network $NETWORK_NAME --ip 192.168.200.10 \
  -p 8010:80 \
  httpd:2.4

# Level 1: Easy - FTP with anonymous
docker run -d --name wormy_lab_02 \
  --network $NETWORK_NAME --ip 192.168.200.11 \
  -p 8011:21 \
  -e FTP_USER=admin -e FTP_PASS=admin123 \
  fauria/vsftpd

echo "  ✓ Level 1: 2 labs (Web, FTP)"

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  LEVEL 2: MEDIUM - Services with Random Credentials"
echo "══════════════════════════════════════════════════════════════════════"

# Level 2: Medium - SSH with password
docker run -d --name wormy_lab_03 \
  --network $NETWORK_NAME --ip 192.168.200.12 \
  -p 8012:22 \
  -e PASSWORD=sshpass123 \
  rastasheep/ubuntu-sshd:latest

# Level 2: Medium - MySQL
docker run -d --name wormy_lab_04 \
  --network $NETWORK_NAME --ip 192.168.200.13 \
  -p 8013:3306 \
  -e MYSQL_ROOT_PASSWORD=mysql123 \
  -e MYSQL_DATABASE=app \
  mysql:5.7

echo "  ✓ Level 2: 2 labs (SSH, MySQL)"

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  LEVEL 3: HARD - Multiple Services, Hidden Ports"
echo "══════════════════════════════════════════════════════════════════════"

# Level 3: Hard - Multi-service container
docker run -d --name wormy_lab_05 \
  --network $NETWORK_NAME --ip 192.168.200.14 \
  -p 8014:5432 -p 8015:6379 \
  -e POSTGRES_PASSWORD=postgres123 \
  -e REDIS_PASSWORD=redis123 \
  postgres:14 redis:7-alpine \
  sh -c "redis-server --requirepass redis123 & postgres -c 'shared_buffers=128MB' & tail -f /dev/null"

# Level 3: Hard - Jenkins with initial admin
docker run -d --name wormy_lab_06 \
  --network $NETWORK_NAME --ip 192.168.200.15 \
  -p 8016:8080 \
  jenkins/jenkins:lts

echo "  ✓ Level 3: 2 labs (Postgres+Redis, Jenkins)"

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  LEVEL 4: EXPERT - Complex Stacks, Multiple Vectors"
echo "══════════════════════════════════════════════════════════════════════"

# Level 4: Expert - MongoDB with auth
docker run -d --name wormy_lab_07 \
  --network $NETWORK_NAME --ip 192.168.200.16 \
  -p 8017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=mongo123 \
  mongo:6

# Level 4: Expert - Elasticsearch
docker run -d --name wormy_lab_08 \
  --network $NETWORK_NAME --ip 192.168.200.17 \
  -p 8018:9200 \
  -e "discovery.type=single-node" \
  elasticsearch:7.17.0

echo "  ✓ Level 4: 2 labs (MongoDB, Elasticsearch)"

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  LEVEL 5: IMPOSSIBLE - Protected Services"
echo "══════════════════════════════════════════════════════════════════════"

# Level 5: Impossible - Docker API
docker run -d --name wormy_lab_09 \
  --network $NETWORK_NAME --ip 192.168.200.18 \
  -p 8019:2375 \
  --privileged \
  docker:dind

# Level 5: Impossible - Multi-service with firewall
docker run -d --name wormy_lab_10 \
  --network $NETWORK_NAME --ip 192.168.200.19 \
  -p 8020:21 -p 8021:22 -p 8022:80 -p 8023:443 \
  -e FTP_USER=hacker -e FTP_PASS=hacker123 \
  ubuntu:22.04 sh -c "
    apt-get update && apt-get install -y vsftpd openssh-server apache2 && 
    echo 'hacker:hacker123' | chpasswd &&
    service vsftpd start && service ssh start && service apache2 start &&
    tail -f /dev/null"

# Level 5: Impossible - DVWA alternative (Mutillidae)
docker run -d --name wormy_lab_11 \
  --network $NETWORK_NAME --ip 192.168.200.20 \
  -p 8024:80 \
  mutillidae/mutillidae

echo "  ✓ Level 5: 3 labs (Docker, Multi-service, DVWA)"

sleep 5

echo ""
echo "======================================================================"
echo "  LAB ENVIRONMENT SUMMARY"
echo "======================================================================"
docker ps --filter "name=wormy_lab" --format "table {{.Names}}\t{{.Ports}}\t{{.IP}}"

echo ""
echo "  Level 1 (Easy):    Labs 1-2    (Default creds, open services)"
echo "  Level 2 (Medium):  Labs 3-4    (Simple creds, single service)"
echo "  Level 3 (Hard):    Labs 5-6    (Multi-service, hidden configs)"
echo "  Level 4 (Expert):  Labs 7-8    (Complex stacks, auth required)"
echo "  Level 5 (Hard):    Labs 9-11   (Protected, vulnerable apps)"
echo ""
echo "  Credentials:"
echo "    Level 1: admin/admin123, anonymous"
echo "    Level 2: root/sshpass123, root/mysql123"
echo "    Level 3: admin/postgres123, admin/redis123, jenkins/(initial)"
echo "    Level 4: admin/mongo123"
echo "    Level 5: hacker/hacker123"
echo "======================================================================"

# Save for training
mkdir -p lab_credentials
cat > lab_credentials/levels.json << EOF
{
  "levels": {
    "1": {"name": "Easy", "labs": [1, 2], "difficulty": 0.2},
    "2": {"name": "Medium", "labs": [3, 4], "difficulty": 0.4},
    "3": {"name": "Hard", "labs": [5, 6], "difficulty": 0.6},
    "4": {"name": "Expert", "labs": [7, 8], "difficulty": 0.8},
    "5": {"name": "Impossible", "labs": [9, 10, 11], "difficulty": 1.0}
  },
  "credentials": {
    "web": "admin:admin123",
    "ftp": "admin:admin123",
    "ssh": "root:sshpass123",
    "mysql": "root:mysql123",
    "postgres": "postgres:postgres123",
    "redis": "redis:redis123",
    "jenkins": "admin:admin",
    "mongodb": "admin:mongo123",
    "multi": "hacker:hacker123"
  }
}
EOF

echo "Credentials saved to lab_credentials/levels.json"
echo "Labs ready for training!"