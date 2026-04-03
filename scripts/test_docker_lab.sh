#!/bin/bash
# Docker Lab Test Script
# Tests Wormy against the Docker lab environment
#
# Usage: ./scripts/test_docker_lab.sh
#
# Prerequisites:
#   - Docker and Docker Compose installed
#   - Wormy dependencies installed
#
# This script:
#   1. Starts the Docker lab
#   2. Waits for services to be ready
#   3. Runs Wormy in scan-only mode against the lab
#   4. Runs Wormy in dry-run mode
#   5. Generates reports
#   6. Tears down the lab

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LAB_DIR="$PROJECT_DIR/docker-lab"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  WORMY ML NETWORK WORM - DOCKER LAB TEST${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERROR] Docker is not installed${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}[ERROR] Docker Compose is not installed${NC}"
    exit 1
fi

# Set docker-compose command
if docker compose version &> /dev/null; then
    DCMD="docker compose"
else
    DCMD="docker-compose"
fi

# Step 1: Start the lab
echo -e "${YELLOW}[1/6] Starting Docker Lab...${NC}"
cd "$LAB_DIR"
$DCMD up -d 2>/dev/null || {
    echo -e "${RED}[ERROR] Failed to start Docker Lab${NC}"
    echo "Make sure you have docker-compose.yml in docker-lab/"
    exit 1
}

# Step 2: Wait for services
echo -e "${YELLOW}[2/6] Waiting for services to be ready...${NC}"
sleep 15

# Check key services
echo -e "  Checking services..."
for port in 8080 2222 3306 6379 27017 9200; do
    if docker port wormy-metasploitable 2>/dev/null | grep -q "$port" || \
       docker port wormy-redis 2>/dev/null | grep -q "$port" || \
       docker port wormy-mongo 2>/dev/null | grep -q "$port"; then
        echo -e "  ${GREEN}✓${NC} Port $port is accessible"
    else
        echo -e "  ${YELLOW}?${NC} Port $port status unknown"
    fi
done

# Step 3: Get lab network info
echo -e "${YELLOW}[3/6] Lab Network Information${NC}"
echo -e "  Metasploitable2: 172.20.0.100"
echo -e "  DVWA:            172.20.0.10 (port 8080)"
echo -e "  WebGoat:         172.20.0.11 (port 8081)"
echo -e "  MySQL:           172.20.0.20 (port 3306)"
echo -e "  PostgreSQL:      172.20.0.21 (port 5432)"
echo -e "  MongoDB:         172.20.0.22 (port 27017)"
echo -e "  Redis:           172.20.0.23 (port 6379)"
echo -e "  Elasticsearch:   172.20.0.24 (port 9200)"
echo -e "  FTP:             172.20.0.30 (port 21)"
echo -e "  SSH:             172.20.0.31 (port 2222)"
echo ""

# Step 4: Run scan
echo -e "${YELLOW}[4/6] Running Wormy scan against lab...${NC}"
cd "$PROJECT_DIR"

# Create test config for Docker lab
cat > configs/config_docker_lab.yaml << 'EOF'
network:
  target_ranges:
    - "172.20.0.0/16"
  excluded_ips:
    - "172.20.0.1"
    - "172.20.0.200"
  scan_timeout: 3
  max_threads: 20
  ports_to_scan:
    - 21
    - 22
    - 23
    - 25
    - 53
    - 80
    - 110
    - 135
    - 139
    - 443
    - 445
    - 1433
    - 3306
    - 3389
    - 5432
    - 5900
    - 6379
    - 8080
    - 8443
    - 9200
    - 27017

exploit:
  max_exploit_attempts: 3
  exploit_timeout: 10
  use_credentials: true
  credential_wordlist: "wordlists/common_creds.txt"
  enable_smb: true
  enable_ssh: true
  enable_web: true

propagation:
  max_infections: 20
  propagation_delay: 1.0
  persistence_enabled: false
  self_replicate: false
  mutation_enabled: false

evasion:
  stealth_mode: true
  randomize_timing: true
  detect_honeypots: true
  detect_ids: true
  encrypt_traffic: true
  max_scan_rate: 50

c2:
  c2_server: "127.0.0.1"
  c2_port: 8443
  beacon_interval: 60
  use_encryption: true
  backup_c2_servers: []
  c2_protocol: "https"

ml:
  host_classifier_path: "ml_models/saved/host_classifier.pkl"
  rl_agent_path: "saved/rl_agent/best_model.h5"
  evasion_model_path: "ml_models/saved/evasion_model.h5"
  use_pretrained: false
  online_learning: true

safety:
  kill_switch_enabled: true
  kill_switch_code: "EMERGENCY_STOP_2024"
  auto_destruct_time: 0
  geofence_enabled: false
  allowed_networks:
    - "172.20.0.0/16"
    - "192.168.0.0/16"
    - "10.0.0.0/8"
  max_runtime_hours: 2
  enable_logging: true
  log_encryption: true

metasploit:
  enabled: false
EOF

echo -e "  Config created: configs/config_docker_lab.yaml"
echo ""

# Step 5: Run in dry-run mode
echo -e "${YELLOW}[5/6] Running Wormy in DRY-RUN mode against lab...${NC}"
echo -e "  (No real exploits will be executed)"
echo ""

python3 worm_core.py \
    --config configs/config_docker_lab.yaml \
    --dry-run \
    --no-monitor \
    --profile audit \
    2>&1 | head -100

echo ""

# Step 6: Tear down
echo -e "${YELLOW}[6/6] Tearing down Docker Lab...${NC}"
cd "$LAB_DIR"
$DCMD down 2>/dev/null

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  DOCKER LAB TEST COMPLETE${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "  Reports generated in: $PROJECT_DIR/reports/"
echo -e "  Logs generated in:    $PROJECT_DIR/logs/"
echo ""
echo -e "  To run manually against the lab:"
echo -e "    cd docker-lab && docker-compose up -d"
echo -e "    python3 worm_core.py --config configs/config_docker_lab.yaml --interactive"
echo -e "    cd docker-lab && docker-compose down"
echo ""
