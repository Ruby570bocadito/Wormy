#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Wormy Lab Setup Script
# Starts vulnerable services for RL agent training
# ⚠️ Educational Use Only
# ═══════════════════════════════════════════════════════════════════

set -e

LAB_NETWORK="192.168.100.0/24"
COMPOSE_FILE="docker-compose-lab.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  🐛 Wormy Lab Environment Setup${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    exit 1
fi

# Detect docker compose command
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

# Parse arguments
ACTION=${1:-"up"}

case $ACTION in
    up|start)
        echo -e "${GREEN}🚀 Starting lab environment...${NC}"
        
        # Pull images first
        echo -e "${YELLOW}📦 Pulling Docker images (this may take a while)...${NC}"
        $DOCKER_COMPOSE -f $COMPOSE_FILE pull
        
        # Start services
        echo -e "${YELLOW}🐳 Starting containers...${NC}"
        $DOCKER_COMPOSE -f $COMPOSE_FILE up -d
        
        # Wait for services
        echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
        sleep 10
        
        # Show status
        echo ""
        echo -e "${GREEN}✅ Lab environment is running!${NC}"
        echo ""
        echo -e "${BLUE}📡 Available Services:${NC}"
        echo "  ┌─────────────────┬────────────────────┬──────────────┐"
        echo "  │ Service         │ IP Address         │ Port         │"
        echo "  ├─────────────────┼────────────────────┼──────────────┤"
        echo "  │ Redis           │ 192.168.100.10     │ 6379         │"
        echo "  │ MySQL           │ 192.168.100.11     │ 3306         │"
        echo "  │ PostgreSQL      │ 192.168.100.12     │ 5432         │"
        echo "  │ MongoDB         │ 192.168.100.13     │ 27017        │"
        echo "  │ MSSQL           │ 192.168.100.14     │ 1433         │"
        echo "  │ RabbitMQ        │ 192.168.100.20     │ 5672         │"
        echo "  │ Jenkins         │ 192.168.100.30     │ 8080         │"
        echo "  │ Docker API      │ 192.168.100.40     │ 2375         │"
        echo "  │ DVWA            │ 192.168.100.50     │ 8081         │"
        echo "  │ Juice-Shop      │ 192.168.100.51     │ 8082         │"
        echo "  │ FTP             │ 192.168.100.60     │ 21           │"
        echo "  │ SSH             │ 192.168.100.61     │ 2222         │"
        echo "  │ SMB             │ 192.168.100.70     │ 445          │"
        echo "  │ Elasticsearch   │ 192.168.100.80     │ 9200         │"
        echo "  │ SNMP            │ 192.168.100.90     │ 161/UDP      │"
        echo "  │ VNC             │ 192.168.100.100    │ 5901         │"
        echo "  └─────────────────┴────────────────────┴──────────────┘"
        echo ""
        echo -e "${YELLOW}💡 Credentials:${NC}"
        echo "  Redis:      redis123"
        echo "  MySQL:      root / (no password)"
        echo "  PostgreSQL: admin / admin123"
        echo "  MongoDB:    admin / admin123"
        echo "  MSSQL:      sa / SqlPassword123!"
        echo "  FTP:        ftpuser / ftppass"
        echo "  SSH:        sshuser / sshpass"
        echo "  VNC:        vncpass"
        echo ""
        ;;

    down|stop)
        echo -e "${YELLOW}🛑 Stopping lab environment...${NC}"
        $DOCKER_COMPOSE -f $COMPOSE_FILE down
        echo -e "${GREEN}✅ Lab stopped${NC}"
        ;;

    restart)
        echo -e "${YELLOW}🔄 Restarting lab...${NC}"
        $DOCKER_COMPOSE -f $COMPOSE_FILE restart
        echo -e "${GREEN}✅ Lab restarted${NC}"
        ;;

    status)
        echo -e "${BLUE}📊 Lab Status:${NC}"
        $DOCKER_COMPOSE -f $COMPOSE_FILE ps
        ;;

    logs)
        echo -e "${BLUE}📜 Lab Logs:${NC}"
        $DOCKER_COMPOSE -f $COMPOSE_FILE logs --tail=50
        ;;

    clean)
        echo -e "${RED}⚠️  Cleaning up lab (removes all containers and volumes)...${NC}"
        read -p "Are you sure? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            $DOCKER_COMPOSE -f $COMPOSE_FILE down -v
            echo -e "${GREEN}✅ Lab cleaned${NC}"
        fi
        ;;

    *)
        echo "Usage: $0 {up|down|restart|status|logs|clean}"
        echo ""
        echo "  up       - Start the lab environment"
        echo "  down     - Stop the lab environment"
        echo "  restart  - Restart the lab environment"
        echo "  status   - Show lab status"
        echo "  logs     - Show lab logs"
        echo "  clean    - Remove all containers and volumes"
        exit 1
        ;;
esac
