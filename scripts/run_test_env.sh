#!/bin/bash
# Test Environment Launcher
# Ejecuta el entorno de prueba completo

echo "=========================================="
echo "  WORMY TEST ENVIRONMENT"
echo "=========================================="

# Check if Python venv exists
if [ ! -d "venv" ]; then
    echo "[ERROR] Virtual environment not found. Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Activate venv
source venv/bin/activate

# Check arguments
MODE=${1:-"simulate"}

case "$MODE" in
    "simulate")
        echo "=== MODE: Simulated Services (Python) ==="
        echo ""
        echo "Starting simulated services in background..."
        python3 simulate_services.py &
        SIMULATE_PID=$!
        sleep 3
        
        echo ""
        echo "Running worm in test environment..."
        python3 worm_core.py --config config_test_env.yaml
        
        # Cleanup
        kill $SIMULATE_PID 2>/dev/null
        ;;
        
    "docker")
        echo "=== MODE: Docker Services ==="
        echo ""
        echo "Starting Docker services..."
        chmod +x setup_test_environment.sh
        ./setup_test_environment.sh start
        sleep 5
        
        echo ""
        echo "Running worm in test environment..."
        python3 worm_core.py --config config_test_env.yaml
        
        # Cleanup
        ./setup_test_environment.sh stop
        ;;
        
    "scan")
        echo "=== MODE: Scan Only ==="
        python3 worm_core.py --config config_test_env.yaml --scan-only
        ;;
        
    "quick")
        echo "=== MODE: Quick Test ==="
        echo "Starting services..."
        python3 simulate_services.py &
        SIMULATE_PID=$!
        sleep 3
        
        echo "Scanning network..."
        python3 worm_core.py --scan-only
        
        kill $SIMULATE_PID 2>/dev/null
        ;;
        
    *)
        echo "Usage: $0 {simulate|docker|scan|quick}"
        echo ""
        echo "  simulate - Simulated Python services (default)"
        echo "  docker   - Real Docker containers"
        echo "  scan     - Scan only (no exploitation)"
        echo "  quick    - Quick test with scan"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "  TEST COMPLETE"
echo "=========================================="