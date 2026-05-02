#!/bin/bash
# Setup and launch script for Metasploit RPC integration with Wormy
# Usage: ./scripts/setup_metasploit.sh

set -e

MSF_USER="msf"
MSF_PASS="wormy2024"
MSF_PORT=55553
MSF_HOST="127.0.0.1"

echo "=============================================="
echo "  Wormy - Metasploit RPC Setup"
echo "=============================================="

# Check if Metasploit is installed
if ! command -v msfrpcd &> /dev/null; then
    echo ""
    echo "[!] msfrpcd not found. Installing Metasploit Framework..."
    echo ""
    
    if command -v apt-get &> /dev/null; then
        echo "[*] Installing via apt..."
        curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
        chmod +x /tmp/msfinstall
        sudo /tmp/msfinstall
    elif command -v pacman &> /dev/null; then
        echo "[*] Installing via pacman..."
        sudo pacman -S metasploit --noconfirm
    elif command -v dnf &> /dev/null; then
        echo "[*] Installing via dnf..."
        sudo dnf install -y metasploit-framework
    else
        echo "[!] Unsupported package manager. Install Metasploit manually:"
        echo "    https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
        exit 1
    fi
    
    echo ""
    echo "[+] Metasploit installed!"
fi

echo ""
echo "[*] Checking msfrpcd..."

if ! command -v msfrpcd &> /dev/null; then
    echo "[!] msfrpcd still not found after installation."
    echo "    Please install Metasploit Framework manually."
    exit 1
fi

echo "[+] msfrpcd found at: $(which msfrpcd)"

# Check if already running
if pgrep -f "msfrpcd" > /dev/null 2>&1; then
    echo "[*] msfrpcd is already running"
    echo "[*] Killing existing instance..."
    pkill -f msfrpcd || true
    sleep 2
fi

# Check for database
echo ""
echo "[*] Setting up Metasploit database..."
if command -v msfdb &> /dev/null; then
    msfdb init 2>/dev/null || echo "    Database already initialized"
fi

# Start msfrpcd
echo ""
echo "[*] Starting msfrpcd..."
echo "    User: $MSF_USER"
echo "    Pass: $MSF_PASS"
echo "    Port: $MSF_PORT"
echo "    Host: $MSF_HOST"
echo ""

msfrpcd -P "$MSF_PASS" -U "$MSF_USER" -p "$MSF_PORT" -a "$MSF_HOST" -n -f &
MSF_PID=$!

sleep 3

# Verify it's running
if kill -0 $MSF_PID 2>/dev/null; then
    echo "[+] msfrpcd started successfully (PID: $MSF_PID)"
    echo ""
    echo "=============================================="
    echo "  Metasploit RPC is ready!"
    echo "=============================================="
    echo ""
    echo "  To enable in Wormy, set in your config:"
    echo ""
    echo "  metasploit:"
    echo "    enabled: true"
    echo "    host: $MSF_HOST"
    echo "    port: $MSF_PORT"
    echo "    user: $MSF_USER"
    echo "    password: $MSF_PASS"
    echo ""
    echo "  Or run Wormy with:"
    echo "    python3 worm_core.py --config configs/config_msf.yaml"
    echo ""
    echo "  To stop msfrpcd: kill $MSF_PID"
    echo "=============================================="
else
    echo "[!] Failed to start msfrpcd"
    exit 1
fi
