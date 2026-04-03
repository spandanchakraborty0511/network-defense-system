import subprocess
import requests
import socket
import datetime
import json
import time
import os
import signal
import sys

# ─── Configuration ────────────────────────────────────────
VPN_INTERFACE = "wg0"
NETWORK_INTERFACE = "eth0"
CHECK_INTERVAL = 10
LOG_FILE = "vpn_monitor_log.json"

# ─── Stats ────────────────────────────────────────────────
stats = {
    "checks": 0,
    "vpn_up": 0,
    "vpn_down": 0,
    "dns_leaks": 0,
    "killswitch_activations": 0,
    "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

# ─── Logging ──────────────────────────────────────────────
def log_event(event_type, details=""):
    log = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            log = json.load(f)
    log.append({
        "timestamp": datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "event": event_type,
        "details": details
    })
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=4)

# ─── VPN Status ───────────────────────────────────────────
def check_vpn_status():
    result = subprocess.run(
        ["ip", "link", "show", VPN_INTERFACE],
        capture_output=True,
        text=True
    )
    return result.returncode == 0

# ─── Public IP ────────────────────────────────────────────
def get_public_ip():
    try:
        response = requests.get(
            "https://api.ipify.org?format=json",
            timeout=5
        )
        return response.json()["ip"]
    except:
        return None

# ─── DNS Leak Check ───────────────────────────────────────
def check_dns_leak():
    leaked = []
    private_ranges = [
        "10.", "172.", "192.168.", "127."
    ]
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns_ip = line.split()[1].strip()
                    is_private = any(
                        dns_ip.startswith(r) for r in private_ranges
                    )
                    if not is_private:
                        leaked.append(dns_ip)
    except:
        pass
    return leaked

# ─── Kill Switch ──────────────────────────────────────────
def enable_kill_switch():
    rules = [
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-o", VPN_INTERFACE, "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-o", NETWORK_INTERFACE,
         "-p", "udp", "--dport", "51820", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-m", "state",
         "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-j", "DROP"],
    ]
    for rule in rules:
        subprocess.run(rule, capture_output=True)
    stats["killswitch_activations"] += 1
    log_event("KILLSWITCH_ENABLED", "VPN dropped")
    print(f"  [!!!] Kill switch ACTIVATED")

def disable_kill_switch():
    subprocess.run(
        ["iptables", "-F", "OUTPUT"],
        capture_output=True
    )
    subprocess.run(
        ["iptables", "-P", "OUTPUT", "ACCEPT"],
        capture_output=True
    )
    log_event("KILLSWITCH_DISABLED", "Manually disabled")
    print(f"  [*] Kill switch disabled")

def is_kill_switch_active():
    result = subprocess.run(
        ["iptables", "-L", "OUTPUT", "-n"],
        capture_output=True,
        text=True
    )
    return "DROP" in result.stdout

# ─── Network Health Check ─────────────────────────────────
def check_network_health():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except:
        return False

# ─── Full Status Check ────────────────────────────────────
def run_status_check():
    stats["checks"] += 1
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[*] Check #{stats['checks']} - {timestamp}")
    print("-" * 55)

    # VPN Status
    vpn_up = check_vpn_status()
    if vpn_up:
        stats["vpn_up"] += 1
        print(f"  [OK] VPN Interface ({VPN_INTERFACE}): UP")
    else:
        stats["vpn_down"] += 1
        print(f"  [!!!] VPN Interface ({VPN_INTERFACE}): DOWN")
        if not is_kill_switch_active():
            print(f"  [*] Activating kill switch...")
            enable_kill_switch()

    # Kill Switch Status
    ks_active = is_kill_switch_active()
    if ks_active:
        print(f"  [OK] Kill Switch: ACTIVE")
    else:
        print(f"  [OK] Kill Switch: INACTIVE (VPN is up)")

    # DNS Leak Check
    leaked = check_dns_leak()
    if leaked:
        stats["dns_leaks"] += 1
        print(f"  [!!!] DNS LEAK: {', '.join(leaked)}")
        log_event("DNS_LEAK", f"Leaked: {leaked}")
    else:
        print(f"  [OK] DNS: No leaks detected")

    # Network Health
    healthy = check_network_health()
    if healthy:
        print(f"  [OK] Network: Reachable")
    else:
        print(f"  [!!!] Network: Unreachable")

    # Public IP
    public_ip = get_public_ip()
    if public_ip:
        print(f"  [OK] Public IP: {public_ip}")
    else:
        print(f"  [!!!] Public IP: Could not fetch")

# ─── Shutdown ─────────────────────────────────────────────
def shutdown(sig, frame):
    print("\n\n[*] Stopping VPN monitor...")
    print("\n" + "=" * 55)
    print("         VPN MONITOR FINAL REPORT")
    print("=" * 55)
    print(f"  Started              : {stats['start_time']}")
    print(f"  Stopped              : "
          f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total Checks         : {stats['checks']}")
    print(f"  VPN Up               : {stats['vpn_up']}")
    print(f"  VPN Down             : {stats['vpn_down']}")
    print(f"  DNS Leaks            : {stats['dns_leaks']}")
    print(f"  Kill Switch Events   : {stats['killswitch_activations']}")

    if stats["vpn_down"] > 0:
        print(f"\n  [!!!] VPN dropped {stats['vpn_down']} times!")
    else:
        print(f"\n  [OK] VPN stayed stable throughout session")

    if stats["dns_leaks"] > 0:
        print(f"  [!!!] DNS leaks detected {stats['dns_leaks']} times!")
    else:
        print(f"  [OK] No DNS leaks detected")

    filename = f"vpn_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"VPN Monitor Report\n")
        f.write(f"Total Checks: {stats['checks']}\n")
        f.write(f"VPN Up: {stats['vpn_up']}\n")
        f.write(f"VPN Down: {stats['vpn_down']}\n")
        f.write(f"DNS Leaks: {stats['dns_leaks']}\n")
        f.write(f"Kill Switch Events: {stats['killswitch_activations']}\n")

    print(f"\n[*] Report saved: {filename}")
    print("=" * 55)
    sys.exit(0)

# ─── Main ─────────────────────────────────────────────────
print("=" * 55)
print("         VPN PROTECTION MONITOR")
print("=" * 55)
print(f"[*] VPN Interface     : {VPN_INTERFACE}")
print(f"[*] Network Interface : {NETWORK_INTERFACE}")
print(f"[*] Check Interval    : {CHECK_INTERVAL} seconds")
print(f"[*] Press Ctrl+C to stop and generate report")
print("=" * 55)

signal.signal(signal.SIGINT, shutdown)

# Initial status
print("\n[*] Initial Status Check:")
print("-" * 55)
vpn_up = check_vpn_status()
print(f"  VPN Interface : {'UP' if vpn_up else 'DOWN (WireGuard not connected)'}")
print(f"  Kill Switch   : {'ACTIVE' if is_kill_switch_active() else 'INACTIVE'}")
leaked = check_dns_leak()
print(f"  DNS Leak      : {'DETECTED' if leaked else 'None'}")
public_ip = get_public_ip()
print(f"  Public IP     : {public_ip}")
print("-" * 55)

try:
    while True:
        run_status_check()
        time.sleep(CHECK_INTERVAL)
except KeyboardInterrupt:
    shutdown(None, None)
