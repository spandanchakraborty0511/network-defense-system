import subprocess
import sys
import datetime
import json
import os

# ─── Configuration ────────────────────────────────────────
VPN_INTERFACE = "wg0"        # WireGuard interface name
ALLOWED_INTERFACE = "eth0"   # Your main network interface
LOG_FILE = "kill_switch_log.json"

def run_command(cmd, description=""):
    """Run a system command and return result"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=isinstance(cmd, str)
        )
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr
    except Exception as e:
        return False, str(e)

def log_action(action, status, details=""):
    """Log kill switch actions"""
    log = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            log = json.load(f)
    
    log.append({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "status": status,
        "details": details
    })
    
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=4)

def check_vpn_status():
    """Check if VPN interface is active"""
    result = subprocess.run(
        ["ip", "link", "show", VPN_INTERFACE],
        capture_output=True,
        text=True
    )
    return result.returncode == 0

def enable_kill_switch():
    """Enable kill switch - block all non-VPN traffic"""
    print("[*] Enabling Kill Switch...")
    print("[!] This will block all traffic except VPN")
    print("-" * 50)
    
    rules = [
        # Allow loopback
        (["iptables", "-A", "OUTPUT", "-o", "lo",
          "-j", "ACCEPT"], "Allow loopback"),
        
        # Allow VPN interface traffic
        (["iptables", "-A", "OUTPUT", "-o", VPN_INTERFACE,
          "-j", "ACCEPT"], "Allow VPN interface"),
        
        # Allow WireGuard handshake (UDP port 51820)
        (["iptables", "-A", "OUTPUT", "-o", ALLOWED_INTERFACE,
          "-p", "udp", "--dport", "51820",
          "-j", "ACCEPT"], "Allow WireGuard UDP"),
        
        # Allow established connections
        (["iptables", "-A", "OUTPUT", "-m", "state",
          "--state", "ESTABLISHED,RELATED",
          "-j", "ACCEPT"], "Allow established"),
        
        # Block everything else
        (["iptables", "-A", "OUTPUT",
          "-j", "DROP"], "Block all other traffic"),
    ]
    
    success_count = 0
    for cmd, description in rules:
        success, output = run_command(cmd)
        if success:
            print(f"  [+] {description}")
            success_count += 1
        else:
            print(f"  [!] Failed: {description}")
            print(f"      Error: {output}")
    
    if success_count == len(rules):
        print(f"\n  [✅] Kill switch ENABLED")
        print(f"  [*] All traffic blocked except VPN tunnel")
        log_action("ENABLE", "SUCCESS")
    else:
        print(f"\n  [⚠️] Kill switch partially enabled")
        log_action("ENABLE", "PARTIAL")

def disable_kill_switch():
    """Disable kill switch - restore normal traffic"""
    print("[*] Disabling Kill Switch...")
    print("[*] Restoring normal network traffic")
    print("-" * 50)
    
    # Flush all OUTPUT rules
    rules = [
        (["iptables", "-F", "OUTPUT"], "Flush OUTPUT rules"),
        (["iptables", "-P", "OUTPUT", "ACCEPT"], "Set default ACCEPT"),
    ]
    
    for cmd, description in rules:
        success, output = run_command(cmd)
        if success:
            print(f"  [+] {description}")
        else:
            print(f"  [!] Failed: {description}")
    
    print(f"\n  [✅] Kill switch DISABLED")
    print(f"  [*] Normal traffic restored")
    log_action("DISABLE", "SUCCESS")

def check_kill_switch_status():
    """Check current iptables rules"""
    print("[*] Current firewall rules:")
    print("-" * 50)
    
    result = subprocess.run(
        ["iptables", "-L", "OUTPUT", "-n", "--line-numbers"],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    
    # Check if kill switch is active
    if "DROP" in result.stdout:
        print("  [✅] Kill switch is ACTIVE")
        return True
    else:
        print("  [❌] Kill switch is NOT active")
        return False

def monitor_vpn_and_killswitch():
    """Monitor VPN status and auto enable kill switch"""
    print("[*] Monitoring VPN connection...")
    print("[*] Kill switch will auto-enable if VPN drops")
    print("-" * 50)
    
    import time
    vpn_was_up = check_vpn_status()
    
    while True:
        vpn_is_up = check_vpn_status()
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        if vpn_is_up:
            print(f"  [{timestamp}] VPN is UP - Traffic flowing through tunnel")
        else:
            print(f"  [{timestamp}] VPN is DOWN - Kill switch activated!")
            enable_kill_switch()
            log_action("AUTO_KILLSWITCH", "VPN_DOWN")
        
        vpn_was_up = vpn_is_up
        time.sleep(5)

# ─── Main ─────────────────────────────────────────────────
print("=" * 55)
print("         VPN KILL SWITCH TOOL")
print("=" * 55)
print(f"  VPN Interface     : {VPN_INTERFACE}")
print(f"  Network Interface : {ALLOWED_INTERFACE}")
print("=" * 55)

print("\nOptions:")
print("  1 - Check kill switch status")
print("  2 - Enable kill switch")
print("  3 - Disable kill switch")
print("  4 - Monitor VPN and auto kill switch")

choice = input("\nEnter choice (1-4): ").strip()

if choice == "1":
    check_kill_switch_status()
elif choice == "2":
    enable_kill_switch()
elif choice == "3":
    disable_kill_switch()
elif choice == "4":
    monitor_vpn_and_killswitch()
else:
    print("[!] Invalid choice")
