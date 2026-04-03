import subprocess
import json
import datetime
import time
import signal
import sys
import os

# ─── Configuration ────────────────────────────────────────
INTERFACE = "eth0"
CHECK_INTERVAL = 30  # seconds between validation checks

CRITICAL_DEVICES = [
    {"ip": "192.168.137.2",   "mac": "00:50:56:e3:5f:5d", "name": "Gateway"},
    {"ip": "192.168.137.1",   "mac": "00:50:56:c0:00:08", "name": "Windows VM"},
    {"ip": "192.168.137.254", "mac": "00:50:56:fd:d0:c9", "name": "DHCP Server"},
]

# ─── Counters ─────────────────────────────────────────────
stats = {
    "checks": 0,
    "violations": 0,
    "repairs": 0,
    "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

# ─── Get ARP Table ────────────────────────────────────────
def get_arp_table():
    result = subprocess.run(
        ["ip", "neigh", "show"],
        capture_output=True,
        text=True
    )
    entries = {}
    for line in result.stdout.strip().split("\n"):
        if line:
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                entries[parts[0]] = {
                    "mac": parts[4],
                    "interface": parts[2],
                    "status": parts[-1]
                }
    return entries

# ─── Backup ───────────────────────────────────────────────
def backup_arp_table():
    entries = get_arp_table()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arp_backup_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump({"timestamp": timestamp, "entries": entries}, f, indent=4)
    print(f"[+] Backup saved: {filename}")
    return filename

# ─── Set Static Entry ─────────────────────────────────────
def set_static_arp(ip, mac):
    subprocess.run(
        ["ip", "neigh", "del", ip, "dev", INTERFACE],
        capture_output=True
    )
    result = subprocess.run(
        ["ip", "neigh", "add", ip, "lladdr", mac,
         "dev", INTERFACE, "nud", "permanent"],
        capture_output=True,
        text=True
    )
    return result.returncode == 0

# ─── Validate Entries ─────────────────────────────────────
def validate_and_repair():
    stats["checks"] += 1
    current_arp = get_arp_table()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n[{timestamp}] Running validation check #{stats['checks']}")
    
    all_ok = True
    for device in CRITICAL_DEVICES:
        ip = device["ip"]
        expected_mac = device["mac"]
        name = device["name"]
        
        if ip not in current_arp:
            print(f"  [!] MISSING: {name} ({ip}) not in ARP table")
            print(f"  [*] Restoring entry...")
            if set_static_arp(ip, expected_mac):
                stats["repairs"] += 1
                print(f"  [+] Restored: {ip} → {expected_mac}")
            all_ok = False

        elif current_arp[ip]["mac"] != expected_mac:
            stats["violations"] += 1
            stats["repairs"] += 1
            print(f"  [!!!] VIOLATION: {name} ({ip})")
            print(f"    Expected MAC : {expected_mac}")
            print(f"    Current MAC  : {current_arp[ip]['mac']}")
            print(f"  [*] Repairing entry...")
            if set_static_arp(ip, expected_mac):
                print(f"  [+] Repaired successfully")
            all_ok = False

        elif current_arp[ip]["status"] != "PERMANENT":
            print(f"  [!] {name} ({ip}) is not PERMANENT, relocking...")
            if set_static_arp(ip, expected_mac):
                stats["repairs"] += 1
                print(f"  [+] Relocked successfully")
            all_ok = False

        else:
            print(f"  [OK] {name} ({ip}) → {expected_mac} PERMANENT")

    if all_ok:
        print(f"  [+] All entries verified and secure")

# ─── Shutdown ─────────────────────────────────────────────
def shutdown(sig, frame):
    print("\n\n[*] Stopping ARP hardening monitor...")
    print("\n" + "=" * 50)
    print("      ARP HARDENING SESSION REPORT")
    print("=" * 50)
    print(f"  Started          : {stats['start_time']}")
    print(f"  Stopped          : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total Checks     : {stats['checks']}")
    print(f"  Violations Found : {stats['violations']}")
    print(f"  Repairs Made     : {stats['repairs']}")
    
    if stats["violations"] == 0:
        print(f"\n  Status: CLEAN - No spoofing attempts detected")
    else:
        print(f"\n  Status: ATTACKED - {stats['violations']} spoofing attempts blocked")
    
    print("=" * 50)
    sys.exit(0)

# ─── Main ─────────────────────────────────────────────────
print("=" * 50)
print("      ARP CACHE HARDENING TOOL")
print("=" * 50)
print(f"[*] Interface      : {INTERFACE}")
print(f"[*] Check Interval : {CHECK_INTERVAL} seconds")
print(f"[*] Protecting     : {len(CRITICAL_DEVICES)} devices")
print("=" * 50)

# Step 1 - Backup
print("\n[*] Step 1: Backing up ARP table...")
backup_arp_table()

# Step 2 - Initial lock
print("\n[*] Step 2: Locking critical entries...")
for device in CRITICAL_DEVICES:
    if set_static_arp(device["ip"], device["mac"]):
        print(f"  [+] Locked: {device['name']} ({device['ip']})")

# Step 3 - Continuous monitoring
print(f"\n[*] Step 3: Starting continuous monitor...")
print(f"[*] Checking every {CHECK_INTERVAL} seconds")
print(f"[*] Press Ctrl+C to stop\n")

signal.signal(signal.SIGINT, shutdown)

while True:
    validate_and_repair()
    time.sleep(CHECK_INTERVAL)
