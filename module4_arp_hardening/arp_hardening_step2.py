import subprocess
import json
import datetime
import os

def get_arp_table():
    result = subprocess.run(
        ["ip", "neigh", "show"],
        capture_output=True,
        text=True
    )
    entries = []
    for line in result.stdout.strip().split("\n"):
        if line:
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                entries.append({
                    "ip": parts[0],
                    "interface": parts[2],
                    "mac": parts[4],
                    "status": parts[-1]
                })
    return entries

def get_gateway():
    """Auto detect gateway IP and MAC"""
    # Get gateway IP
    result = subprocess.run(
        ["ip", "route"],
        capture_output=True,
        text=True
    )
    
    gateway_ip = None
    for line in result.stdout.strip().split("\n"):
        if line.startswith("default"):
            parts = line.split()
            gateway_ip = parts[2]
            break

    if not gateway_ip:
        # Fallback - use known gateway
        gateway_ip = "192.168.137.2"

    # Get gateway MAC from ARP table
    gateway_mac = None
    arp_entries = get_arp_table()
    for entry in arp_entries:
        if entry["ip"] == gateway_ip:
            gateway_mac = entry["mac"]
            break

    return gateway_ip, gateway_mac

def backup_arp_table(entries):
    """Save ARP table to JSON backup file"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arp_backup_{timestamp}.json"
    
    backup_data = {
        "timestamp": timestamp,
        "entries": entries
    }
    
    with open(filename, "w") as f:
        json.dump(backup_data, f, indent=4)
    
    print(f"[+] ARP table backed up to: {filename}")
    return filename

def display_arp_table(entries):
    print("\n" + "=" * 55)
    print("         CURRENT ARP TABLE")
    print("=" * 55)
    print(f"  {'IP Address':<20} {'MAC Address':<20} {'Status'}")
    print("-" * 55)
    for entry in entries:
        print(f"  {entry['ip']:<20} {entry['mac']:<20} {entry['status']}")
    print("=" * 55)

# ─── Main ─────────────────────────────────────────────────
print("[*] Reading current ARP table...")
entries = get_arp_table()
display_arp_table(entries)

print("\n[*] Auto-detecting gateway...")
gateway_ip, gateway_mac = get_gateway()

if gateway_ip and gateway_mac:
    print(f"[+] Gateway detected:")
    print(f"    IP  : {gateway_ip}")
    print(f"    MAC : {gateway_mac}")
else:
    print(f"[!] Gateway IP found: {gateway_ip}")
    print(f"[!] Gateway MAC not in ARP table yet")
    print(f"[*] Try pinging gateway first:")
    print(f"    ping {gateway_ip} -c 3")

print("\n[*] Backing up ARP table...")
backup_file = backup_arp_table(entries)
print(f"[+] Backup complete!")
