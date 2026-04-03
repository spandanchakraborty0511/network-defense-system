import subprocess
import json
import datetime

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

def set_static_arp(ip, mac, interface="eth0"):
    """Lock an ARP entry as static"""
    try:
        # Remove existing dynamic entry first
        subprocess.run(
            ["ip", "neigh", "del", ip, "dev", interface],
            capture_output=True
        )
        
        # Add new static entry
        result = subprocess.run(
            ["ip", "neigh", "add",
             ip, "lladdr", mac,
             "dev", interface,
             "nud", "permanent"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"[+] LOCKED: {ip} → {mac}")
            return True
        else:
            print(f"[!] Failed to lock {ip}: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[!] Error setting static ARP: {e}")
        return False

def verify_static_entries(critical_ips):
    """Check if entries are correctly set as permanent"""
    result = subprocess.run(
        ["ip", "neigh", "show"],
        capture_output=True,
        text=True
    )
    
    print("\n" + "=" * 55)
    print("         ARP HARDENING VERIFICATION")
    print("=" * 55)
    print(f"  {'IP Address':<20} {'MAC Address':<20} {'Status'}")
    print("-" * 55)
    
    for line in result.stdout.strip().split("\n"):
        if line:
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                mac = parts[4]
                status = parts[-1]
                
                if ip in critical_ips:
                    if status == "PERMANENT":
                        print(f"  {ip:<20} {mac:<20} ✅ LOCKED")
                    else:
                        print(f"  {ip:<20} {mac:<20} ⚠️  {status}")
                else:
                    print(f"  {ip:<20} {mac:<20} {status}")
    
    print("=" * 55)

def restore_dynamic_arp(ip, mac, interface="eth0"):
    """Restore entry back to dynamic if needed"""
    subprocess.run(
        ["ip", "neigh", "del", ip, "dev", interface],
        capture_output=True
    )
    subprocess.run(
        ["ip", "neigh", "add",
         ip, "lladdr", mac,
         "dev", interface,
         "nud", "stale"],
        capture_output=True
    )
    print(f"[*] Restored dynamic entry: {ip} → {mac}")

# ─── Critical devices to protect ─────────────────────────
CRITICAL_DEVICES = [
    {"ip": "192.168.137.2",   "mac": "00:50:56:e3:5f:5d", "name": "Gateway"},
    {"ip": "192.168.137.1",   "mac": "00:50:56:c0:00:08", "name": "Windows VM"},
    {"ip": "192.168.137.254", "mac": "00:50:56:fd:d0:c9", "name": "DHCP Server"},
]

# ─── Main ─────────────────────────────────────────────────
print("[*] Starting ARP Cache Hardening...")
print(f"[*] Protecting {len(CRITICAL_DEVICES)} critical devices")
print("=" * 55)

success_count = 0
critical_ips = []

for device in CRITICAL_DEVICES:
    print(f"\n[*] Locking {device['name']}...")
    if set_static_arp(device["ip"], device["mac"]):
        success_count += 1
        critical_ips.append(device["ip"])

print(f"\n[+] Successfully locked {success_count}/{len(CRITICAL_DEVICES)} entries")

# Verify all entries
verify_static_entries(critical_ips)

print(f"\n[*] ARP hardening complete!")
print(f"[*] These entries cannot be changed by ARP spoofing attacks")
