import subprocess
import json
import datetime

def get_arp_table():
    """Read current ARP table from system"""
    result = subprocess.run(
        ["ip", "neigh", "show"],
        capture_output=True,
        text=True
    )
    
    entries = []
    for line in result.stdout.strip().split("\n"):
        if line:
            parts = line.split()
            # Line format: IP dev INTERFACE lladdr MAC STATUS
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                interface = parts[2]
                mac = parts[4]
                status = parts[-1]
                entries.append({
                    "ip": ip,
                    "interface": interface,
                    "mac": mac,
                    "status": status
                })
    return entries

def display_arp_table(entries):
    """Display ARP table in clean format"""
    print("\n" + "=" * 55)
    print("         CURRENT ARP TABLE")
    print("=" * 55)
    print(f"  {'IP Address':<20} {'MAC Address':<20} {'Status'}")
    print("-" * 55)
    
    for entry in entries:
        print(f"  {entry['ip']:<20} {entry['mac']:<20} {entry['status']}")
    
    print("=" * 55)
    print(f"  Total entries: {len(entries)}")
    print(f"  Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

# Run it
print("[*] Reading current ARP table...")
entries = get_arp_table()
display_arp_table(entries)
