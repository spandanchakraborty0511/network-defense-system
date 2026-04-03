#!/usr/bin/env python3
# Module 1 - ARP Spoofing Detector (Fixed)

from scapy.all import *
import sqlite3, datetime, os, signal, sys

IFACE   = "eth0"
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arp_monitor.db")

# ── Database Setup ─────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS arp_table (
        ip_address TEXT PRIMARY KEY,
        mac_address TEXT,
        first_seen TEXT,
        last_seen TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        old_mac TEXT,
        new_mac TEXT,
        alert_type TEXT
    )''')
    conn.commit()
    conn.close()
    print(f"[*] Database initialized → {DB_FILE}")

def get_conn():
    return sqlite3.connect(DB_FILE)

# ── ARP Table ──────────────────────────────────────────────
arp_table = {}  # ip -> mac (in memory)

def load_arp_table():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT ip_address, mac_address FROM arp_table")
    for ip, mac in c.fetchall():
        arp_table[ip] = mac
    conn.close()
    print(f"[*] Loaded {len(arp_table)} known devices from database")

def save_arp_entry(ip, mac):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO arp_table
                 (ip_address, mac_address, first_seen, last_seen)
                 VALUES (?, ?, COALESCE((SELECT first_seen FROM arp_table WHERE ip_address=?), ?), ?)''',
              (ip, mac, ip, now, now))
    conn.commit()
    conn.close()

def save_alert(ip, old_mac, new_mac, alert_type):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_conn()
    c = conn.cursor()
    c.execute('''INSERT INTO alerts (timestamp, ip_address, old_mac, new_mac, alert_type)
                 VALUES (?, ?, ?, ?, ?)''',
              (now, ip, old_mac, new_mac, alert_type))
    conn.commit()
    conn.close()

# ── Packet Handler ─────────────────────────────────────────
alert_count = 0

def handle_arp(pkt):
    global alert_count

    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]

    # Only process ARP replies (op=2) and requests (op=1)
    src_ip  = arp.psrc
    src_mac = arp.hwsrc

    # Skip broadcast and empty
    if src_ip == "0.0.0.0" or src_mac == "ff:ff:ff:ff:ff:ff":
        return

    # First time seeing this IP
    if src_ip not in arp_table:
        arp_table[src_ip] = src_mac
        save_arp_entry(src_ip, src_mac)
        print(f"  [+] NEW DEVICE: {src_ip} → {src_mac}")

    # MAC changed — possible ARP spoof!
    elif arp_table[src_ip] != src_mac:
        old_mac = arp_table[src_ip]
        alert_count += 1

        print(f"\n  \033[91m[!] ARP SPOOF DETECTED!\033[0m")
        print(f"      IP      : {src_ip}")
        print(f"      OLD MAC : {old_mac}")
        print(f"      NEW MAC : {src_mac}")
        print(f"      Time    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Update table and save alert
        arp_table[src_ip] = src_mac
        save_arp_entry(src_ip, src_mac)
        save_alert(src_ip, old_mac, src_mac, "MAC_CHANGE")

# ── Report ─────────────────────────────────────────────────
def print_report(sig=None, frame=None):
    print("\n" + "=" * 55)
    print("   ARP MONITOR REPORT")
    print("=" * 55)
    print(f"  Known Devices : {len(arp_table)}")
    print(f"  Total Alerts  : {alert_count}")

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20")
    rows = c.fetchall()
    conn.close()

    if rows:
        print(f"\n  ALERTS:")
        for r in rows:
            print(f"  [{r[1]}] {r[2]} | {r[3]} → {r[4]}")
    else:
        print("\n  No alerts recorded.")

    print("\n  KNOWN DEVICES:")
    for ip, mac in arp_table.items():
        print(f"  {ip:20s} → {mac}")
    print("=" * 55)
    sys.exit(0)

signal.signal(signal.SIGINT, print_report)

# ── Main ───────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("   MODULE 1 — ARP SPOOFING DETECTOR")
    print("=" * 55)
    print(f"  [*] Interface : {IFACE}")
    print(f"  [*] Database  : {DB_FILE}")
    print(f"  [*] Press Ctrl+C to stop\n")

    init_db()
    load_arp_table()

    print(f"\n[*] Sniffing ARP packets on {IFACE}...")
    print("[*] Waiting for ARP traffic — run ping to generate traffic\n")

    sniff(iface=IFACE, filter="arp", prn=handle_arp, store=0)

if __name__ == "__main__":
    main()
