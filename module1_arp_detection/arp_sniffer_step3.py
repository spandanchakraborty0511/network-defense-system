from scapy.all import sniff, ARP
import sqlite3
import datetime

# ─── Database Setup ───────────────────────────────────────
def setup_database():
    conn = sqlite3.connect("arp_monitor.db")
    cursor = conn.cursor()
    
    # Table to store learned MAC-IP mappings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS arp_table (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    ''')
    
    # Table to store alerts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            old_mac TEXT,
            new_mac TEXT,
            alert_type TEXT
        )
    ''')
    
    conn.commit()
    return conn

# ─── Log Alert to Database ────────────────────────────────
def log_alert(conn, ip, old_mac, new_mac, alert_type):
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO alerts (timestamp, ip_address, old_mac, new_mac, alert_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, ip, old_mac, new_mac, alert_type))
    conn.commit()
    print(f"  [DB] Alert saved to database at {timestamp}")

# ─── Update ARP Table in Database ────────────────────────
def update_arp_table(conn, ip, mac):
    cursor = conn.cursor()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if IP exists
    cursor.execute("SELECT mac_address FROM arp_table WHERE ip_address=?", (ip,))
    result = cursor.fetchone()
    
    if result is None:
        # New entry
        cursor.execute('''
            INSERT INTO arp_table (ip_address, mac_address, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
        ''', (ip, mac, now, now))
    else:
        # Update last seen
        cursor.execute('''
            UPDATE arp_table SET mac_address=?, last_seen=?
            WHERE ip_address=?
        ''', (mac, now, ip))
    
    conn.commit()

# ─── In-Memory ARP Table ──────────────────────────────────
arp_table = {}

# ─── Packet Handler ───────────────────────────────────────
def process_packet(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]

        if arp.op == 2:
            sender_ip = arp.psrc
            sender_mac = arp.hwsrc

            if sender_ip not in arp_table:
                arp_table[sender_ip] = sender_mac
                update_arp_table(conn, sender_ip, sender_mac)
                print(f"[+] New device learned: {sender_ip} → {sender_mac}")

            elif arp_table[sender_ip] != sender_mac:
                print(f"\n[!!!] ALERT - MAC CHANGE DETECTED")
                print(f"  IP          : {sender_ip}")
                print(f"  Old MAC     : {arp_table[sender_ip]}")
                print(f"  New MAC     : {sender_mac}")
                print(f"  Possible ARP Spoofing Attack!")
                print("-" * 40)
                log_alert(conn, sender_ip, arp_table[sender_ip], sender_mac, "MAC_CHANGE")
                arp_table[sender_ip] = sender_mac
                update_arp_table(conn, sender_ip, sender_mac)

            else:
                print(f"[OK] {sender_ip} → {sender_mac} (unchanged)")

# ─── Main ─────────────────────────────────────────────────
print("[*] Setting up database...")
conn = setup_database()
print("[*] Database ready")
print("[*] Monitoring ARP traffic... Press Ctrl+C to stop")
sniff(filter="arp", prn=process_packet, store=0)
