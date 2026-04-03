#!/usr/bin/env python3
# Alert Simulator — injects fake alerts into all module databases

import sqlite3, json, time, datetime, random, os

ARP_DB    = "module1_arp_detection/arp_monitor.db"
TRAFFIC_DB= "module2_traffic_anomaly/traffic_anomaly.db"
IDS_JSON  = "module8_ids/ids_alerts.json"

IPS = ["192.168.137.1","192.168.137.2","192.168.137.50","192.168.137.99"]
MACS= ["aa:bb:cc:dd:ee:ff","de:ad:be:ef:00:01","ba:d0:ca:fe:11:22"]

def inject_arp_alert():
    try:
        conn = sqlite3.connect(ARP_DB)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, ip_address TEXT,
            old_mac TEXT, new_mac TEXT, alert_type TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS arp_table (
            ip_address TEXT PRIMARY KEY, mac_address TEXT,
            first_seen TEXT, last_seen TEXT)''')
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip  = random.choice(IPS)
        old = "00:50:56:e3:5f:5d"
        new = random.choice(MACS)
        c.execute("INSERT INTO alerts (timestamp,ip_address,old_mac,new_mac,alert_type) VALUES (?,?,?,?,?)",
                  (now, ip, old, new, "MAC_CHANGE"))
        c.execute("INSERT OR REPLACE INTO arp_table VALUES (?,?,?,?)",
                  (ip, new, now, now))
        conn.commit()
        conn.close()
        print(f"  [ARP]     {ip} MAC changed → {new}")
    except Exception as e:
        print(f"  [ARP ERROR] {e}")

def inject_traffic_alert():
    try:
        conn = sqlite3.connect(TRAFFIC_DB)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, anomaly_type TEXT,
            source_ip TEXT, details TEXT)''')
        now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        types= ["TTL_ANOMALY","DUPLICATE_PACKET","LATENCY_SPIKE"]
        t    = random.choice(types)
        ip   = random.choice(IPS)
        c.execute("INSERT INTO anomalies (timestamp,anomaly_type,source_ip,details) VALUES (?,?,?,?)",
                  (now, t, ip, f"Anomaly detected from {ip}"))
        conn.commit()
        conn.close()
        print(f"  [TRAFFIC] {t} from {ip}")
    except Exception as e:
        print(f"  [TRAFFIC ERROR] {e}")

def inject_ids_alert():
    try:
        rules = [
            ("ARP_SPOOFING",  "HIGH"),
            ("PORT_SCAN",     "MEDIUM"),
            ("ICMP_FLOOD",    "MEDIUM"),
            ("DNS_SPOOFING",  "HIGH"),
            ("SSL_STRIP",     "HIGH"),
        ]
        if os.path.exists(IDS_JSON):
            with open(IDS_JSON) as f:
                alerts = json.load(f)
        else:
            alerts = []

        now        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rule, sev  = random.choice(rules)
        ip         = random.choice(IPS)
        alerts.append({
            "timestamp": now,
            "rule":      rule,
            "src_ip":    ip,
            "severity":  sev,
            "details":   f"{rule} detected from {ip}"
        })
        # Keep last 100 alerts only
        alerts = alerts[-100:]
        with open(IDS_JSON, "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"  [IDS]     {rule} [{sev}] from {ip}")
    except Exception as e:
        print(f"  [IDS ERROR] {e}")

def main():
    print("=" * 50)
    print("   ALERT SIMULATOR")
    print("=" * 50)
    print("[*] Injecting alerts every 5 seconds...")
    print("[*] Press Ctrl+C to stop\n")

    count = 0
    while True:
        count += 1
        print(f"\n[Batch {count}] {datetime.datetime.now().strftime('%H:%M:%S')}")
        inject_arp_alert()
        inject_traffic_alert()
        inject_ids_alert()
        # Sometimes inject multiple
        if random.random() > 0.5:
            inject_ids_alert()
        if random.random() > 0.7:
            inject_arp_alert()
        time.sleep(5)

if __name__ == "__main__":
    main()
