from scapy.all import sniff, IP, ICMP, sr1
import datetime
import threading
import time
import sqlite3
import signal
import sys

# ─── Configuration ────────────────────────────────────────
INTERFACE = "eth0"
TARGET_IP = "192.168.137.1"
TTL_THRESHOLD = 5
LATENCY_THRESHOLD = 50  # ms
LATENCY_CHECK_INTERVAL = 3  # seconds

# ─── Database Setup ───────────────────────────────────────
conn = sqlite3.connect("traffic_anomaly.db")

def setup_database():
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ttl_baseline (
            ip_address TEXT PRIMARY KEY,
            baseline_ttl INTEGER,
            first_seen TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            anomaly_type TEXT,
            source_ip TEXT,
            details TEXT
        )
    ''')
    conn.commit()

def log_anomaly(anomaly_type, source_ip, details):
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO anomalies (timestamp, anomaly_type, source_ip, details)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, anomaly_type, source_ip, details))
    conn.commit()
    print(f"  [DB] Anomaly logged at {timestamp}")

# ─── Shared State ─────────────────────────────────────────
ttl_table = {}
packet_ids = {}
alert_count = 0
anomaly_types = {
    "TTL": 0,
    "LATENCY": 0,
    "DUPLICATE": 0
}

# ─── TTL Detection ────────────────────────────────────────
def check_ttl(src_ip, ttl):
    global alert_count
    if src_ip not in ttl_table:
        ttl_table[src_ip] = ttl
        cursor = conn.cursor()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT OR IGNORE INTO ttl_baseline (ip_address, baseline_ttl, first_seen)
            VALUES (?, ?, ?)
        ''', (src_ip, ttl, now))
        conn.commit()
        print(f"[+] New device: {src_ip} TTL={ttl}")
    else:
        diff = abs(ttl_table[src_ip] - ttl)
        if diff > TTL_THRESHOLD:
            alert_count += 1
            anomaly_types["TTL"] += 1
            print(f"\n[!!!] TTL ANOMALY - {src_ip}")
            print(f"  Expected: {ttl_table[src_ip]} | Got: {ttl}")
            print("-" * 40)
            log_anomaly("TTL_ANOMALY", src_ip,
                f"Expected={ttl_table[src_ip]} Got={ttl}")

# ─── Duplicate Packet Detection ───────────────────────────
def check_duplicate(src_ip, packet_id):
    global alert_count
    key = f"{src_ip}_{packet_id}"
    if key in packet_ids:
        alert_count += 1
        anomaly_types["DUPLICATE"] += 1
        print(f"\n[!!!] DUPLICATE PACKET - {src_ip}")
        print(f"  Packet ID: {packet_id}")
        print(f"  Possible MITM forwarding detected")
        print("-" * 40)
        log_anomaly("DUPLICATE_PACKET", src_ip,
            f"PacketID={packet_id}")
    else:
        packet_ids[key] = True
        # Keep table small
        if len(packet_ids) > 1000:
            packet_ids.clear()

# ─── Packet Handler ───────────────────────────────────────
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ttl = packet[IP].ttl
        packet_id = packet[IP].id

        check_ttl(src_ip, ttl)
        check_duplicate(src_ip, packet_id)

# ─── Latency Monitor ──────────────────────────────────────
def monitor_latency():
    global alert_count
    baseline_samples = []
    print(f"[*] Building latency baseline for {TARGET_IP}...")

    while True:
        try:
            start = time.time()
            reply = sr1(IP(dst=TARGET_IP)/ICMP(),
                       timeout=2, verbose=0)
            end = time.time()

            if reply:
                latency = round((end - start) * 1000, 2)

                if len(baseline_samples) < 5:
                    baseline_samples.append(latency)
                    print(f"[~] Baseline sample {len(baseline_samples)}/5: "
                          f"{latency}ms")
                else:
                    avg = sum(baseline_samples) / len(baseline_samples)
                    diff = latency - avg

                    if diff > LATENCY_THRESHOLD:
                        alert_count += 1
                        anomaly_types["LATENCY"] += 1
                        print(f"\n[!!!] LATENCY SPIKE - {TARGET_IP}")
                        print(f"  Baseline: {round(avg, 2)}ms")
                        print(f"  Current : {latency}ms")
                        print(f"  Spike   : +{round(diff, 2)}ms")
                        print("-" * 40)
                        log_anomaly("LATENCY_SPIKE", TARGET_IP,
                            f"Baseline={round(avg,2)}ms Current={latency}ms")
                    else:
                        print(f"[OK] Latency {TARGET_IP}: "
                              f"{latency}ms (avg={round(avg,2)}ms)")

        except Exception as e:
            print(f"[!] Latency check error: {e}")

        time.sleep(LATENCY_CHECK_INTERVAL)

# ─── Shutdown & Report ────────────────────────────────────
def shutdown(sig, frame):
    print("\n\n[*] Stopping detector...")
    print("\n" + "=" * 50)
    print("     TRAFFIC ANOMALY DETECTION REPORT")
    print("=" * 50)
    print(f"  Total Alerts     : {alert_count}")
    print(f"  TTL Anomalies    : {anomaly_types['TTL']}")
    print(f"  Latency Spikes   : {anomaly_types['LATENCY']}")
    print(f"  Duplicate Packets: {anomaly_types['DUPLICATE']}")

    if alert_count == 0:
        print("\n  Threat Level: NONE - Network looks clean")
    elif alert_count <= 3:
        print("\n  Threat Level: LOW")
    elif alert_count <= 10:
        print("\n  Threat Level: MEDIUM - Possible MITM")
    else:
        print("\n  Threat Level: HIGH - Active MITM attack")

    print("\n  Known Devices:")
    for ip, ttl in ttl_table.items():
        print(f"    {ip} baseline TTL={ttl}")

    filename = f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"Total Alerts: {alert_count}\n")
        f.write(f"TTL Anomalies: {anomaly_types['TTL']}\n")
        f.write(f"Latency Spikes: {anomaly_types['LATENCY']}\n")
        f.write(f"Duplicate Packets: {anomaly_types['DUPLICATE']}\n")

    print(f"\n[*] Report saved: {filename}")
    print("=" * 50)
    conn.close()
    sys.exit(0)

# ─── Main ─────────────────────────────────────────────────
print("[*] Setting up database...")
setup_database()
print("[*] Starting Traffic Anomaly Detector")
print(f"[*] Interface : {INTERFACE}")
print(f"[*] Target IP : {TARGET_IP}")
print("[*] Press Ctrl+C to stop and generate report")
print("=" * 50)

signal.signal(signal.SIGINT, shutdown)

latency_thread = threading.Thread(
    target=monitor_latency,
    daemon=True
)
latency_thread.start()

sniff(iface=INTERFACE, filter="ip", prn=process_packet, store=0)
