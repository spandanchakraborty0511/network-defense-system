from scapy.all import sniff, IP, ICMP, sr1
import datetime
import threading
import time

# Store baseline latencies
# Format: { "IP" : [list of latency measurements] }
latency_table = {}
ttl_table = {}
TTL_THRESHOLD = 5
LATENCY_THRESHOLD = 50  # milliseconds

# ─── Latency Checker ──────────────────────────────────────
def measure_latency(target_ip):
    try:
        start = time.time()
        reply = sr1(
            IP(dst=target_ip)/ICMP(),
            timeout=2,
            verbose=0
        )
        end = time.time()

        if reply:
            latency = (end - start) * 1000  # convert to ms
            return round(latency, 2)
    except:
        pass
    return None

def monitor_latency(target_ip):
    print(f"[*] Starting latency monitor for {target_ip}")
    baseline_samples = []

    while True:
        latency = measure_latency(target_ip)

        if latency is not None:
            # Build baseline with first 5 measurements
            if len(baseline_samples) < 5:
                baseline_samples.append(latency)
                print(f"[~] Building baseline for {target_ip}: {latency}ms")

            else:
                avg_baseline = sum(baseline_samples) / len(baseline_samples)
                diff = latency - avg_baseline

                if diff > LATENCY_THRESHOLD:
                    print(f"\n[!!!] LATENCY SPIKE DETECTED")
                    print(f"  Target IP      : {target_ip}")
                    print(f"  Baseline Avg   : {round(avg_baseline, 2)}ms")
                    print(f"  Current        : {latency}ms")
                    print(f"  Spike          : +{round(diff, 2)}ms")
                    print(f"  Possible MITM attack!")
                    print("-" * 40)
                else:
                    print(f"[OK] {target_ip} latency={latency}ms "
                          f"(baseline={round(avg_baseline, 2)}ms)")

        time.sleep(2)  # check every 2 seconds

# ─── TTL Monitor ──────────────────────────────────────────
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ttl = packet[IP].ttl

        if src_ip not in ttl_table:
            ttl_table[src_ip] = ttl
            print(f"[+] New device: {src_ip} TTL={ttl}")
        else:
            baseline_ttl = ttl_table[src_ip]
            ttl_diff = abs(baseline_ttl - ttl)
            if ttl_diff > TTL_THRESHOLD:
                print(f"\n[!!!] TTL ANOMALY DETECTED")
                print(f"  Source IP    : {src_ip}")
                print(f"  Expected TTL : {baseline_ttl}")
                print(f"  Current TTL  : {ttl}")
                print("-" * 40)

# ─── Main ─────────────────────────────────────────────────
TARGET_IP = "192.168.137.1"  # Windows VM IP

print("[*] Starting Network Anomaly Detector")
print(f"[*] Monitoring TTL on eth0")
print(f"[*] Monitoring latency to {TARGET_IP}")
print("[*] Press Ctrl+C to stop")
print("=" * 50)

# Start latency monitor in background thread
latency_thread = threading.Thread(
    target=monitor_latency,
    args=(TARGET_IP,),
    daemon=True
)
latency_thread.start()

# Start TTL sniffer
sniff(iface="eth0", filter="ip", prn=process_packet, store=0)
