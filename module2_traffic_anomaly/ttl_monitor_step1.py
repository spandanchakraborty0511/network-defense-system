from scapy.all import sniff, IP
import datetime

# Store baseline TTL values
# Format: { "IP address" : TTL value }
ttl_table = {}

# How much TTL change triggers an alert
TTL_THRESHOLD = 5

def process_packet(packet):
    # Only process packets with IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ttl = packet[IP].ttl

        # Case 1 - New IP, learn its TTL
        if src_ip not in ttl_table:
            ttl_table[src_ip] = ttl
            print(f"[+] New device learned: {src_ip} TTL={ttl}")

        # Case 2 - Known IP, check TTL change
        else:
            baseline_ttl = ttl_table[src_ip]
            ttl_diff = abs(baseline_ttl - ttl)

            if ttl_diff > TTL_THRESHOLD:
                print(f"\n[!!!] TTL ANOMALY DETECTED")
                print(f"  Source IP    : {src_ip}")
                print(f"  Expected TTL : {baseline_ttl}")
                print(f"  Current TTL  : {ttl}")
                print(f"  Difference   : {ttl_diff}")
                print(f"  Possible MITM attack!")
                print("-" * 40)
            else:
                print(f"[OK] {src_ip} TTL={ttl} (normal)")

print("[*] Starting TTL monitor on eth0...")
print("[*] Press Ctrl+C to stop")
print("=" * 50)
sniff(iface="eth0", filter="ip", prn=process_packet, store=0)
