from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, DNS, Raw
import datetime
import json
import signal
import sys

# ─── Stats ────────────────────────────────────────────────
stats = {
    "total_alerts": 0,
    "by_rule": {
        "ARP_SPOOFING": 0,
        "PORT_SCAN": 0,
        "ICMP_FLOOD": 0,
        "DNS_SPOOFING": 0,
        "SSL_STRIP": 0
    },
    "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

alerts = []

# ─── Alert System ─────────────────────────────────────────
def fire_alert(rule_name, severity, src_ip, details):
    stats["total_alerts"] += 1
    stats["by_rule"][rule_name] += 1
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = {
        "id": stats["total_alerts"],
        "timestamp": timestamp,
        "rule": rule_name,
        "severity": severity,
        "src_ip": src_ip,
        "details": details
    }
    alerts.append(alert)

    if severity == "HIGH":
        prefix = "[!!!]"
    elif severity == "MEDIUM":
        prefix = "[!! ]"
    else:
        prefix = "[!  ]"

    print(f"\n{prefix} ALERT #{stats['total_alerts']} - {rule_name}")
    print(f"  Severity  : {severity}")
    print(f"  Source IP : {src_ip}")
    print(f"  Time      : {timestamp}")
    print(f"  Details   : {details}")
    print("-" * 50)

# ─── Rule 1: ARP Spoofing ─────────────────────────────────
arp_table = {}

def rule_arp_spoof(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 2:
            src_ip = arp.psrc
            src_mac = arp.hwsrc
            if src_ip in arp_table:
                if arp_table[src_ip] != src_mac:
                    fire_alert(
                        "ARP_SPOOFING", "HIGH", src_ip,
                        f"MAC changed from {arp_table[src_ip]} to {src_mac}"
                    )
            arp_table[src_ip] = src_mac

# ─── Rule 2: Port Scan ────────────────────────────────────
port_scan_tracker = {}
PORT_SCAN_THRESHOLD = 10

def rule_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        now = datetime.datetime.now()

        if flags == 0x02:
            if src_ip not in port_scan_tracker:
                port_scan_tracker[src_ip] = {
                    "ports": set(),
                    "first_seen": now
                }

            port_scan_tracker[src_ip]["ports"].add(dst_port)
            time_diff = (
                now - port_scan_tracker[src_ip]["first_seen"]
            ).seconds
            port_count = len(port_scan_tracker[src_ip]["ports"])

            if time_diff <= 5 and port_count >= PORT_SCAN_THRESHOLD:
                fire_alert(
                    "PORT_SCAN", "MEDIUM", src_ip,
                    f"Scanned {port_count} ports in {time_diff} seconds"
                )
                port_scan_tracker[src_ip] = {
                    "ports": set(),
                    "first_seen": now
                }

# ─── Rule 3: ICMP Flood ───────────────────────────────────
icmp_tracker = {}
ICMP_THRESHOLD = 20

def rule_icmp_flood(packet):
    if packet.haslayer(ICMP):
        src_ip = packet[IP].src
        now = datetime.datetime.now()

        if src_ip not in icmp_tracker:
            icmp_tracker[src_ip] = {"count": 0, "first_seen": now}

        icmp_tracker[src_ip]["count"] += 1
        time_diff = (
            now - icmp_tracker[src_ip]["first_seen"]
        ).seconds
        count = icmp_tracker[src_ip]["count"]

        if time_diff <= 5 and count >= ICMP_THRESHOLD:
            fire_alert(
                "ICMP_FLOOD", "MEDIUM", src_ip,
                f"{count} ICMP packets in {time_diff} seconds"
            )
            icmp_tracker[src_ip] = {"count": 0, "first_seen": now}

# ─── Rule 4: DNS Spoofing ─────────────────────────────────
dns_baseline = {}

def rule_dns_spoof(packet):
    if packet.haslayer(DNS):
        dns = packet[DNS]
        if dns.qr == 1 and dns.ancount > 0:
            src_ip = packet[IP].src
            try:
                query_name = dns.qd.qname.decode()
                answer_ip = dns.an.rdata
                if query_name in dns_baseline:
                    if dns_baseline[query_name] != str(answer_ip):
                        fire_alert(
                            "DNS_SPOOFING", "HIGH", src_ip,
                            f"{query_name} resolved to {answer_ip} "
                            f"expected {dns_baseline[query_name]}"
                        )
                else:
                    dns_baseline[query_name] = str(answer_ip)
                    print(f"[DNS] Learned: {query_name} → {answer_ip}")
            except:
                pass

# ─── Rule 5: SSL Strip Detection ─────────────────────────
def rule_ssl_strip(packet):
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            # Detect HTTP traffic on port 80
            # that contains sensitive keywords
            if dst_port == 80:
                suspicious_keywords = [
                    "password", "passwd", "login",
                    "credential", "token", "session"
                ]
                for keyword in suspicious_keywords:
                    if keyword in payload.lower():
                        fire_alert(
                            "SSL_STRIP", "HIGH", src_ip,
                            f"Sensitive keyword '{keyword}' "
                            f"found in HTTP traffic on port 80"
                        )
                        break

            # Detect HTTP responses with
            # Location header pointing to HTTP
            if "Location: http://" in payload:
                fire_alert(
                    "SSL_STRIP", "HIGH", src_ip,
                    "HTTP redirect detected - possible SSL strip"
                )
        except:
            pass

# ─── Main Packet Handler ──────────────────────────────────
packets_processed = 0

def process_packet(packet):
    global packets_processed
    packets_processed += 1

    rule_arp_spoof(packet)

    if packet.haslayer(IP):
        rule_port_scan(packet)
        rule_icmp_flood(packet)
        rule_dns_spoof(packet)
        rule_ssl_strip(packet)

    if packets_processed % 100 == 0:
        print(f"[*] Packets processed: {packets_processed} "
              f"| Alerts: {stats['total_alerts']}")

# ─── Shutdown & Report ────────────────────────────────────
def shutdown(sig, frame):
    print("\n\n[*] Stopping IDS...")
    print("\n" + "=" * 55)
    print("           IDS FINAL REPORT")
    print("=" * 55)
    print(f"  Started          : {stats['start_time']}")
    print(f"  Stopped          : "
          f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Packets Processed: {packets_processed}")
    print(f"  Total Alerts     : {stats['total_alerts']}")
    print(f"\n  Alerts by Rule:")
    for rule, count in stats["by_rule"].items():
        bar = "█" * count
        print(f"    {rule:<20} : {count:>3} {bar}")

    if stats["total_alerts"] == 0:
        print(f"\n  Threat Level: NONE - Network clean")
    elif stats["total_alerts"] <= 5:
        print(f"\n  Threat Level: LOW")
    elif stats["total_alerts"] <= 15:
        print(f"\n  Threat Level: MEDIUM")
    else:
        print(f"\n  Threat Level: HIGH - Active attacks detected")

    # Save alerts
    with open("ids_alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)
    print(f"\n[*] Alerts saved: ids_alerts.json")

    # Save report
    filename = f"ids_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"IDS Report\n")
        f.write(f"Total Alerts: {stats['total_alerts']}\n")
        f.write(f"Packets Processed: {packets_processed}\n")
        for rule, count in stats["by_rule"].items():
            f.write(f"{rule}: {count}\n")

    print(f"[*] Report saved: {filename}")
    print("=" * 55)
    sys.exit(0)

# ─── Main ─────────────────────────────────────────────────
print("=" * 55)
print("      CUSTOM IDS - FINAL v2.0")
print("=" * 55)
print("  Active Rules:")
print("    Rule 1: ARP Spoofing    (HIGH)")
print("    Rule 2: Port Scan       (MEDIUM)")
print("    Rule 3: ICMP Flood      (MEDIUM)")
print("    Rule 4: DNS Spoofing    (HIGH)")
print("    Rule 5: SSL Strip       (HIGH)")
print("=" * 55)
print("[*] Starting IDS on eth0...")
print("[*] Press Ctrl+C to stop and generate report")
print("=" * 55)

signal.signal(signal.SIGINT, shutdown)
sniff(iface="eth0", prn=process_packet, store=0)
