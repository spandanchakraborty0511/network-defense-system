from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, DNS
import datetime
import json
import os

# ─── Alert System ─────────────────────────────────────────
alerts = []
alert_count = 0

def fire_alert(rule_name, severity, src_ip, details):
    global alert_count
    alert_count += 1
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    alert = {
        "id": alert_count,
        "timestamp": timestamp,
        "rule": rule_name,
        "severity": severity,
        "src_ip": src_ip,
        "details": details
    }
    alerts.append(alert)
    
    # Color based on severity
    if severity == "HIGH":
        prefix = "[!!!]"
    elif severity == "MEDIUM":
        prefix = "[!! ]"
    else:
        prefix = "[!  ]"
    
    print(f"\n{prefix} ALERT #{alert_count} - {rule_name}")
    print(f"  Severity  : {severity}")
    print(f"  Source IP : {src_ip}")
    print(f"  Time      : {timestamp}")
    print(f"  Details   : {details}")
    print("-" * 50)

# ─── Rule 1: ARP Spoofing Detection ───────────────────────
arp_table = {}

def rule_arp_spoof(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 2:  # ARP Reply
            src_ip = arp.psrc
            src_mac = arp.hwsrc
            
            if src_ip in arp_table:
                if arp_table[src_ip] != src_mac:
                    fire_alert(
                        "ARP_SPOOFING",
                        "HIGH",
                        src_ip,
                        f"MAC changed from {arp_table[src_ip]} to {src_mac}"
                    )
            arp_table[src_ip] = src_mac

# ─── Rule 2: Port Scan Detection ──────────────────────────
port_scan_tracker = {}
PORT_SCAN_THRESHOLD = 10  # ports in 5 seconds

def rule_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        now = datetime.datetime.now()
        
        # SYN packets indicate port scanning
        if flags == 0x02:  # SYN flag
            if src_ip not in port_scan_tracker:
                port_scan_tracker[src_ip] = {
                    "ports": set(),
                    "first_seen": now
                }
            
            port_scan_tracker[src_ip]["ports"].add(dst_port)
            
            # Check time window
            time_diff = (now - port_scan_tracker[src_ip]["first_seen"]).seconds
            port_count = len(port_scan_tracker[src_ip]["ports"])
            
            if time_diff <= 5 and port_count >= PORT_SCAN_THRESHOLD:
                fire_alert(
                    "PORT_SCAN",
                    "MEDIUM",
                    src_ip,
                    f"Scanned {port_count} ports in {time_diff} seconds"
                )
                # Reset tracker
                port_scan_tracker[src_ip] = {
                    "ports": set(),
                    "first_seen": now
                }

# ─── Rule 3: ICMP Flood Detection ─────────────────────────
icmp_tracker = {}
ICMP_THRESHOLD = 20  # packets in 5 seconds

def rule_icmp_flood(packet):
    if packet.haslayer(ICMP):
        src_ip = packet[IP].src
        now = datetime.datetime.now()
        
        if src_ip not in icmp_tracker:
            icmp_tracker[src_ip] = {
                "count": 0,
                "first_seen": now
            }
        
        icmp_tracker[src_ip]["count"] += 1
        time_diff = (now - icmp_tracker[src_ip]["first_seen"]).seconds
        count = icmp_tracker[src_ip]["count"]
        
        if time_diff <= 5 and count >= ICMP_THRESHOLD:
            fire_alert(
                "ICMP_FLOOD",
                "MEDIUM",
                src_ip,
                f"{count} ICMP packets in {time_diff} seconds"
            )
            icmp_tracker[src_ip] = {"count": 0, "first_seen": now}

# ─── Rule 4: DNS Spoofing Detection ───────────────────────
dns_baseline = {}

def rule_dns_spoof(packet):
    if packet.haslayer(DNS):
        dns = packet[DNS]
        
        # Only check DNS responses
        if dns.qr == 1 and dns.ancount > 0:
            src_ip = packet[IP].src
            
            try:
                query_name = dns.qd.qname.decode()
                answer_ip = dns.an.rdata
                
                if query_name in dns_baseline:
                    if dns_baseline[query_name] != str(answer_ip):
                        fire_alert(
                            "DNS_SPOOFING",
                            "HIGH",
                            src_ip,
                            f"{query_name} resolved to {answer_ip} "
                            f"(expected {dns_baseline[query_name]})"
                        )
                else:
                    dns_baseline[query_name] = str(answer_ip)
                    print(f"[DNS] Learned: {query_name} → {answer_ip}")
            except:
                pass

# ─── Main Packet Handler ──────────────────────────────────
def process_packet(packet):
    rule_arp_spoof(packet)
    
    if packet.haslayer(IP):
        rule_port_scan(packet)
        rule_icmp_flood(packet)
        rule_dns_spoof(packet)

# ─── Main ─────────────────────────────────────────────────
print("=" * 55)
print("      CUSTOM IDS - RULE ENGINE v1.0")
print("=" * 55)
print("  Active Rules:")
print("    Rule 1: ARP Spoofing Detection")
print("    Rule 2: Port Scan Detection")
print("    Rule 3: ICMP Flood Detection")
print("    Rule 4: DNS Spoofing Detection")
print("=" * 55)
print("[*] Starting IDS on eth0...")
print("[*] Press Ctrl+C to stop")
print("=" * 55)

try:
    sniff(iface="eth0", prn=process_packet, store=0)
except KeyboardInterrupt:
    print(f"\n[*] IDS stopped")
    print(f"[*] Total alerts fired: {alert_count}")
    
    # Save alerts
    with open("ids_alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)
    print(f"[*] Alerts saved to ids_alerts.json")
