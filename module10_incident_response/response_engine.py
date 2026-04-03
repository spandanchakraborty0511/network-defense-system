import json, os, time, datetime, subprocess, threading, sqlite3

# ─── Paths ────────────────────────────────────────────────
IDS_ALERTS = "../module8_ids/ids_alerts.json"
ARP_DB     = "../module1_arp_detection/arp_monitor.db"
LOG_FILE   = "incident_log.json"
BLOCK_FILE = "blocked_ips.json"

# ─── Config ───────────────────────────────────────────────
CHECK_INTERVAL   = 5
AUTO_UNBLOCK     = 120
HIGH_THRESHOLD   = 1
MEDIUM_THRESHOLD = 5

# ─── State ────────────────────────────────────────────────
processed_ids = set()
blocked_ips   = {}
incident_log  = []
medium_counts = {}

# ─── Helpers ──────────────────────────────────────────────
def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg, color=""):
    RED="\033[91m"; GRN="\033[92m"; YLW="\033[93m"; BLU="\033[94m"; RST="\033[0m"
    c = {"red":RED,"green":GRN,"yellow":YLW,"blue":BLU}.get(color,"")
    print(f"  [{now()}] {c}{msg}{RST}")

def save_log():
    try:
        with open(LOG_FILE,"w") as f: json.dump(incident_log,f,indent=2)
    except: pass

def save_blocked():
    try:
        with open(BLOCK_FILE,"w") as f:
            json.dump({ip:{"blocked_at":v["blocked_at"],"reason":v["reason"],
                           "unblock_at":v["unblock_at"]} for ip,v in blocked_ips.items()},f,indent=2)
    except: pass

# ─── Load alerts from Module 8 IDS JSON ───────────────────
def load_ids_alerts():
    try:
        if os.path.exists(IDS_ALERTS):
            with open(IDS_ALERTS,"r") as f: return json.load(f)
    except: pass
    return []

# ─── Load alerts from Module 1 ARP DB ─────────────────────
def load_arp_alerts():
    alerts = []
    try:
        if not os.path.exists(ARP_DB): return alerts
        conn = sqlite3.connect(ARP_DB)
        c    = conn.cursor()
        c.execute("SELECT timestamp, ip_address, old_mac, new_mac, alert_type FROM alerts ORDER BY timestamp DESC LIMIT 100")
        rows = c.fetchall()
        conn.close()
        for i, r in enumerate(rows):
            alerts.append({
                "id":        f"arp_{i}_{r[0]}",
                "timestamp": r[0],
                "src_ip":    r[1],
                "rule":      "ARP_SPOOFING",
                "severity":  "HIGH",
                "details":   f"MAC changed from {r[2]} to {r[3]}"
            })
    except Exception as e:
        pass
    return alerts

# ─── Block IP ──────────────────────────────────────────────
def block_ip(ip, reason):
    if ip in blocked_ips:
        return
    if not ip or ip in ("N/A","0.0.0.0","127.0.0.1"):
        return

    try:
        subprocess.run(["iptables","-A","INPUT", "-s",ip,"-j","DROP"],capture_output=True)
        subprocess.run(["iptables","-A","OUTPUT","-d",ip,"-j","DROP"],capture_output=True)

        unblock_time = (datetime.datetime.now() + datetime.timedelta(seconds=AUTO_UNBLOCK)).strftime("%Y-%m-%d %H:%M:%S")
        blocked_ips[ip] = {
            "blocked_at": now(),
            "reason":     reason,
            "unblock_at": unblock_time
        }
        entry = {
            "timestamp":  now(),
            "action":     "BLOCK",
            "ip":         ip,
            "reason":     reason,
            "unblock_at": unblock_time
        }
        incident_log.append(entry)
        save_log(); save_blocked()

        log(f"🚫 BLOCKED {ip} — {reason}", "red")
        log(f"   Auto-unblock at: {unblock_time}", "yellow")

        # Desktop notification
        try:
            subprocess.run(["notify-send","NetDefend",f"BLOCKED: {ip}\n{reason}"],capture_output=True)
        except: pass

    except Exception as e:
        log(f"Block failed for {ip}: {e}", "red")

# ─── Unblock IP ───────────────────────────────────────────
def unblock_ip(ip):
    try:
        subprocess.run(["iptables","-D","INPUT", "-s",ip,"-j","DROP"],capture_output=True)
        subprocess.run(["iptables","-D","OUTPUT","-d",ip,"-j","DROP"],capture_output=True)
        reason = blocked_ips.get(ip,{}).get("reason","")
        del blocked_ips[ip]
        incident_log.append({"timestamp":now(),"action":"UNBLOCK","ip":ip,"reason":f"Auto-unblock after {AUTO_UNBLOCK}s"})
        save_log(); save_blocked()
        log(f"✅ UNBLOCKED {ip}", "green")
    except Exception as e:
        log(f"Unblock failed for {ip}: {e}", "red")

# ─── Auto-unblock checker ─────────────────────────────────
def check_unblocks():
    now_dt = datetime.datetime.now()
    to_unblock = []
    for ip, info in blocked_ips.items():
        try:
            unblock_dt = datetime.datetime.strptime(info["unblock_at"],"%Y-%m-%d %H:%M:%S")
            if now_dt >= unblock_dt:
                to_unblock.append(ip)
        except: pass
    for ip in to_unblock:
        unblock_ip(ip)

# ─── Process alerts ───────────────────────────────────────
def process_alerts(alerts):
    for alert in alerts:
        # Build unique ID
        uid = alert.get("id") or f"{alert.get('timestamp','')}_{alert.get('src_ip','')}"
        if uid in processed_ids:
            continue
        processed_ids.add(uid)

        ip       = alert.get("src_ip","N/A")
        severity = str(alert.get("severity","")).upper()
        rule     = alert.get("rule","UNKNOWN")
        details  = alert.get("details","")

        if not ip or ip == "N/A":
            continue

        # HIGH → block immediately
        if severity == "HIGH":
            log(f"⚠️  HIGH alert: {rule} from {ip} — {details}", "red")
            block_ip(ip, f"{rule} — {details}")

        # MEDIUM → count and block after threshold
        elif severity == "MEDIUM":
            medium_counts[ip] = medium_counts.get(ip,0) + 1
            count = medium_counts[ip]
            log(f"🟡 MEDIUM alert: {rule} from {ip} [{count}/{MEDIUM_THRESHOLD}]", "yellow")
            if count >= MEDIUM_THRESHOLD:
                block_ip(ip, f"{rule} × {count} times — threshold reached")

# ─── Main loop ────────────────────────────────────────────
def main():
    print("=" * 55)
    print("    MODULE 10 — AUTOMATED INCIDENT RESPONSE")
    print("=" * 55)
    print(f"  [*] Check interval  : {CHECK_INTERVAL}s")
    print(f"  [*] Auto-unblock    : {AUTO_UNBLOCK}s")
    print(f"  [*] HIGH threshold  : block after {HIGH_THRESHOLD} alert")
    print(f"  [*] MEDIUM threshold: block after {MEDIUM_THRESHOLD} alerts")
    print(f"  [*] Sources: Module 1 (ARP DB) + Module 8 (IDS JSON)")
    print(f"  [*] Press Ctrl+C to stop")
    print("=" * 55 + "\n")

    while True:
        try:
            # Load from BOTH sources
            ids_alerts = load_ids_alerts()
            arp_alerts = load_arp_alerts()
            all_alerts = ids_alerts + arp_alerts

            if all_alerts:
                process_alerts(all_alerts)

            # Check auto-unblocks
            check_unblocks()

            # Status line
            if blocked_ips:
                log(f"📊 Status: {len(all_alerts)} alerts | {len(blocked_ips)} blocked IPs", "blue")

        except Exception as e:
            log(f"Error in main loop: {e}", "red")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
