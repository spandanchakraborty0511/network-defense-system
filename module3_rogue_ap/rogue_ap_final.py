#!/usr/bin/env python3
# Module 3 - FINAL: Rogue Access Point Detection System

from scapy.all import *
import subprocess, time, datetime, json, os, threading, signal, sys

IFACE       = "wlan0"
REPORT_DIR  = os.path.dirname(os.path.abspath(__file__))
DB_FILE     = os.path.join(REPORT_DIR, "rogue_ap.json")

CHANNELS_2G = list(range(1, 14))
CHANNELS_5G = [36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140]
ALL_CHANNELS = CHANNELS_2G + CHANNELS_5G

WHITELIST_SSIDS = [
    "VITC-HOS2-4",
    "VITC-HOS2-5",
    "eduroam",
]

TRUSTED_APS = {
    "Configure.Me-26FA10": {
        "bssids": ["10:f0:68:e6:fa:1b"],
        "enc":    "WPA/WPA2"
    }
}

# ── State ──────────────────────────────────────────────────
networks   = {}
ssid_map   = {}
alerts     = []
scan_count = 0
start_time = datetime.datetime.now()
running    = True

# ── Helpers ────────────────────────────────────────────────
def reset_monitor_mode():
    """Put wlan0 back into monitor mode after a crash"""
    print("  [*] Resetting wlan0 to monitor mode...")
    subprocess.run(["ip", "link", "set", IFACE, "down"],  capture_output=True)
    subprocess.run(["iw", "dev", IFACE, "set", "type", "monitor"], capture_output=True)
    subprocess.run(["ip", "link", "set", IFACE, "up"],    capture_output=True)
    time.sleep(2)
    print("  [*] wlan0 monitor mode restored.")

def hop(ch):
    subprocess.run(["iw","dev",IFACE,"set","channel",str(ch)],
                   capture_output=True)

def get_enc(pkt):
    cap = pkt[Dot11Beacon].cap
    if not cap.privacy:
        return "OPEN"
    elt = pkt[Dot11Elt]
    while elt and isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            return "WPA2"
        if elt.ID == 221 and hasattr(elt,'info') and len(elt.info)>=4 and elt.info[:4]==b'\x00\x50\xf2\x01':
            return "WPA"
        elt = elt.payload if hasattr(elt,'payload') else None
    return "WEP"

def get_channel(pkt):
    elt = pkt[Dot11Elt]
    while elt and isinstance(elt, Dot11Elt):
        if elt.ID == 3:
            return int.from_bytes(elt.info, "little")
        elt = elt.payload if hasattr(elt,'payload') else None
    return "?"

def get_vendor(mac):
    vendors = {
        "10:f0:68": "TP-Link",   "b0:1f:8c": "Cisco",
        "44:12:44": "Huawei",    "24:f2:7f": "Huawei",
        "70:3a:0e": "Huawei",    "d0:4f:58": "Xiaomi",
        "54:f0:b1": "Xiaomi",    "c8:84:8c": "Aruba",
        "be:a9:85": "Samsung",   "26:20:3d": "Apple",
        "32:e3:7a": "Microsoft",
    }
    for k,v in vendors.items():
        if mac.upper().startswith(k.upper()):
            return v
    return "Unknown"

def alert(atype, ssid, bssid, detail, severity="HIGH"):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for a in alerts:
        if a["type"]==atype and a["bssid"]==bssid:
            return
    entry = {
        "timestamp": ts, "type": atype,
        "ssid": ssid,    "bssid": bssid,
        "detail": detail,"severity": severity,
        "vendor": get_vendor(bssid)
    }
    alerts.append(entry)
    RED="\033[91m"; YLW="\033[93m"; BLU="\033[94m"; RST="\033[0m"; BLD="\033[1m"
    c = RED if severity=="HIGH" else YLW if severity=="MEDIUM" else BLU
    print(f"\n  {c}{BLD}[!] ALERT [{severity}] {atype}{RST}")
    print(f"      SSID   : {ssid}")
    print(f"      BSSID  : {bssid} ({get_vendor(bssid)})")
    print(f"      Detail : {detail}")
    print(f"      Time   : {ts}")
    save_db()

def save_db():
    data = {
        "scan_start":  start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "last_update": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "networks":    list(networks.values()),
        "alerts":      alerts,
        "stats": {
            "total_networks": len(networks),
            "total_alerts":   len(alerts),
            "high":   sum(1 for a in alerts if a["severity"]=="HIGH"),
            "medium": sum(1 for a in alerts if a["severity"]=="MEDIUM"),
            "low":    sum(1 for a in alerts if a["severity"]=="LOW"),
        }
    }
    for n in data["networks"]:
        for k in ["first_seen","last_seen"]:
            if k in n and not isinstance(n[k], str):
                n[k] = str(n[k])
    with open(DB_FILE,"w") as f:
        json.dump(data, f, indent=2)

# ── Packet Handler ─────────────────────────────────────────
def handle_beacon(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return
    bssid  = pkt[Dot11].addr2
    ssid   = pkt[Dot11Elt].info.decode(errors="ignore").strip() or "<hidden>"
    signal = getattr(pkt, "dBm_AntSignal", -100)
    enc    = get_enc(pkt)
    ch     = get_channel(pkt)
    vendor = get_vendor(bssid)
    now    = datetime.datetime.now()

    if bssid not in networks:
        networks[bssid] = {
            "ssid": ssid, "bssid": bssid, "enc": enc,
            "channel": ch, "signal": signal, "vendor": vendor,
            "first_seen": now, "last_seen": now, "beacon_count": 1
        }
        if ssid not in ssid_map:
            ssid_map[ssid] = []
        if bssid not in ssid_map[ssid]:
            ssid_map[ssid].append(bssid)

        if enc == "OPEN" and ssid != "<hidden>":
            alert("OPEN_NETWORK", ssid, bssid,
                  f"Unencrypted open WiFi on CH{ch} — data sent in plaintext", "MEDIUM")

        if ssid in TRUSTED_APS:
            expected = TRUSTED_APS[ssid]["enc"]
            if enc == "OPEN":
                alert("EVIL_TWIN_OPEN", ssid, bssid,
                      f"'{ssid}' broadcasting OPEN — expected {expected}. Possible honeypot!", "HIGH")

        if ssid == "<hidden>":
            alert("HIDDEN_SSID", ssid, bssid,
                  f"Hidden network on CH{ch} ({vendor}) — may be rogue AP", "LOW")

        if enc == "WEP":
            alert("WEAK_ENCRYPTION", ssid, bssid,
                  f"WEP encryption is broken and crackable in minutes", "HIGH")

        if ssid not in WHITELIST_SSIDS:
            if ssid in ssid_map and len(ssid_map[ssid]) > 1:
                others = [b for b in ssid_map[ssid] if b != bssid]
                alert("EVIL_TWIN", ssid, bssid,
                      f"Duplicate SSID '{ssid}' from {bssid} — also seen from {others}", "HIGH")
    else:
        networks[bssid]["last_seen"]     = now
        networks[bssid]["beacon_count"] += 1
        networks[bssid]["signal"]        = signal
        old_ch = networks[bssid]["channel"]
        if old_ch != ch and old_ch != "?" and ch != "?":
            diff = abs(int(str(old_ch)) - int(str(ch)))
            if diff > 5:
                alert("CHANNEL_SPOOF", ssid, bssid,
                      f"AP jumped from CH{old_ch} to CH{ch} — possible channel spoofing", "MEDIUM")
                networks[bssid]["channel"] = ch

# ── Channel Hopper Thread ──────────────────────────────────
def channel_hopper():
    global scan_count
    ch_idx = 0
    while running:
        ch = ALL_CHANNELS[ch_idx % len(ALL_CHANNELS)]
        hop(ch)
        time.sleep(0.4)
        ch_idx += 1
        if ch_idx % len(ALL_CHANNELS) == 0:
            scan_count += 1

# ── Signal Handler ─────────────────────────────────────────
def shutdown(sig, frame):
    global running
    running = False
    print_report()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

# ── Final Report ───────────────────────────────────────────
def print_report():
    duration = (datetime.datetime.now() - start_time).seconds
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORT_DIR, f"rogue_ap_report_{ts}.txt")
    lines = [
        "=" * 65,
        "   MODULE 3 — ROGUE AP DETECTION REPORT",
        "=" * 65,
        f"  Scan Start   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Duration     : {duration}s ({scan_count} full channel sweeps)",
        f"  Interface    : {IFACE}",
        f"  Networks     : {len(networks)}",
        f"  Total Alerts : {len(alerts)}",
        f"  HIGH         : {sum(1 for a in alerts if a['severity']=='HIGH')}",
        f"  MEDIUM       : {sum(1 for a in alerts if a['severity']=='MEDIUM')}",
        f"  LOW          : {sum(1 for a in alerts if a['severity']=='LOW')}",
        "=" * 65, "",
    ]
    if alerts:
        lines.append("  SECURITY ALERTS:")
        lines.append("  " + "-" * 60)
        for a in alerts:
            lines += [
                f"  [{a['severity']:6s}] {a['type']}",
                f"          SSID   : {a['ssid']}",
                f"          BSSID  : {a['bssid']} ({a['vendor']})",
                f"          Detail : {a['detail']}",
                f"          Time   : {a['timestamp']}",
                ""
            ]
    else:
        lines.append("  No threats detected.")
    lines += ["", "  ALL DETECTED NETWORKS:", "  " + "-" * 60]
    for n in sorted(networks.values(), key=lambda x: x["ssid"]):
        fs = n['first_seen'] if isinstance(n['first_seen'], str) else str(n['first_seen'])
        lines.append(
            f"  {n['ssid']:30s} | {n['bssid']} | "
            f"CH:{str(n['channel']):4s} | {n['enc']:5s} | "
            f"{n['vendor']:12s} | Beacons:{n['beacon_count']}"
        )
    lines += ["", "=" * 65]
    report = "\n".join(lines)
    print("\n" + report)
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\n  [*] Report saved → {report_file}")
    print(f"  [*] Database    → {DB_FILE}")

# ── Sniff with auto-restart on crash ──────────────────────
def start_sniff():
    while running:
        try:
            sniff(iface=IFACE, prn=handle_beacon, store=0,
                  stop_filter=lambda p: not running,
                  timeout=30)           # restart every 30s even if no crash
        except Exception as e:
            if not running:
                break
            print(f"\n  [!] Socket error: {e}")
            print(f"  [*] Restarting in 3 seconds...")
            time.sleep(3)
            reset_monitor_mode()
            print(f"  [*] Resuming scan... ({len(networks)} networks so far)")

# ── Main ───────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("   MODULE 3 — ROGUE ACCESS POINT DETECTION SYSTEM")
    print("=" * 65)
    print(f"  [*] Interface   : {IFACE}")
    print(f"  [*] Channels    : 2.4GHz (1-13) + 5GHz (36-140)")
    print(f"  [*] Rules       : 6 detection rules active")
    print(f"  [*] Whitelist   : {WHITELIST_SSIDS}")
    print(f"  [*] Auto-restart: ON (never terminates on socket crash)")
    print(f"  [*] Press Ctrl+C to stop and generate report")
    print("=" * 65 + "\n")

    # Start channel hopper in background
    t = threading.Thread(target=channel_hopper, daemon=True)
    t.start()

    # Sniff with auto-restart
    start_sniff()

if __name__ == "__main__":
    main()
