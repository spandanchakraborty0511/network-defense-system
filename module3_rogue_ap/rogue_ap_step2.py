#!/usr/bin/env python3
# Module 3 - Step 2: Rogue AP Detector

from scapy.all import *
import subprocess
import time
import datetime

IFACE = "wlan0"
CHANNELS_2G = list(range(1, 14))
CHANNELS_5G = [36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140]
ALL_CHANNELS = CHANNELS_2G + CHANNELS_5G

# ── Trusted AP database (legitimate networks you know) ─────
# Add your known legitimate networks here
TRUSTED_APS = {
    "VITC-HOS2-4": {
        "known_bssids": [],   # will auto-learn first scan
        "enc": "WPA/WPA2"
    },
    "Configure.Me-26FA10": {
        "known_bssids": ["10:f0:68:e6:fa:1b"],
        "enc": "WPA/WPA2"
    }
}

# ── State ──────────────────────────────────────────────────
networks   = {}   # bssid -> info
ssid_map   = {}   # ssid  -> list of bssids (for evil twin detection)
alerts     = []
scan_count = 0

def hop_channel(ch):
    subprocess.run(["iw", "dev", IFACE, "set", "channel", str(ch)],
                   capture_output=True)

def get_enc(pkt):
    cap = pkt[Dot11Beacon].cap
    if not cap.privacy:
        return "OPEN"
    # Check for RSN (WPA2)
    elt = pkt[Dot11Elt]
    while elt and isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            return "WPA2"
        if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x01':
            return "WPA"
        elt = elt.payload if hasattr(elt, 'payload') else None
    return "WEP"

def get_channel(pkt):
    elt = pkt[Dot11Elt]
    while elt and isinstance(elt, Dot11Elt):
        if elt.ID == 3:
            return int.from_bytes(elt.info, "little")
        elt = elt.payload if hasattr(elt, 'payload') else None
    return None

def raise_alert(alert_type, ssid, bssid, detail, severity="HIGH"):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        "timestamp": ts,
        "type":      alert_type,
        "ssid":      ssid,
        "bssid":     bssid,
        "detail":    detail,
        "severity":  severity
    }
    alerts.append(alert)

    colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
    c = colors.get(severity, "")
    print(f"\n  {c}[!] ALERT [{severity}] {alert_type}\033[0m")
    print(f"      SSID   : {ssid}")
    print(f"      BSSID  : {bssid}")
    print(f"      Detail : {detail}")
    print(f"      Time   : {ts}\n")

def handle_beacon(pkt):
    global scan_count
    if not pkt.haslayer(Dot11Beacon):
        return

    bssid  = pkt[Dot11].addr2
    ssid   = pkt[Dot11Elt].info.decode(errors="ignore").strip()
    if not ssid:
        ssid = "<hidden>"

    signal = getattr(pkt, "dBm_AntSignal", -100)
    enc    = get_enc(pkt)
    ch     = get_channel(pkt)

    # ── First time seeing this BSSID ───────────────────────
    if bssid not in networks:
        networks[bssid] = {
            "ssid": ssid, "bssid": bssid,
            "enc": enc, "channel": ch,
            "signal": signal, "first_seen": datetime.datetime.now(),
            "last_seen": datetime.datetime.now()
        }

        # Track all BSSIDs per SSID
        if ssid not in ssid_map:
            ssid_map[ssid] = []
        ssid_map[ssid].append(bssid)

        # ── DETECTION 1: Open network with trusted SSID ────
        if ssid in TRUSTED_APS:
            trusted_enc = TRUSTED_APS[ssid]["enc"]
            if enc == "OPEN" and trusted_enc != "OPEN":
                raise_alert(
                    "EVIL_TWIN_OPEN",
                    ssid, bssid,
                    f"Known network '{ssid}' broadcasting as OPEN (expected {trusted_enc})",
                    "HIGH"
                )

        # ── DETECTION 2: Completely open network ───────────
        if enc == "OPEN" and ssid not in ["<hidden>"]:
            raise_alert(
                "OPEN_NETWORK",
                ssid, bssid,
                f"Unencrypted open network detected on CH{ch}",
                "MEDIUM"
            )

        # ── DETECTION 3: Hidden SSID ───────────────────────
        if ssid == "<hidden>":
            raise_alert(
                "HIDDEN_SSID",
                ssid, bssid,
                f"Hidden SSID network detected (BSSID: {bssid}) on CH{ch}",
                "LOW"
            )

        # ── DETECTION 4: Weak encryption (WEP) ────────────
        if enc == "WEP":
            raise_alert(
                "WEAK_ENCRYPTION",
                ssid, bssid,
                f"Network using broken WEP encryption on CH{ch}",
                "HIGH"
            )

    else:
        # Update last seen
        networks[bssid]["last_seen"] = datetime.datetime.now()

        # ── DETECTION 5: Evil Twin (same SSID, many BSSIDs)
        if ssid in ssid_map and len(ssid_map[ssid]) > 1:
            if ssid not in TRUSTED_APS or len(TRUSTED_APS[ssid]["known_bssids"]) == 0:
                # Only alert once per bssid group
                already = any(
                    a["type"] == "EVIL_TWIN" and a["ssid"] == ssid
                    for a in alerts
                )
                if not already:
                    raise_alert(
                        "EVIL_TWIN",
                        ssid, bssid,
                        f"Multiple BSSIDs for SSID '{ssid}': {ssid_map[ssid]}",
                        "MEDIUM"
                    )

def print_summary():
    print("\n" + "=" * 60)
    print("   SCAN SUMMARY")
    print("=" * 60)
    print(f"  Networks found : {len(networks)}")
    print(f"  Alerts raised  : {len(alerts)}")
    print()

    if alerts:
        print("  ALERTS:")
        for a in alerts:
            print(f"  [{a['severity']:6s}] {a['type']:20s} | {a['ssid']} | {a['bssid']}")
    else:
        print("  No suspicious networks detected.")

    print()
    print("  ALL NETWORKS:")
    for n in sorted(networks.values(), key=lambda x: x["ssid"]):
        print(f"  {n['ssid']:30s} | {n['bssid']} | CH:{str(n['channel']):4s} | {n['enc']}")
    print("=" * 60)

def main():
    print("=" * 60)
    print("   MODULE 3 - STEP 2: Rogue AP Detector")
    print("=" * 60)
    print(f"[*] Interface : {IFACE}")
    print(f"[*] Scanning 2.4GHz + 5GHz channels")
    print("[*] Press Ctrl+C to stop and see summary\n")

    ch_idx = 0
    try:
        while True:
            ch = ALL_CHANNELS[ch_idx % len(ALL_CHANNELS)]
            hop_channel(ch)
            sniff(iface=IFACE, prn=handle_beacon,
                  timeout=1.5, store=0)
            ch_idx += 1

            if ch_idx % len(ALL_CHANNELS) == 0:
                scan_count += 1
                print(f"[*] Full scan #{scan_count} complete | "
                      f"Networks: {len(networks)} | Alerts: {len(alerts)}")

    except KeyboardInterrupt:
        print_summary()

if __name__ == "__main__":
    main()
