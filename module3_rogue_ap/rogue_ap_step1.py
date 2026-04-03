#!/usr/bin/env python3
# Module 3 - Step 1: Basic AP Scanner

from scapy.all import *
import subprocess
import time

IFACE = "wlan0"
CHANNELS = list(range(1, 14))

networks = {}

def hop_channel(ch):
    subprocess.run(["iw", "dev", IFACE, "set", "channel", str(ch)],
                   capture_output=True)

def handle_beacon(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return

    bssid = pkt[Dot11].addr2
    ssid  = pkt[Dot11Elt].info.decode(errors="ignore").strip()
    if not ssid:
        ssid = "<hidden>"

    # Get signal strength
    signal = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -100

    # Get channel
    ch = None
    elt = pkt[Dot11Elt]
    while elt:
        if elt.ID == 3:
            ch = int.from_bytes(elt.info, "little")
            break
        elt = elt.payload if elt.payload else None

    # Get encryption
    cap = pkt[Dot11Beacon].cap
    enc = "OPEN"
    if cap.privacy:
        enc = "WPA/WPA2"

    if bssid not in networks:
        networks[bssid] = {
            "ssid":    ssid,
            "bssid":   bssid,
            "channel": ch,
            "signal":  signal,
            "enc":     enc,
            "seen":    1
        }
        print(f"  [+] {ssid:30s} | {bssid} | CH:{str(ch):3s} | {enc}")
    else:
        networks[bssid]["seen"] += 1

def main():
    print("=" * 60)
    print("   MODULE 3 - STEP 1: WiFi AP Scanner")
    print("=" * 60)
    print(f"[*] Interface : {IFACE}")
    print(f"[*] Channels  : 1-13")
    print("[*] Press Ctrl+C to stop\n")

    ch_idx = 0
    try:
        while True:
            ch = CHANNELS[ch_idx % len(CHANNELS)]
            hop_channel(ch)
            sniff(iface=IFACE, prn=handle_beacon,
                  timeout=1.5, store=0)
            ch_idx += 1

            if ch_idx % 13 == 0:
                print(f"\n[*] Scan complete. Total networks: {len(networks)}\n")

    except KeyboardInterrupt:
        print(f"\n[*] Done. Found {len(networks)} networks.")
        for n in networks.values():
            print(f"  {n['ssid']:30s} | {n['bssid']} | CH:{str(n['channel']):3s} | {n['enc']}")

if __name__ == "__main__":
    main()

