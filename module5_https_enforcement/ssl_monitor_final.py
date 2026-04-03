import ssl
import socket
import requests
import datetime
import hashlib
import json
import os
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Configuration ────────────────────────────────────────
CHECK_INTERVAL = 10
BASELINE_FILE = "cert_baseline.json"
DOMAINS_TO_MONITOR = [
    "github.com",
    "google.com",
    "facebook.com",
    "wikipedia.org"
]

stats = {
    "checks": 0,
    "cert_changes": 0,
    "expiry_warnings": 0,
    "http_vulnerabilities": 0
}

# ─── Load/Save Baseline ───────────────────────────────────
def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

# ─── Get Certificate ──────────────────────────────────────
def get_certificate(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)
                fingerprint = hashlib.sha256(der_cert).hexdigest()
                expiry_str = cert["notAfter"]
                expiry_date = datetime.datetime.strptime(
                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (expiry_date - datetime.datetime.now()).days
                issuer = dict(x[0] for x in cert["issuer"])
                return {
                    "domain": domain,
                    "fingerprint": fingerprint,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "expiry_date": expiry_str,
                    "days_until_expiry": days_left,
                    "valid": True
                }
    except Exception as e:
        return {"domain": domain, "valid": False, "error": str(e)}

# ─── Check HTTPS ──────────────────────────────────────────
def check_https(domain):
    try:
        response = requests.get(
            f"http://{domain}",
            allow_redirects=True,
            timeout=5,
            verify=False
        )
        enforced = response.url.startswith("https://")
        hsts = "Strict-Transport-Security" in response.headers
        return enforced, hsts
    except:
        return False, False

# ─── Monitor Domain ───────────────────────────────────────
def monitor_domain(domain, baseline):
    print(f"\n  Checking {domain}...")

    cert = get_certificate(domain)

    if not cert["valid"]:
        print(f"    [ERROR] {cert['error']}")
        return baseline

    if domain in baseline:
        if baseline[domain]["fingerprint"] != cert["fingerprint"]:
            stats["cert_changes"] += 1
            print(f"    [!!!] CERTIFICATE CHANGED - Possible MITM!")
            print(f"      Old: {baseline[domain]['fingerprint'][:20]}...")
            print(f"      New: {cert['fingerprint'][:20]}...")
        else:
            print(f"    [OK] Certificate unchanged")
    else:
        print(f"    [+] Baseline saved")

    if cert["days_until_expiry"] < 7:
        stats["expiry_warnings"] += 1
        print(f"    [CRITICAL] Expires in {cert['days_until_expiry']} days")
    elif cert["days_until_expiry"] < 30:
        stats["expiry_warnings"] += 1
        print(f"    [WARNING] Expires in {cert['days_until_expiry']} days")
    else:
        print(f"    [OK] Expires in {cert['days_until_expiry']} days")

    enforced, hsts = check_https(domain)
    if not enforced:
        stats["http_vulnerabilities"] += 1
        print(f"    [WARNING] No HTTPS redirect - SSL strip risk")
    else:
        print(f"    [OK] HTTPS enforced")

    if hsts:
        print(f"    [OK] HSTS enabled")
    else:
        print(f"    [WARNING] No HSTS header")

    baseline[domain] = cert
    return baseline

# ─── Generate Report ──────────────────────────────────────
def generate_report():
    print("\n" + "=" * 50)
    print("        SSL MONITORING REPORT")
    print("=" * 50)
    print(f"  Total Checks         : {stats['checks']}")
    print(f"  Certificate Changes  : {stats['cert_changes']}")
    print(f"  Expiry Warnings      : {stats['expiry_warnings']}")
    print(f"  HTTP Vulnerabilities : {stats['http_vulnerabilities']}")

    if stats["cert_changes"] > 0:
        print(f"\n  [ALERT] Certificate changes detected!")
    else:
        print(f"\n  [OK] No certificate changes detected")

    filename = f"ssl_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"Total Checks: {stats['checks']}\n")
        f.write(f"Certificate Changes: {stats['cert_changes']}\n")
        f.write(f"Expiry Warnings: {stats['expiry_warnings']}\n")
        f.write(f"HTTP Vulnerabilities: {stats['http_vulnerabilities']}\n")
    print(f"\n[*] Report saved: {filename}")
    print("=" * 50)

# ─── Main ─────────────────────────────────────────────────
print("=" * 50)
print("      SSL ENFORCEMENT MONITOR")
print("=" * 50)
print(f"[*] Monitoring {len(DOMAINS_TO_MONITOR)} domains")
print(f"[*] Check interval: {CHECK_INTERVAL} seconds")
print(f"[*] Press Ctrl+C to stop")
print("=" * 50)

baseline = load_baseline()

try:
    while True:
        stats["checks"] += 1
        print(f"\n[*] Check #{stats['checks']} - "
              f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)

        for domain in DOMAINS_TO_MONITOR:
            baseline = monitor_domain(domain, baseline)

        save_baseline(baseline)
        print(f"\n[*] Next check in {CHECK_INTERVAL} seconds...")
        time.sleep(CHECK_INTERVAL)

except KeyboardInterrupt:
    generate_report()
