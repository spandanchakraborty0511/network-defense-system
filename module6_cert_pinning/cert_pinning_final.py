import ssl
import socket
import hashlib
import json
import datetime
import time
import os

# ─── Configuration ────────────────────────────────────────
CHECK_INTERVAL = 30
PINS_FILE = "trusted_pins.json"
LOG_FILE = "pin_validation_log.json"

DOMAINS = [
    "github.com",
    "google.com",
    "facebook.com",
    "wikipedia.org"
]

# ─── Stats ────────────────────────────────────────────────
stats = {
    "checks": 0,
    "valid": 0,
    "mismatches": 0,
    "errors": 0,
    "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

# ─── Load/Save Pins ───────────────────────────────────────
def load_pins():
    if os.path.exists(PINS_FILE):
        with open(PINS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_pins(pins):
    with open(PINS_FILE, "w") as f:
        json.dump(pins, f, indent=4)

# ─── Load/Save Log ────────────────────────────────────────
def load_log():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    return []

def save_log(log):
    with open(LOG_FILE, "w") as f:
        json.dump(log, f, indent=4)

def add_log_entry(domain, result, details=""):
    log = load_log()
    log.append({
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain,
        "result": result,
        "details": details
    })
    save_log(log)

# ─── Get Live Pin ─────────────────────────────────────────
def get_live_pin(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                sha256_pin = hashlib.sha256(der_cert).hexdigest()
                expiry_str = cert["notAfter"]
                expiry_date = datetime.datetime.strptime(
                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (expiry_date - datetime.datetime.now()).days
                issuer = dict(x[0] for x in cert["issuer"])
                return {
                    "pin": sha256_pin,
                    "days_left": days_left,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "expiry": expiry_str
                }
    except Exception as e:
        return None

# ─── Validate Domain ──────────────────────────────────────
def validate_domain(domain, pins):
    live = get_live_pin(domain)

    if live is None:
        stats["errors"] += 1
        print(f"  [ERROR] {domain} - Could not connect")
        add_log_entry(domain, "ERROR", "Connection failed")
        return pins

    # First time seeing this domain
    if domain not in pins:
        pins[domain] = {
            "sha256_pin": live["pin"],
            "issuer": live["issuer"],
            "expiry": live["expiry"],
            "pinned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "previous_pins": []
        }
        stats["valid"] += 1
        print(f"  [NEW] {domain} - Pin saved")
        add_log_entry(domain, "NEW_PIN", f"Pin: {live['pin'][:20]}...")
        save_pins(pins)
        return pins

    trusted_pin = pins[domain]["sha256_pin"]

    # Pin matches
    if live["pin"] == trusted_pin:
        stats["valid"] += 1
        expiry_warning = ""
        if live["days_left"] < 30:
            expiry_warning = f" [WARNING: expires in {live['days_left']} days]"
        print(f"  [OK] {domain} - Pin valid{expiry_warning}")
        add_log_entry(domain, "VALID")

    # Pin mismatch
    else:
        stats["mismatches"] += 1
        print(f"\n  [!!!] PIN MISMATCH: {domain}")
        print(f"    Expected : {trusted_pin[:32]}...")
        print(f"    Got      : {live['pin'][:32]}...")
        print(f"    Issuer   : {live['issuer']}")
        print(f"    POSSIBLE MITM ATTACK DETECTED")
        print(f"    If certificate was rotated legitimately,")
        print(f"    update pins by running cert_pinning_step1.py")

        add_log_entry(
            domain, "MISMATCH",
            f"Expected={trusted_pin[:20]} Got={live['pin'][:20]}"
        )

    return pins

# ─── Generate Report ──────────────────────────────────────
def generate_report(pins):
    print("\n" + "=" * 55)
    print("      CERTIFICATE PINNING FINAL REPORT")
    print("=" * 55)
    print(f"  Started    : {stats['start_time']}")
    print(f"  Stopped    : "
          f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Checks     : {stats['checks']}")
    print(f"  Valid      : {stats['valid']}")
    print(f"  Mismatches : {stats['mismatches']}")
    print(f"  Errors     : {stats['errors']}")

    print(f"\n  Pinned Domains:")
    for domain, data in pins.items():
        print(f"    {domain}")
        print(f"      Pin    : {data['sha256_pin'][:32]}...")
        print(f"      Issuer : {data['issuer']}")
        print(f"      Pinned : {data['pinned_at']}")

    if stats["mismatches"] > 0:
        print(f"\n  [ALERT] {stats['mismatches']} pin mismatches detected!")
        print(f"  Possible MITM attacks occurred!")
    else:
        print(f"\n  [OK] No pin mismatches detected")

    filename = f"pin_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"Certificate Pinning Report\n")
        f.write(f"Checks: {stats['checks']}\n")
        f.write(f"Valid: {stats['valid']}\n")
        f.write(f"Mismatches: {stats['mismatches']}\n")

    print(f"\n[*] Report saved: {filename}")
    print("=" * 55)

# ─── Main ─────────────────────────────────────────────────
print("=" * 55)
print("      CERTIFICATE PINNING MONITOR")
print("=" * 55)
print(f"[*] Monitoring {len(DOMAINS)} domains")
print(f"[*] Check interval: {CHECK_INTERVAL} seconds")
print(f"[*] Press Ctrl+C to stop and generate report")
print("=" * 55)

pins = load_pins()
print(f"[*] Loaded {len(pins)} existing pins")

try:
    while True:
        stats["checks"] += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[*] Check #{stats['checks']} - {timestamp}")
        print("-" * 55)

        for domain in DOMAINS:
            pins = validate_domain(domain, pins)

        print(f"\n[*] Next check in {CHECK_INTERVAL} seconds...")
        time.sleep(CHECK_INTERVAL)

except KeyboardInterrupt:
    generate_report(pins)
