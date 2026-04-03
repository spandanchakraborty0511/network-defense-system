import ssl
import socket
import hashlib
import json
import datetime

def load_pins(filename="trusted_pins.json"):
    """Load saved trusted pins"""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("[!] No trusted pins file found")
        print("[!] Run cert_pinning_step1.py first")
        return {}

def get_live_pin(domain, port=443):
    """Get current certificate pin from live connection"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                sha256_pin = hashlib.sha256(der_cert).hexdigest()
                return sha256_pin
    except Exception as e:
        print(f"  [!] Connection error: {e}")
        return None

def validate_pin(domain, trusted_pins):
    """Validate current certificate against trusted pin"""
    print(f"\n[*] Validating: {domain}")
    print("-" * 50)

    # Check if we have a pin for this domain
    if domain not in trusted_pins:
        print(f"  [!] No trusted pin found for {domain}")
        print(f"  [!] Run cert_pinning_step1.py to create pins first")
        return "NO_PIN"

    trusted_pin = trusted_pins[domain]["sha256_pin"]
    pinned_at = trusted_pins[domain]["pinned_at"]
    issuer = trusted_pins[domain]["issuer"]

    print(f"  Trusted Pin  : {trusted_pin[:32]}...")
    print(f"  Pinned At    : {pinned_at}")
    print(f"  Issuer       : {issuer}")

    # Get live pin
    print(f"  [*] Fetching live certificate...")
    live_pin = get_live_pin(domain)

    if live_pin is None:
        print(f"  [❌] Could not fetch live certificate")
        return "ERROR"

    print(f"  Live Pin     : {live_pin[:32]}...")

    # Compare pins
    if live_pin == trusted_pin:
        print(f"  [✅] PIN VALID - Certificate matches trusted pin")
        return "VALID"
    else:
        print(f"  [!!!] PIN MISMATCH DETECTED")
        print(f"  [!!!] Expected : {trusted_pin}")
        print(f"  [!!!] Got      : {live_pin}")
        print(f"  [!!!] Possible MITM attack or certificate rotation!")
        return "MISMATCH"

# ─── Main ─────────────────────────────────────────────────
print("=" * 50)
print("      CERTIFICATE PIN VALIDATOR")
print("=" * 50)

# Load trusted pins
trusted_pins = load_pins()

if not trusted_pins:
    exit(1)

print(f"[*] Loaded {len(trusted_pins)} trusted pins")

# Validate each domain
DOMAINS = list(trusted_pins.keys())
results = {}

for domain in DOMAINS:
    result = validate_pin(domain, trusted_pins)
    results[domain] = result

# Summary
print("\n" + "=" * 50)
print("         VALIDATION SUMMARY")
print("=" * 50)
print(f"  {'Domain':<25} {'Result'}")
print("-" * 50)

for domain, result in results.items():
    if result == "VALID":
        status = "✅ VALID"
    elif result == "MISMATCH":
        status = "❌ MISMATCH - POSSIBLE MITM"
    elif result == "NO_PIN":
        status = "⚠️  NO PIN"
    else:
        status = "❌ ERROR"
    print(f"  {domain:<25} {status}")

print("=" * 50)
