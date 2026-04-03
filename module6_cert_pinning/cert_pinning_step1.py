import ssl
import socket
import hashlib
import json
import datetime
import os

def get_certificate_pin(domain, port=443):
    """Extract certificate fingerprint for pinning"""
    try:
        print(f"[*] Connecting to {domain}:{port}")
        
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get raw certificate bytes
                der_cert = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                
                # Generate multiple hash formats
                sha256_pin = hashlib.sha256(der_cert).hexdigest()
                sha1_pin = hashlib.sha1(der_cert).hexdigest()
                
                # Extract certificate details
                subject = dict(x[0] for x in cert["subject"])
                issuer = dict(x[0] for x in cert["issuer"])
                
                expiry_str = cert["notAfter"]
                expiry_date = datetime.datetime.strptime(
                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (expiry_date - datetime.datetime.now()).days
                
                pin_data = {
                    "domain": domain,
                    "subject": subject.get("commonName", domain),
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "sha256_pin": sha256_pin,
                    "sha1_pin": sha1_pin,
                    "expiry_date": expiry_str,
                    "days_until_expiry": days_left,
                    "pinned_at": datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                }
                
                return pin_data
                
    except Exception as e:
        print(f"[!] Error connecting to {domain}: {e}")
        return None

def display_pin(pin_data):
    """Display pin information"""
    print(f"\n{'='*55}")
    print(f"  Certificate Pin for: {pin_data['domain']}")
    print(f"{'='*55}")
    print(f"  Subject    : {pin_data['subject']}")
    print(f"  Issuer     : {pin_data['issuer']}")
    print(f"  Expires    : {pin_data['expiry_date']}")
    print(f"  Days Left  : {pin_data['days_until_expiry']}")
    print(f"  SHA256 Pin : {pin_data['sha256_pin']}")
    print(f"  SHA1 Pin   : {pin_data['sha1_pin']}")
    print(f"  Pinned At  : {pin_data['pinned_at']}")
    print(f"{'='*55}")

def save_pins(pins, filename="trusted_pins.json"):
    """Save pins to file"""
    with open(filename, "w") as f:
        json.dump(pins, f, indent=4)
    print(f"\n[+] Pins saved to: {filename}")

# ─── Main ─────────────────────────────────────────────────
DOMAINS = [
    "github.com",
    "google.com",
    "facebook.com"
]

print("=" * 55)
print("      CERTIFICATE PIN EXTRACTOR")
print("=" * 55)

pins = {}
for domain in DOMAINS:
    pin_data = get_certificate_pin(domain)
    if pin_data:
        display_pin(pin_data)
        pins[domain] = pin_data

save_pins(pins)
print("[*] These pins are now your trusted baseline")
print("[*] Any change = possible MITM attack")
