import ssl
import socket
import datetime
import hashlib
import json
import os

def get_certificate_info(domain, port=443):
    """Extract SSL certificate details from a domain"""
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)
                
                # Generate certificate fingerprint
                fingerprint = hashlib.sha256(der_cert).hexdigest()
                
                # Extract expiry date
                expiry_str = cert["notAfter"]
                expiry_date = datetime.datetime.strptime(
                    expiry_str, "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (expiry_date - datetime.datetime.now()).days
                
                # Extract issuer
                issuer = dict(x[0] for x in cert["issuer"])
                subject = dict(x[0] for x in cert["subject"])
                
                return {
                    "domain": domain,
                    "fingerprint": fingerprint,
                    "issuer": issuer.get("organizationName", "Unknown"),
                    "subject": subject.get("commonName", domain),
                    "expiry_date": expiry_str,
                    "days_until_expiry": days_left,
                    "valid": True,
                    "checked_at": datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                }

    except ssl.SSLCertVerificationError as e:
        return {
            "domain": domain,
            "valid": False,
            "error": f"Certificate verification failed: {e}"
        }
    except Exception as e:
        return {
            "domain": domain,
            "valid": False,
            "error": str(e)
        }

def display_certificate(cert_info):
    """Display certificate details cleanly"""
    print(f"\n  Domain     : {cert_info['domain']}")

    if not cert_info["valid"]:
        print(f"  [❌] ERROR : {cert_info['error']}")
        return

    print(f"  Issuer     : {cert_info['issuer']}")
    print(f"  Subject    : {cert_info['subject']}")
    print(f"  Expires    : {cert_info['expiry_date']}")
    print(f"  Days Left  : {cert_info['days_until_expiry']} days")
    print(f"  Fingerprint: {cert_info['fingerprint'][:32]}...")

    if cert_info["days_until_expiry"] < 30:
        print(f"  [⚠️ ] WARNING: Certificate expires soon!")
    elif cert_info["days_until_expiry"] < 7:
        print(f"  [❌] CRITICAL: Certificate expires in less than 7 days!")
    else:
        print(f"  [✅] Certificate is valid")

def save_certificate_baseline(cert_info, filename="cert_baseline.json"):
    """Save certificate fingerprints as baseline"""
    baseline = {}

    if os.path.exists(filename):
        with open(filename, "r") as f:
            baseline = json.load(f)

    if cert_info["valid"]:
        domain = cert_info["domain"]

        # Check for certificate change
        if domain in baseline:
            if baseline[domain]["fingerprint"] != cert_info["fingerprint"]:
                print(f"\n  [!!!] CERTIFICATE CHANGE DETECTED for {domain}")
                print(f"    Old fingerprint: {baseline[domain]['fingerprint'][:32]}...")
                print(f"    New fingerprint: {cert_info['fingerprint'][:32]}...")
                print(f"    Possible MITM attack!")
            else:
                print(f"  [✅] Certificate unchanged for {domain}")
        else:
            print(f"  [+] New baseline saved for {domain}")

        baseline[domain] = cert_info

    with open(filename, "w") as f:
        json.dump(baseline, f, indent=4)

# ─── Main ─────────────────────────────────────────────────
DOMAINS = [
    "github.com",
    "google.com",
    "facebook.com"
]

print("=" * 50)
print("      SSL CERTIFICATE MONITOR")
print("=" * 50)

for domain in DOMAINS:
    print(f"\n[*] Checking certificate: {domain}")
    print("-" * 50)
    cert_info = get_certificate_info(domain)
    display_certificate(cert_info)
    save_certificate_baseline(cert_info)

print("\n[*] Certificate baseline saved to cert_baseline.json")
print("[*] Run again to detect any certificate changes")
print("=" * 50)
