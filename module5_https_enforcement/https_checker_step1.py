import requests
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_https_enforcement(domain):
    """Check if domain properly enforces HTTPS"""
    print(f"\n[*] Checking: {domain}")
    print("-" * 50)

    results = {
        "domain": domain,
        "http_redirects_to_https": False,
        "hsts_enabled": False,
        "hsts_max_age": None,
        "certificate_valid": False,
        "final_url": None
    }

    # Test 1 - Does HTTP redirect to HTTPS?
    try:
        http_response = requests.get(
            f"http://{domain}",
            allow_redirects=True,
            timeout=5,
            verify=False
        )
        final_url = http_response.url

        if final_url.startswith("https://"):
            results["http_redirects_to_https"] = True
            print(f"  [✅] HTTP → HTTPS redirect: YES")
        else:
            print(f"  [❌] HTTP → HTTPS redirect: NO")
            print(f"       Final URL: {final_url}")

        results["final_url"] = final_url

    except requests.exceptions.ConnectionError:
        print(f"  [!] Could not connect to http://{domain}")
    except Exception as e:
        print(f"  [!] HTTP check error: {e}")

    # Test 2 - Does HTTPS work?
    try:
        https_response = requests.get(
            f"https://{domain}",
            timeout=5,
            verify=True
        )
        results["certificate_valid"] = True
        print(f"  [✅] HTTPS connection: VALID")
        print(f"       Status code: {https_response.status_code}")

        # Test 3 - HSTS header present?
        hsts = https_response.headers.get("Strict-Transport-Security")
        if hsts:
            results["hsts_enabled"] = True
            print(f"  [✅] HSTS header: PRESENT")
            print(f"       Value: {hsts}")

            # Extract max-age
            for part in hsts.split(";"):
                if "max-age" in part:
                    max_age = part.split("=")[1].strip()
                    results["hsts_max_age"] = max_age
                    print(f"       Max-age: {max_age} seconds")
        else:
            print(f"  [❌] HSTS header: MISSING")
            print(f"       Vulnerable to SSL stripping!")

    except requests.exceptions.SSLError:
        print(f"  [❌] HTTPS connection: SSL ERROR")
    except Exception as e:
        print(f"  [!] HTTPS check error: {e}")

    # Summary
    print(f"\n  Security Score:")
    score = 0
    if results["http_redirects_to_https"]: score += 1
    if results["certificate_valid"]: score += 1
    if results["hsts_enabled"]: score += 1

    if score == 3:
        print(f"  [✅✅✅] FULLY SECURE (3/3)")
    elif score == 2:
        print(f"  [✅✅❌] MOSTLY SECURE (2/3)")
    elif score == 1:
        print(f"  [✅❌❌] PARTIALLY SECURE (1/3)")
    else:
        print(f"  [❌❌❌] NOT SECURE (0/3)")

    return results

# ─── Test Multiple Sites ───────────────────────────────────
DOMAINS_TO_CHECK = [
    "google.com",
    "github.com",
    "facebook.com",
    "wikipedia.org",
    "example.com"
]

print("=" * 50)
print("     HTTPS ENFORCEMENT CHECKER")
print("=" * 50)

all_results = []
for domain in DOMAINS_TO_CHECK:
    result = check_https_enforcement(domain)
    all_results.append(result)

# Final Summary
print("\n" + "=" * 50)
print("         FINAL SUMMARY")
print("=" * 50)
print(f"  {'Domain':<25} {'HTTPS':<8} {'HSTS':<8} {'Score'}")
print("-" * 50)

for r in all_results:
    https = "✅" if r["http_redirects_to_https"] else "❌"
    hsts = "✅" if r["hsts_enabled"] else "❌"
    score = sum([r["http_redirects_to_https"],
                 r["certificate_valid"],
                 r["hsts_enabled"]])
    print(f"  {r['domain']:<25} {https:<8} {hsts:<8} {score}/3")

print("=" * 50)
