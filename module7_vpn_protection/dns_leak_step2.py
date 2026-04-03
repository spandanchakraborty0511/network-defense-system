import socket
import requests
import subprocess
import json
import datetime

def get_current_ip():
    """Get current public IP address"""
    try:
        response = requests.get(
            "https://api.ipify.org?format=json",
            timeout=5
        )
        return response.json()["ip"]
    except Exception as e:
        print(f"[!] Could not get public IP: {e}")
        return None

def get_dns_servers():
    """Get current DNS servers being used"""
    dns_servers = []
    
    try:
        # Read from resolv.conf
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns_ip = line.split()[1].strip()
                    dns_servers.append(dns_ip)
    except Exception as e:
        print(f"[!] Could not read DNS config: {e}")
    
    return dns_servers

def check_dns_leak():
    """Check if DNS requests are leaking"""
    print("[*] Checking for DNS leaks...")
    
    dns_servers = get_dns_servers()
    
    print(f"\n  Current DNS Servers:")
    for dns in dns_servers:
        print(f"    → {dns}")
    
    # Check if DNS servers are private or public
    leaked = []
    safe = []
    
    private_ranges = [
        "10.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.",
        "172.23.", "172.24.", "172.25.", "172.26.",
        "172.27.", "172.28.", "172.29.", "172.30.",
        "172.31.", "192.168.", "127."
    ]
    
    for dns in dns_servers:
        is_private = any(dns.startswith(r) for r in private_ranges)
        if is_private:
            safe.append(dns)
            print(f"\n  [OK] {dns} - Private DNS (safe)")
        else:
            leaked.append(dns)
            print(f"\n  [!!!] {dns} - Public DNS detected!")
            print(f"        This DNS server can see your queries!")
    
    return leaked, safe

def check_dns_resolution():
    """Test DNS resolution and measure speed"""
    test_domains = [
        "google.com",
        "github.com",
        "cloudflare.com"
    ]
    
    print(f"\n[*] Testing DNS resolution speed...")
    print("-" * 50)
    
    results = []
    for domain in test_domains:
        try:
            start = datetime.datetime.now()
            ip = socket.gethostbyname(domain)
            end = datetime.datetime.now()
            
            ms = (end - start).microseconds / 1000
            results.append({
                "domain": domain,
                "ip": ip,
                "ms": round(ms, 2)
            })
            print(f"  {domain:<25} → {ip:<16} {ms:.2f}ms")
            
        except Exception as e:
            print(f"  {domain:<25} → ERROR: {e}")
    
    return results

def get_ip_info(ip):
    """Get information about an IP address"""
    try:
        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5
        )
        data = response.json()
        return {
            "ip": ip,
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "timezone": data.get("timezone", "Unknown")
        }
    except:
        return {"ip": ip, "country": "Unknown"}

# ─── Main ─────────────────────────────────────────────────
print("=" * 55)
print("         DNS LEAK DETECTION TOOL")
print("=" * 55)

# Step 1 - Get public IP
print("\n[*] Getting your public IP address...")
public_ip = get_current_ip()

if public_ip:
    print(f"[+] Your public IP: {public_ip}")
    print("[*] Getting IP information...")
    ip_info = get_ip_info(public_ip)
    print(f"  Country  : {ip_info.get('country', 'Unknown')}")
    print(f"  City     : {ip_info.get('city', 'Unknown')}")
    print(f"  Provider : {ip_info.get('org', 'Unknown')}")

# Step 2 - Check DNS servers
print("\n[*] Checking DNS configuration...")
leaked, safe = check_dns_leak()

# Step 3 - Test DNS resolution
dns_results = check_dns_resolution()

# Step 4 - Summary
print("\n" + "=" * 55)
print("            DNS LEAK REPORT")
print("=" * 55)
print(f"  Public IP      : {public_ip}")
print(f"  Safe DNS       : {len(safe)} servers")
print(f"  Leaked DNS     : {len(leaked)} servers")

if leaked:
    print(f"\n  [!!!] DNS LEAK DETECTED")
    print(f"  Leaked servers: {', '.join(leaked)}")
    print(f"  These servers can see your browsing history!")
    print(f"\n  Fix: Use VPN with DNS leak protection")
    print(f"  Or set DNS to: 1.1.1.1 or 8.8.8.8")
else:
    print(f"\n  [OK] No DNS leak detected")
    print(f"  All DNS queries are going through private servers")

print("=" * 55)

# Save report
report = {
    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "public_ip": public_ip,
    "dns_servers": get_dns_servers(),
    "leaked": leaked,
    "safe": safe
}

with open("dns_leak_report.json", "w") as f:
    json.dump(report, f, indent=4)
print(f"\n[*] Report saved: dns_leak_report.json")
