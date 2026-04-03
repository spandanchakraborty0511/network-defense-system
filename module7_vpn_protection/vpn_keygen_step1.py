import subprocess
import os
import json
import datetime

def generate_wireguard_keys():
    """Generate WireGuard public/private key pair"""
    print("[*] Generating WireGuard key pair...")
    
    # Generate private key
    private_key_result = subprocess.run(
        ["wg", "genkey"],
        capture_output=True,
        text=True
    )
    private_key = private_key_result.stdout.strip()
    
    # Derive public key from private key
    public_key_result = subprocess.run(
        ["wg", "pubkey"],
        input=private_key,
        capture_output=True,
        text=True
    )
    public_key = public_key_result.stdout.strip()
    
    # Generate preshared key for extra security
    preshared_key_result = subprocess.run(
        ["wg", "genpsk"],
        capture_output=True,
        text=True
    )
    preshared_key = preshared_key_result.stdout.strip()
    
    return private_key, public_key, preshared_key

def save_keys(private_key, public_key, preshared_key):
    """Save keys to files securely"""
    
    # Save private key
    with open("private_key.txt", "w") as f:
        f.write(private_key)
    os.chmod("private_key.txt", 0o600)
    print("[+] Private key saved: private_key.txt (chmod 600)")
    
    # Save public key
    with open("public_key.txt", "w") as f:
        f.write(public_key)
    print("[+] Public key saved: public_key.txt")
    
    # Save preshared key
    with open("preshared_key.txt", "w") as f:
        f.write(preshared_key)
    os.chmod("preshared_key.txt", 0o600)
    print("[+] Preshared key saved: preshared_key.txt (chmod 600)")
    
    # Save all keys to JSON
    key_data = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "private_key": private_key,
        "public_key": public_key,
        "preshared_key": preshared_key
    }
    
    with open("keys.json", "w") as f:
        json.dump(key_data, f, indent=4)
    os.chmod("keys.json", 0o600)
    print("[+] All keys saved: keys.json (chmod 600)")

def display_keys(private_key, public_key, preshared_key):
    """Display keys in clean format"""
    print("\n" + "=" * 55)
    print("         WIREGUARD KEY PAIR")
    print("=" * 55)
    print(f"  Private Key  : {private_key[:20]}...")
    print(f"  Public Key   : {public_key[:20]}...")
    print(f"  Preshared Key: {preshared_key[:20]}...")
    print("=" * 55)
    print("\n  [!] IMPORTANT:")
    print("  Private key must NEVER be shared")
    print("  Public key is shared with VPN server")
    print("  Preshared key is shared with VPN peer")
    print("=" * 55)

# ─── Main ─────────────────────────────────────────────────
print("=" * 55)
print("      WIREGUARD KEY GENERATOR")
print("=" * 55)

private_key, public_key, preshared_key = generate_wireguard_keys()
display_keys(private_key, public_key, preshared_key)
save_keys(private_key, public_key, preshared_key)

print("\n[*] Keys generated successfully!")
print("[*] Ready to configure WireGuard tunnel")
