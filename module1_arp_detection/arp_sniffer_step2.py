from scapy.all import sniff, ARP

# This dictionary acts as our database
# Format: { "IP address" : "MAC address" }
arp_table = {}

def process_packet(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]

        # We only care about ARP REPLIES (op=2)
        # Replies are what update ARP caches
        if arp.op == 2:
            sender_ip = arp.psrc
            sender_mac = arp.hwsrc

            # Case 1 - New IP we've never seen before
            if sender_ip not in arp_table:
                arp_table[sender_ip] = sender_mac
                print(f"[+] New device learned: {sender_ip} → {sender_mac}")

            # Case 2 - IP we know, but MAC has CHANGED
            elif arp_table[sender_ip] != sender_mac:
                print(f"[!!!] ALERT - MAC CHANGE DETECTED")
                print(f"  IP          : {sender_ip}")
                print(f"  Old MAC     : {arp_table[sender_ip]}")
                print(f"  New MAC     : {sender_mac}")
                print(f"  Possible ARP Spoofing Attack!")
                print("-" * 40)
                # Update the table with new MAC
                arp_table[sender_ip] = sender_mac

            # Case 3 - Everything matches, all good
            else:
                print(f"[OK] {sender_ip} → {sender_mac} (unchanged)")

print("[*] Monitoring ARP traffic... Press Ctrl+C to stop")
sniff(filter="arp", prn=process_packet, store=0)
