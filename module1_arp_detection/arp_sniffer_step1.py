from scapy.all import sniff, ARP

def process_packet(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]
        
        op_type = "REQUEST" if arp.op == 1 else "REPLY"
        
        print(f"[ARP {op_type}]")
        print(f"  Sender IP  : {arp.psrc}")
        print(f"  Sender MAC : {arp.hwsrc}")
        print(f"  Target IP  : {arp.pdst}")
        print(f"  Target MAC : {arp.hwdst}")
        print("-" * 40)

print("[*] Starting ARP sniffer... Press Ctrl+C to stop")
sniff(filter="arp", prn=process_packet, store=0)
