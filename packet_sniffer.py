from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = packet.proto if hasattr(packet, "proto") else "Unknown"

        print(f"[+] Packet: {src} -> {dst} | Protocol: {proto}")

        if TCP in packet or UDP in packet:
            payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
            if payload:
                print(f"    Payload: {payload[:50]}...\n")

print("🌐 Starting packet sniffer (Press Ctrl+C to stop)...")
sniff(prn=process_packet, store=False, count=10)