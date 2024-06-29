#Task 1 ---> Basic Network Sniffer

'''Build a network sniffer in Python that captures and
analyzes network traffic. This project will help you
understand how data flows on a network and how
network packets are structured.'''

from scapy.all import sniff
from scapy.all import IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")
        
        # Check if the packet has a UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")
        
        # Check if the packet has an ICMP layer
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"ICMP Packet: Type {icmp_layer.type} Code {icmp_layer.code}")

# Start sniffing
print("Starting network sniffer...")
sniff(prn=packet_callback, store=0)
