import os
from scapy.all import *

def packet_handler(packet):
    """
    Handle each captured packet and display relevant information.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = packet[Raw].load if Raw in packet else None
        
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {proto}")
        if payload:
            print("Payload Data:", payload)
        print("="*50)

        # Save packet information to a file
        with open("packet_log.txt", "a") as f:
            f.write(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {proto}\n")
            if payload:
                f.write("Payload Data:" + str(payload) + "\n")
            f.write("="*50 + "\n")

def packet_sniffer(interface="eth0", count=100):
    """
    Sniff network packets on the specified interface.
    """
    print(f"[*] Sniffing packets on interface {interface}...")

    # Start sniffing packets
    sniff(iface=interface, prn=packet_handler, count=count)

    print("[*] Packet sniffing complete.")

if __name__ == "__main__":
    # Clear previous log file
    if os.path.exists("packet_log.txt"):
        os.remove("packet_log.txt")

    # Start packet sniffing
    packet_sniffer()
