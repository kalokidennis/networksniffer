import argparse
from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, Raw, wrpcap, conf

# Ensure Npcap or WinPcap is properly installed and used on Windows
conf.use_pcap = True

# List to store captured packets
captured_packets = []

# Packet callback function to handle and parse packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Check if it's a TCP packet
        if packet.haslayer(TCP):
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            print(f"[+] TCP Packet: {ip_src}:{tcp_src_port} -> {ip_dst}:{tcp_dst_port}")

            # HTTP packet parsing (HTTP uses port 80 or 443 for HTTPS)
            if tcp_dst_port == 80 or tcp_dst_port == 443:
                if packet.haslayer(Raw):  # HTTP data is usually in the Raw layer
                    http_payload = packet[Raw].load
                    print(f"[+] HTTP Data: {http_payload.decode(errors='ignore')}")

        # Check if it's a UDP packet (for DNS traffic)
        elif packet.haslayer(UDP):
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            print(f"[+] UDP Packet: {ip_src}:{udp_src_port} -> {ip_dst}:{udp_dst_port}")
            
            # DNS packet parsing (DNS uses UDP port 53)
            if udp_dst_port == 53 or udp_src_port == 53:
                if packet.haslayer(DNS):
                    dns_query = packet[DNS].qd.qname if packet[DNS].qd else b""
                    print(f"[+] DNS Query: {dns_query.decode(errors='ignore')}")

    # ARP packet parsing (ARP doesn't have an IP layer)
    if packet.haslayer(ARP):
        arp_src_ip = packet[ARP].psrc
        arp_dst_ip = packet[ARP].pdst
        arp_op = packet[ARP].op  # 1 for ARP request, 2 for ARP reply
        operation = "Request" if arp_op == 1 else "Reply"
        print(f"[+] ARP {operation}: {arp_src_ip} -> {arp_dst_ip}")

    # Add packet to captured list
    captured_packets.append(packet)

# Argument parser setup
def parse_arguments():
    parser = argparse.ArgumentParser(description="A simple network sniffer with protocol-specific parsing for Windows")
    
    parser.add_argument(
        "-p", "--protocol",
        type=str,
        choices=["tcp", "udp", "arp", "dns", "http"],
        default="tcp",
        help="Specify which protocol to capture (default: tcp)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=20,
        help="Number of packets to capture (default: 20)"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="captured_traffic.pcap",
        help="Output file for saving the captured packets (default: captured_traffic.pcap)"
    )
    return parser.parse_args()

# Main function to start sniffing based on user arguments
def main():
    # Parse the command-line arguments
    args = parse_arguments()

    # Set protocol filter based on user input
    if args.protocol == "tcp":
        filter_string = "tcp"
    elif args.protocol == "udp":
        filter_string = "udp"
    elif args.protocol == "arp":
        filter_string = "arp"
    elif args.protocol == "dns":
        filter_string = "udp port 53"
    elif args.protocol == "http":
        filter_string = "tcp port 80"
    else:
        filter_string = ""

    print(f"Sniffing {args.protocol.upper()} packets...")

    # Start sniffing with user-specified count and filter
    sniff(prn=packet_callback, count=args.count, filter=filter_string)

    # Save captured packets to the specified output file
    wrpcap(args.output, captured_packets)

    print(f"Captured packets saved to {args.output}")

if __name__ == "__main__":
    main()
