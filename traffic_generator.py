#!/usr/bin/env python3

# traffic_generator.py
# Generates various types of network traffic and saves it to a PCAP file
# for testing the pcap_analyzer.py tool.

import argparse
import random
import time
import os
from datetime import datetime

# Attempt to import Scapy
try:
    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap, send, sendp, RandShort
    from scapy.utils import PcapWriter
    # For HTTP-like traffic (optional, can craft manually too)
    # from scapy.layers.http import HTTPRequest (More complex to ensure it's basic)
except ImportError:
    print("Critical Error: Scapy is not installed. Please install it: pip install scapy")
    exit(1)

# --- Configuration ---
DEFAULT_SRC_IP = "192.168.1.101" # A source IP for generated packets
DEFAULT_NORMAL_DST_IPS = ["8.8.8.8", "1.1.1.1", "192.168.1.1"] # Benign destinations
DEFAULT_MALICIOUS_DST_IP = "10.0.0.99" # This IP should be in your analyzer's blacklist
DEFAULT_UNUSUAL_PORT_TCP = 31337
DEFAULT_UNUSUAL_PORT_UDP = 41414
DEFAULT_LONG_CONN_DURATION_S = 120 # Simulate a 2-minute connection for "long-lived"
DEFAULT_OUTPUT_PCAP = "generated_traffic.pcap"

# --- Packet Crafting Functions ---

def create_base_packet(src_ip, dst_ip, src_mac="00:11:22:33:44:55", dst_mac="AA:BB:CC:DD:EE:FF"):
    """Creates a base Ethernet/IP packet."""
    return Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip)

def generate_normal_tcp_traffic(num_packets, src_ip, normal_dst_ips):
    """Generates some 'normal' TCP traffic to common ports."""
    packets = []
    common_tcp_ports = [80, 443, 22, 25, 110]
    print(f"Generating {num_packets} normal TCP packets...")
    for i in range(num_packets):
        dst_ip = random.choice(normal_dst_ips)
        sport = RandShort() # Random source port
        dport = random.choice(common_tcp_ports)
        
        # Simulate a simple TCP handshake (SYN, SYN-ACK, ACK) and some data
        # For simplicity, we'll just send a few packets that look like part of a flow
        
        # SYN packet
        if i % 3 == 0:
            pkt = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0, 2**32-1))
        # Data packet (simulating after handshake)
        elif i % 3 == 1:
            pkt = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=random.randint(0, 2**32-1), ack=random.randint(0, 2**32-1)) / Raw(load=f"Normal TCP data payload {i}")
        # FIN packet
        else:
            pkt = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=random.randint(0, 2**32-1), ack=random.randint(0, 2**32-1))
        
        pkt.time = time.time() + (i * 0.01) # Slightly offset packet times
        packets.append(pkt)
    return packets

def generate_normal_udp_traffic(num_packets, src_ip, normal_dst_ips):
    """Generates some 'normal' UDP traffic to common ports (e.g., DNS)."""
    packets = []
    common_udp_ports = [53, 123, 161] # DNS, NTP, SNMP
    print(f"Generating {num_packets} normal UDP packets...")
    for i in range(num_packets):
        dst_ip = random.choice(normal_dst_ips)
        sport = RandShort()
        dport = random.choice(common_udp_ports)
        pkt = create_base_packet(src_ip, dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=f"Normal UDP data {i}")
        pkt.time = time.time() + (i * 0.02)
        packets.append(pkt)
    return packets

def generate_malicious_ip_traffic(num_packets, src_ip, malicious_ip, use_tcp=True):
    """Generates traffic to/from a 'malicious' IP."""
    packets = []
    print(f"Generating {num_packets} packets involving malicious IP {malicious_ip}...")
    for i in range(num_packets):
        # Alternate between source and destination being malicious
        current_src_ip = src_ip if i % 2 == 0 else malicious_ip
        current_dst_ip = malicious_ip if i % 2 == 0 else src_ip
        
        sport = RandShort()
        dport = random.randint(1025, 65535) # Random high port

        if use_tcp:
            pkt = create_base_packet(current_src_ip, current_dst_ip) / TCP(sport=sport, dport=dport, flags="S") / Raw(load="Suspicious TCP payload")
        else: # UDP
            pkt = create_base_packet(current_src_ip, current_dst_ip) / UDP(sport=sport, dport=dport) / Raw(load="Suspicious UDP payload")
        pkt.time = time.time() + (i * 0.015)
        packets.append(pkt)
    return packets

def generate_unusual_port_traffic(num_packets, src_ip, dst_ip, unusual_port, protocol="TCP"):
    """Generates traffic to an unusual port."""
    packets = []
    proto_name = protocol.upper()
    print(f"Generating {num_packets} {proto_name} packets to unusual port {unusual_port} on {dst_ip}...")
    for i in range(num_packets):
        sport = RandShort()
        if proto_name == "TCP":
            pkt = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=unusual_port, flags="S") / Raw(load=f"Data to unusual TCP port {unusual_port}")
        elif proto_name == "UDP":
            pkt = create_base_packet(src_ip, dst_ip) / UDP(sport=sport, dport=unusual_port) / Raw(load=f"Data to unusual UDP port {unusual_port}")
        else:
            print(f"Warning: Unsupported protocol {protocol} for unusual port traffic. Skipping.")
            continue
        pkt.time = time.time() + (i * 0.025)
        packets.append(pkt)
    return packets

def generate_simulated_long_connection(duration_seconds, src_ip, dst_ip, dst_port=1234):
    """
    Simulates a long-lived TCP connection by sending a few packets
    with start and end times separated by duration_seconds.
    The analyzer should pick this up based on flow start/last_seen times.
    """
    packets = []
    print(f"Simulating a long connection ({duration_seconds}s) to {dst_ip}:{dst_port}...")
    start_time = time.time()
    
    # Packet 1: Start of connection
    sport = RandShort()
    pkt_start = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=dst_port, flags="S") / Raw(load="Long conn: Start")
    pkt_start.time = start_time
    packets.append(pkt_start)

    # Packet 2: Some data in between (optional, makes it more realistic)
    # Send it a bit after the start
    if duration_seconds > 2: # Only if duration is somewhat significant
        pkt_middle = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=dst_port, flags="PA") / Raw(load="Long conn: Middle data")
        pkt_middle.time = start_time + (duration_seconds / 2.0)
        packets.append(pkt_middle)

    # Packet 3: End of observed activity for this "long" flow
    pkt_end = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=dst_port, flags="PA") / Raw(load="Long conn: End")
    pkt_end.time = start_time + duration_seconds
    packets.append(pkt_end)
    
    return packets

def generate_http_on_non_standard_port(num_packets, src_ip, dst_ip, non_std_port=8001):
    """Generates HTTP-like GET requests on a non-standard TCP port."""
    packets = []
    print(f"Generating {num_packets} HTTP-like GETs to {dst_ip}:{non_std_port}...")
    http_payload = f"GET /testpage.html HTTP/1.1\r\nHost: {dst_ip}\r\n\r\n"
    for i in range(num_packets):
        sport = RandShort()
        pkt = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=non_std_port, flags="PA") / Raw(load=http_payload)
        pkt.time = time.time() + (i * 0.03)
        packets.append(pkt)
    return packets

def generate_non_http_on_http_port(num_packets, src_ip, dst_ip, http_port=80):
    """Generates non-HTTP TCP traffic (random payload) on a standard HTTP port."""
    packets = []
    print(f"Generating {num_packets} non-HTTP TCP packets to {dst_ip}:{http_port}...")
    for i in range(num_packets):
        sport = RandShort()
        random_payload = os.urandom(random.randint(20, 100)) # Random binary data
        pkt = create_base_packet(src_ip, dst_ip) / TCP(sport=sport, dport=http_port, flags="PA") / Raw(load=random_payload)
        pkt.time = time.time() + (i * 0.035)
        packets.append(pkt)
    return packets

def main():
    parser = argparse.ArgumentParser(
        description="Generate fake network traffic for PCAP analysis testing.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--output-pcap", "-o",
        default=DEFAULT_OUTPUT_PCAP,
        help=f"Filename for the output PCAP (default: {DEFAULT_OUTPUT_PCAP})"
    )
    parser.add_argument(
        "--src-ip",
        default=DEFAULT_SRC_IP,
        help=f"Source IP for generated packets (default: {DEFAULT_SRC_IP})"
    )
    parser.add_argument(
        "--malicious-ip",
        default=DEFAULT_MALICIOUS_DST_IP,
        help=f"Target 'malicious' IP for testing (default: {DEFAULT_MALICIOUS_DST_IP})"
    )
    parser.add_argument(
        "--num-normal-tcp", type=int, default=20,
        help="Number of normal TCP packets (default: 20)"
    )
    parser.add_argument(
        "--num-normal-udp", type=int, default=15,
        help="Number of normal UDP packets (default: 15)"
    )
    parser.add_argument(
        "--num-malicious", type=int, default=10,
        help="Number of packets involving the malicious IP (default: 10)"
    )
    parser.add_argument(
        "--num-unusual-tcp", type=int, default=5,
        help=f"Number of TCP packets to unusual port {DEFAULT_UNUSUAL_PORT_TCP} (default: 5)"
    )
    parser.add_argument(
        "--num-unusual-udp", type=int, default=5,
        help=f"Number of UDP packets to unusual port {DEFAULT_UNUSUAL_PORT_UDP} (default: 5)"
    )
    parser.add_argument(
        "--long-conn-duration", type=int, default=DEFAULT_LONG_CONN_DURATION_S,
        help=f"Duration in seconds for simulated long connection (default: {DEFAULT_LONG_CONN_DURATION_S})"
    )
    parser.add_argument(
        "--num-http-non-std", type=int, default=5,
        help="Number of HTTP-like packets to non-standard port (default: 5)"
    )
    parser.add_argument(
        "--num-non-http-std", type=int, default=5,
        help="Number of non-HTTP packets to standard HTTP port (default: 5)"
    )
    # Add more arguments for other parameters if needed

    args = parser.parse_args()

    all_packets = []
    current_time_offset = 0 # To ensure packets are somewhat ordered in time

    # 1. Normal TCP Traffic
    if args.num_normal_tcp > 0:
        pkts = generate_normal_tcp_traffic(args.num_normal_tcp, args.src_ip, DEFAULT_NORMAL_DST_IPS)
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        current_time_offset += args.num_normal_tcp * 0.1 # Add a small delay before next batch

    # 2. Normal UDP Traffic
    if args.num_normal_udp > 0:
        pkts = generate_normal_udp_traffic(args.num_normal_udp, args.src_ip, DEFAULT_NORMAL_DST_IPS)
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        current_time_offset += args.num_normal_udp * 0.1

    # 3. Malicious IP Traffic (TCP)
    if args.num_malicious > 0:
        pkts = generate_malicious_ip_traffic(args.num_malicious // 2, args.src_ip, args.malicious_ip, use_tcp=True)
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        current_time_offset += (args.num_malicious // 2) * 0.1
    # Malicious IP Traffic (UDP)
    if args.num_malicious > 0:
        pkts = generate_malicious_ip_traffic(args.num_malicious - (args.num_malicious // 2) , args.src_ip, args.malicious_ip, use_tcp=False)
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        current_time_offset += (args.num_malicious - (args.num_malicious // 2)) * 0.1


    # 4. Unusual TCP Port Traffic
    if args.num_unusual_tcp > 0:
        pkts = generate_unusual_port_traffic(args.num_unusual_tcp, args.src_ip, random.choice(DEFAULT_NORMAL_DST_IPS), DEFAULT_UNUSUAL_PORT_TCP, "TCP")
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        current_time_offset += args.num_unusual_tcp * 0.1

    # 5. Unusual UDP Port Traffic
    if args.num_unusual_udp > 0:
        pkts = generate_unusual_port_traffic(args.num_unusual_udp, args.src_ip, random.choice(DEFAULT_NORMAL_DST_IPS), DEFAULT_UNUSUAL_PORT_UDP, "UDP")
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        current_time_offset += args.num_unusual_udp * 0.1

    # 6. Simulated Long Connection
    if args.long_conn_duration > 0:
        # Ensure this uses a distinct time range
        pkts = generate_simulated_long_connection(args.long_conn_duration, args.src_ip, random.choice(DEFAULT_NORMAL_DST_IPS))
        # Adjust time for these packets to be after current offset, and maintain their internal timing
        base_time_for_long_conn = time.time() + current_time_offset
        for p in pkts:
            p.time = base_time_for_long_conn + (p.time - pkts[0].time) # Preserve relative timing
        all_packets.extend(pkts)
        current_time_offset += args.long_conn_duration + 1.0 # Add duration + buffer

    # 7. HTTP on Non-Standard Port
    if args.num_http_non_std > 0:
        pkts = generate_http_on_non_standard_port(args.num_http_non_std, args.src_ip, random.choice(DEFAULT_NORMAL_DST_IPS))
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        current_time_offset += args.num_http_non_std * 0.1

    # 8. Non-HTTP on Standard HTTP Port
    if args.num_non_http_std > 0:
        pkts = generate_non_http_on_http_port(args.num_non_http_std, args.src_ip, random.choice(DEFAULT_NORMAL_DST_IPS))
        for p in pkts: p.time += current_time_offset
        all_packets.extend(pkts)
        # current_time_offset += args.num_non_http_std * 0.1 # Not strictly needed for last batch

    # Sort packets by time before writing, essential for realistic PCAP
    all_packets.sort(key=lambda pkt: pkt.time)
    
    print(f"\nGenerated a total of {len(all_packets)} packets.")
    
    # Write to PCAP file
    try:
        print(f"Writing packets to {args.output_pcap}...")
        wrpcap(args.output_pcap, all_packets)
        print(f"Successfully saved to {args.output_pcap}")
    except Exception as e:
        print(f"Error writing PCAP file: {e}")

if __name__ == "__main__":
    main()
