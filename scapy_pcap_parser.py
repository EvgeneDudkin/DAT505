from scapy.all import *
from collections import Counter
import argparse
import os
import re

def extract_http_host(payload):
    try:
        lines = payload.decode(errors='ignore').split('\r\n')
        for line in lines:
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except:
        return None

def parse_pcap(input_file, output_file):
    dns_queries = []
    http_hosts = []
    ip_counter = Counter()
    protocol_counter = Counter()

    packets = rdpcap(input_file)

    for pkt in packets:
        # Count IPs and protocols
        if IP in pkt:
            ip_counter[pkt[IP].src] += 1
            ip_counter[pkt[IP].dst] += 1

            # Guess protocol
            proto = pkt[IP].proto
            if proto == 6:
                protocol_counter['TCP'] += 1
            elif proto == 17:
                protocol_counter['UDP'] += 1
            else:
                protocol_counter[f"IP_PROTO_{proto}"] += 1

        # DNS Query extraction
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            qname = pkt[DNSQR].qname.decode().strip('.')
            dns_queries.append(qname)

        # HTTP Host extraction (very basic)
        if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
            payload = bytes(pkt[TCP].payload)
            host = extract_http_host(payload)
            if host:
                http_hosts.append(host)

    # Output to file
    with open(output_file, 'w') as f:
        f.write("=== DNS Queries ===\n")
        for q in sorted(set(dns_queries)):
            f.write(f"{q}\n")

        f.write("\n=== Visited HTTP Hosts ===\n")
        for h in sorted(set(http_hosts)):
            f.write(f"{h}\n")

        f.write("\n=== Top Talkers (IP Addresses) ===\n")
        for ip, count in ip_counter.most_common(10):
            f.write(f"{ip}: {count} packets\n")

        f.write("\n=== Protocol Usage ===\n")
        for proto, count in protocol_counter.items():
            f.write(f"{proto}: {count}\n")

    print(f"[+] Analysis complete. Output written to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scapy PCAP Parser")
    parser.add_argument("input", help="Input .pcap file")
    parser.add_argument("output", help="Output text file")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] Error: input file '{args.input}' does not exist.")
    else:
        parse_pcap(args.input, args.output)