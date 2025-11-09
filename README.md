# 🔍 ARP & DNS Spoofing Lab Toolkit (Scapy-based)

This repository contains Python tools developed for a UiS DAT505 lab focused on ARP spoofing, DNS spoofing, and traffic analysis using Scapy in a controlled virtual network.

---

## 🧪 Tools Included

### 1. `arp_spoof.py`
A script to perform ARP cache poisoning and maintain a transparent Man-in-the-Middle (MitM) position between a victim and a gateway.

**Features:**
- Bi-directional ARP spoofing
- Optional IP forwarding
- Graceful ARP table restore on exit (CTRL+C)
- Verbose mode for debugging

**Usage:**
```bash
sudo python3 arp_spoof.py -t <victim_ip> -s <gateway_ip> -i <interface> [--ip-forward] [-v]
```

---

### 2. `dns_spoof.py`
A selective DNS spoofing tool to redirect victim DNS queries to attacker-controlled IPs.

**Features:**
- Whitelist / Blacklist spoofing modes
- Configurable spoofed IP address
- Optional forwarding of non-targeted queries
- Works alongside ARP spoofing
- TXT-based domain list input

**Usage:**
```bash
sudo python3 dns_spoof.py -i <interface> -f <domain_list.txt> -m <whitelist|blacklist> -a <attacker_ip> -d <real_dns_ip> [--forward]
```

---

### 3. `scapy_pcap_parser.py`
A PCAP parser that extracts useful metadata from captured traffic.

**Extracts:**
- DNS queries
- HTTP host headers
- Top IP talkers
- Protocol usage statistics

**Usage:**
```bash
python3 scapy_pcap_parser.py <input.pcap> <output.txt>
```

---

## 🧪 Lab Setup

These scripts were tested in an isolated VirtualBox environment with:
- **Attacker VM**: Kali Linux
- **Victim VM**: Ubuntu or Windows
- **Gateway VM**: Ubuntu with Apache and DNS (`dnsmasq`)

All machines were manually IP-configured and connected via an **Internal Network**. The attacker was positioned between victim and gateway using ARP spoofing.

---

## ⚠️ Disclaimer

This project is intended for **educational use only** in secure, isolated environments. Never run these tools on public or unauthorized networks. Use responsibly and ethically.
