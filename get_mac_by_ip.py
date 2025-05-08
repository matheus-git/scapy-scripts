from scapy.all import ARP, Ether, srp
import sys

if len(sys.argv) != 2:
    print("Usage: get_mac_by_ip <net>")
    sys.exit(1)

def get_mac_by_ip(target_ip, interface=None, timeout=2):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=timeout, iface=interface, verbose=False)[0]

    if result:
        return result[0][1].hwsrc
    else:
        return None

print(get_mac_by_ip(sys.argv[1]))

