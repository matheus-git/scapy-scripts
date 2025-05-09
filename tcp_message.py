from scapy.all import *
import sys
import logging

conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 3:
    print("Usage: tcp_message <ip> <port>")
    sys.exit(1)

def handshake(src_port, dst_ip, dst_port):
    ip = IP(dst=dst_ip)
    print(f"[+] Initiating TCP handshake with {dst_ip}:{dst_port}")
    syn = TCP(sport=src_port, dport=dst_port, flags="S", seq=0)
    resp = sr1(ip / syn, timeout=2)

    if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN-ACK
        ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=1, ack=resp.seq + 1)
        send(ip / ack)
        print(f"[+] Handshake completed. Server Seq={resp.seq}, Client Seq=1")
        return 1, resp.seq + 1
    else:
        raise RuntimeError("[!] No SYN-ACK received. Handshake failed.")

def send_payload(src_port, dst_ip, dst_port, seq, ack, payload):
    ip = IP(dst=dst_ip)
    print(f"[>] Sending payload: {repr(payload.strip())}")
    psh_ack = TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq, ack=ack)
    ack_resp = sr1(ip / psh_ack / payload, timeout=2)

    if ack_resp:
        print(f"[<] Server ACK received: Seq={ack_resp[TCP].seq}, Ack={ack_resp[TCP].ack}")
    else:
        print("[!] No ACK received for payload.")

def fin(src_port, dst_ip, dst_port, seq, ack):
    ip = IP(dst=dst_ip)
    print(f"[x] Sending FIN: Seq={seq}, Ack={ack}")
    fin_pkt = TCP(sport=src_port, dport=dst_port, flags="FA", seq=seq, ack=ack)
    fin_resp = sr1(ip / fin_pkt, timeout=2)

    if fin_resp and fin_resp[TCP].flags & 0x01:  # FIN flag
        print("[<] Server FIN received.")
        server_seq = fin_resp[TCP].seq
        server_ack = fin_resp[TCP].ack

        ack_final = TCP(sport=src_port, dport=dst_port, flags="A", seq=seq + 1, ack=server_seq + 1)
        send(ip / ack_final)
        print("[✓] Final ACK sent. Connection closed cleanly.")
    else:
        print("[!] No FIN received from server. Connection may remain half-open.")

# === Main execution ===
dst_ip = sys.argv[1]
dst_port = int(sys.argv[2])
src_port = 8999

try:
    seq, ack = handshake(src_port, dst_ip, dst_port)

    payload = "hello\n"
    send_payload(src_port, dst_ip, dst_port, seq, ack, payload)
    next_seq = seq + len(payload)

    fin(src_port, dst_ip, dst_port, next_seq, ack)

except Exception as e:
    print(f"[ERROR] {e}")
