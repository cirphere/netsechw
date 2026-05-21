# HW1 - TCP Session Hijacking 개선 과제 실행 가이드

PDF (netsec06_L2attacks, netsec07_L4attacks) 기반으로 정리한 VM 실행 절차입니다.
강의 환경(Mininet + scapy)을 그대로 사용합니다.

## 토폴로지
```
                       h3 (10.0.0.3)  - 공격자 (ARP spoofer + hijacker)
                          |
        +-----------------+-----------------+
        |                 s1                |
        h1 (10.0.0.1) ---/   \--- h2 (10.0.0.2)
        client (victim)        server
```

## 파일 구성
| 파일 | 용도 |
|------|------|
| `arpspoof.py`      | 교재 (netsec06 p.15) 원본 — 양방향 ARP 포이즈닝 |
| `hijack_step0.py`  | Step 0: 교재 (netsec07 p.62-63) 코드 — 들여쓰기만 수정 |
| `hijack_step1.py`  | Step 1: 양방향 hijack (server 응답 수신) |
| `hijack_step2.py`  | Step 2: 투명 MITM (victim 무자각 + 정상 송수신) |

전제: MiniEdit으로 토폴로지(h1=10.0.0.1, h2=10.0.0.2, h3=10.0.0.3 + 스위치)를
이미 띄우고 `Start CLI` 로 `mininet>` 상태에 진입했다고 가정합니다.

## 호스트 xterm 열기

`mininet>` 프롬프트에서:
```
mininet> xterm h1 h2 h3
```
세 호스트 각각의 xterm 창에서 아래 명령들을 실행합니다.

스크립트는 `/Users/circle/netsec/hw1/` 에 있으므로, h3 xterm에서:
```bash
cd /root/netsec/hw1   # 또는 VM에서 이 폴더가 마운트/복사된 경로
ls
```

> **인터페이스 이름 확인**: h3 xterm에서 `ip -br a` 로 인터페이스 이름이
> `h3-eth0` 인지 확인. 다르면 스크립트에 `-i <iface>` 로 넘기세요.

> **의존성**: 각 호스트는 같은 VM의 네임스페이스이므로 한 번만 설치하면 됩니다.
> ```bash
> sudo apt install -y python3-scapy ncat tcpdump
> ```

---

## Step 0 - 기본 공격 환경 성공 확인

**스크린샷 포인트**: h2의 ncat 화면에 공격자가 inject 한 한 줄이 도착하는 모습.

1. **h2 (server)**:
   ```bash
   ncat -l -p 1001
   ```

2. **h1 (client)**:
   ```bash
   ncat 10.0.0.2 1001
   hello from h1
   ```
   → h2 화면에 `hello from h1` 표시 확인.

3. **h3 (attacker)** - ARP 스푸핑 시작:
   ```bash
   sysctl -w net.ipv4.ip_forward=0
   python3 arpspoof.py 10.0.0.1 10.0.0.2
   ```
   (별도 xterm에서) `arp -n` 으로 h1/h2의 ARP 테이블이 둘 다 h3의 MAC을
   가리키는지 확인 → MITM 위치 확보.

4. **h3** (또 다른 xterm) - hijacking:
   ```bash
   python3 hijack_step0.py -s 10.0.0.2 -p 1001 -c 10.0.0.1
   ```
   첫 server→client ACK/PSH-ACK 을 잡으면 `>>` 프롬프트가 뜸. 메시지 입력 →
   h2 화면에 그대로 들어가는지 확인 (Step 0 완료).

> ⚠ Step 0 까지는 client 가 메세지를 한 번 보낸 직후 attacker 가 끼어듭니다.
> 이 시점부터 client 가 추가로 입력하면 seq/ack 어긋남으로 RST 가 날 수도
> 있습니다 (정상). Step 2에서 해결.

---

## Step 1 - 하이재킹 세션 양방향 통신

**스크린샷 포인트**: h3 attacker 화면에서 자신이 입력한 메시지와 **server 가 응답으로 보낸 메시지**가 둘 다 보이는 모습.

1. Step 0 의 ncat/arpspoof 환경 그대로.
2. h3 에서 Step 0 대신 Step 1 실행:
   ```bash
   python3 hijack_step1.py -s 10.0.0.2 -p 1001
   ```
3. 흐름:
   - h1: `ncat 10.0.0.2 1001` → "hi" 입력 (세션 활성화 트리거)
   - h3 attacker: `[+] hijacked ...` 로그 → `>>` 프롬프트에 메시지 입력
   - h2 server xterm 에서 답장 입력 → h3 attacker 창에 `[server] ...` 로 표시

확인 사항:
- attacker 가 보낸 메시지가 server 에 도착
- server 가 보낸 메시지가 attacker 에 도착
- (Step 2 와 달리) client 는 이때부터 연결이 이상해질 수 있음 - 정상

---

## Step 2 - 투명 MITM (victim 인식 불가)

**스크린샷 포인트**:
- (a) victim h1 의 ncat 창에 server 메시지가 **정상** 도착
- (b) server h2 가 client/attacker 양쪽 메시지를 **각각** 수신
- (c) attacker h3 화면에 server 메시지가 출력
- (d) server 가 Ctrl-C 등으로 종료하면 client 도 정상 종료

1. h3 환경:
   ```bash
   sysctl -w net.ipv4.ip_forward=0   # 커널 자동 포워딩 OFF
   python3 arpspoof.py 10.0.0.1 10.0.0.2
   ```

2. h2: `ncat -l -p 1001`
3. h1: `ncat 10.0.0.2 1001`
4. h3:
   ```bash
   python3 hijack_step2.py -s 10.0.0.2 -c 10.0.0.1 -p 1001
   ```

테스트 시나리오 (스크린샷 캡쳐 권장):
1. h1 에서 `client says hello` 입력 → h2 에 도착 확인.
2. h2 에서 `server says hi` 입력 → h1, h3 양쪽 모두에 출력 확인.
3. h3 의 `attacker>` 프롬프트에서 `secretly injected!` 입력
   → h2 에는 도착 (server 가 받음), h1 에는 도착하지 않음.
4. h2 가 다시 메세지 보내면 h1 / h3 둘 다에 도착.
5. h2 종료 (Ctrl-C) → h1 의 ncat 도 자동 종료.

작동 원리 요약 (보고서에 정리하기 좋은 포인트):
- h3 가 h1↔h2 양쪽에 ARP 응답을 뿌려 모든 트래픽이 h3 를 경유.
- 커널 IP forwarding 은 끄고 scapy 가 직접 패킷 단위 relay.
- 공격자가 inject 한 누적 바이트를 `cli_offset` 로 관리:
  - client→server 패킷: `seq += cli_offset` (server 가 일관된 stream 으로 봄)
  - server→client 패킷: `ack -= cli_offset` (client 가 자기가 보낸 만큼만 ACK 받음)
- TCP FIN/RST 는 그대로 relay → 정상 종료 전파.

---

## 스크린샷 체크리스트 (보고서 첨부용)

- [ ] Step 0: arpspoof 실행 화면 + 양쪽 ARP 테이블 (`arp -n`)
- [ ] Step 0: hijack_step0 에서 메시지 inject → h2 ncat 수신 화면
- [ ] Step 1: attacker 화면에서 inject + server 응답 동시 표시
- [ ] Step 2: client/server/attacker 3창 모두에서 메시지 흐름
- [ ] Step 2: attacker inject 시 client 화면에는 보이지 않는 모습
- [ ] Step 2: server 종료 시 client 도 같이 종료되는 모습

## 자주 발생하는 문제

| 증상 | 원인/해결 |
|------|-----------|
| Inject 후 RST | seq/ack 어긋남. Step2 에서는 `cli_offset` 관리로 해결. Step0/1 에서는 발생 가능. |
| ARP 스푸핑이 안 먹음 | mininet 캐시. h1/h2 에서 `ip neigh flush all` 후 ping 재시도 |
| scapy `permission denied` | `sudo` 로 실행 |
| h3 가 패킷을 못 봄 | `arpspoof` 가 살아있는지 확인, `tcpdump -ni h3-eth0` 로 검증 |
| 인터페이스 이름 다름 | 스크립트의 `dev` 값이나 `-i` 옵션 수정 |
