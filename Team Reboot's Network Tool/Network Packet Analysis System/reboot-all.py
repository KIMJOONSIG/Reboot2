###sudo 명령어를 사용하여 파일 실행(ex. sudo python3 [.py])
###melicious_domain.txt 파일도 다운받아 함께 실행해야 함
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNSRR, Raw,ARP,Ether
import time
import threading
import sys
import re


###탐지 공격종류: 악성 도메인 탐지, SQL 인젝션 탐지, 랜드 어택, ARP 스푸핑, 스캐너 탐지, ssh연결 탐지,get post연결 탐지 ,목적지가 127.0.0.1 탐지, 디렉터리 리스팅 탐지, xss탐지, Command_injection탐지,VPN탐지,네트워크 스니핑 탐지
##########악성 도메인 목록 불러오기############
def load_malicious_domains(file_path):
    with open(file_path, 'r') as file:
       return set(line.strip() for line in file)

malicious_domains = load_malicious_domains("malicious_domains.txt")
#########################################

# 경고를 발생시키는 함수
def raise_alert(packet_count):
    print(f"Alert! Excessive packet rate detected: {packet_count} packets in the last second.")

#SQL 인젝션 탐지
def detect_sql_injection(payload):
    sql_keywords = ["SELECT", "UPDATE", "INSERT", "DELETE", "DROP", "UNION", "OR"]
    
    for keyword in sql_keywords:
        if keyword in payload:
            return True
    return False

# 중지 이벤트 객체 생성
stop_event = threading.Event()
# land attack을 탐지하는 함수
def detect_land_attack(packet):
    if IP in packet and packet[IP].src == packet[IP].dst:
        raise_alert(1)

duplicate_ips = defaultdict(set)

# arp spoofing을 탐지하는 함수
def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP 응답 패킷인 경우
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        
	# mac주소를 이용해 arp spoofing 탐지
        if ip in duplicate_ips and mac not in duplicate_ips[ip]:
            print(f"Possible ARP Spoofing detected:")
            print(f"IP: {ip}, MAC: {mac}")
            print(f"Other MACs for this IP: {', '.join(duplicate_ips[ip])}")
            print("=" * 40)
        
        duplicate_ips[ip].add(mac)

# 패킷 콜백 함수
def packet_callback(packet):
    global packet_count, packet_last_time
    
    #패킷에서 DNS 응답과 도메인 이름 추출(악성 도메인은 초록색으로 추출)
    if packet.haslayer(DNSRR):
        rrname = packet[DNSRR].rrname.decode('utf-8')
        if rrname in malicious_domains:
            print(f"\033[92m악성 도메인 감지: {rrname}\033[0m") ##########악성 도메인 감지#######
        else:
            print(f"도메인: {rrname}") #######일반적인 도메인##########

    # 패킷에 IP 계층이 있으면
    if packet.haslayer(IP):
        timestamp = time.time()  # 현재 시간
        packet_size = len(packet)  # 패킷 크기
        protocol = packet[IP].proto  # 프로토콜 번호
        protocol_name = packet[IP].sprintf("%IP.proto%")  # 프로토콜 이름
        src_ip = packet[IP].src  # 소스 IP
        dst_ip = packet[IP].dst  # 목적지 IP

        seq_num = 0
        tcp_flags = None
        udp_length = None
        
        # TCP 계층이 있으면
        if TCP in packet:
            seq_num = packet[TCP].seq  # 시퀀스 번호
            tcp_flags = packet[TCP].flags  # TCP 플래그
        # UDP 계층이 있으면
        elif UDP in packet:
            udp_length = packet[UDP].len  # UDP 길이
        
        ip_src = packet[IP].src
        
        # 비정상 패킷 판별
        is_protocol_abnormal = False
        if protocol == 1:  # ICMP 프로토콜인 경우 (예시)
            is_protocol_abnormal = True
        
        # 비정상 패킷 크기 판별
 
        if TCP in packet:
            ip_dst = packet[IP].dst
            src_port = packet[TCP].sport
            flags = packet[TCP].flags
        
            #######스캐너탐지
            if flags == 0x01:  # FIN flag set (FIN scan)
                print(f"FIN scan detected: Source IP: {ip_src}, Destination IP: {ip_dst}, Source   Port: {src_port}")
            elif flags == 0x00:  # No flags set (NULL scan)
                print(f"NULL scan detected: Source IP: {ip_src}, Destination IP: {ip_dst}, Source Port: {src_port}")
            elif flags == 0x29:  # FIN, URG, PSH flags set (Xmas scan)
                print(f"Xmas scan detected: Source IP: {ip_src}, Destination IP: {ip_dst}, Source Port: {src_port}")

            else:
                print(f"")
        

        #####SSH연결 탐지
            if  packet.haslayer(Raw):  # 패킷이 TCP 레이어 and 원시 데이터(Raw) 레이어를 가지고 있는지 확인
                if packet[TCP].dport == 22 or packet[TCP].sport == 22:  # 패킷이 SSH 포트 (22번)로 가거나 오는지 확인
                    print("Possible SSH connection attempt:") # SSH 연결 시도일 가능성이 있는 경우 메시지를 출력
                    print(packet.summary()) # 패킷의 요약 정보를 출력
                    print(packet[TCP].payload) # packet의 TCP payload를 출력, SSH 연결의 내용
                    print("=" * 40) # 구분선을 출력, 각 패킷 정보 사이에 구분

        #
       #### # 패킷 안에 IP와 TCP일 때 payload 출력 #get요청 확인
            payload = packet[TCP].payload
            if payload:
                try:
                    payload_str = payload.decode('utf-8') #utf-8로 디코딩
                    if 'GET' in payload_str or 'POST' in payload_str: #페이로드 중 GET, POST가 있는지 확인 후 페이로드 출력
                        print(f"Payload: {payload}")
                except (UnicodeDecodeError, AttributeError):
                    print('Payload Decoding Error...')
  
        # 색상 선택
        if is_protocol_abnormal:
            color = "\033[91m"
        
        else:
            color = "\033[0m"
        
        # 패킷 정보 출력
        print(f"{color}Timestamp: {timestamp:.6f}, Packet Size: {packet_size} bytes, Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        if protocol == 6 or protocol == 17:
            src_port = packet[IP].sport
            dst_port = packet[IP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
            if seq_num != 0:
                print(f"Sequence Number: {seq_num}")
            if TCP in packet and packet[TCP].flags is not None:
                print(f"TCP Flags: {packet[TCP].flags}")
            if udp_length is not None:
                print(f"UDP Length: {udp_length}")
        print("-" * 50)
        print("\033[0m")


        # 패킷이 IP 레이어를 가지고 있고, 해당 IP의 목적지가 127.0.0.1인지 확인
    if packet.haslayer(IP) and packet[IP].dst == "127.0.0.1":
        print("Detected packet with destination 127.0.0.1:")

        ########디렉토리 리스팅 관련 HTTP 요청 탐지##########
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if payload.startswith('GET') and(keyword in payload.lower() for keyword in ['directory', 'index', 'listing']):
                print(f"\033[91mDirectory listing request detected: {payload}\033[0m")
     
                ##Command_injection탐지
            if "';" in payload or "&&" in payload:
                print("Possible Command Injection detected!")
                print("Packet Details:")
                print(packet.summary())
                print("Payload:")
                print(payload)
                print("=" * 40)

            ##XSS탐지
            if packet.haslayer(Raw) and "HTTP" in payload:
                http_payload = payload.split('\r\n\r\n')[1]
                # XSS 취약점 패턴 검사
                xss_patterns = ["<script>", "alert(", "onmouseover="]
                for pattern in xss_patterns:
                    if re.search(pattern, http_payload, re.IGNORECASE):
                        print("Possible XSS detected!")
                        print("Packet Details:")
                        print(packet.summary())
                        print("Payload:")
                        print(http_payload)
                        print("=" * 40)
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                payload = packet[TCP].payload
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='ignore')
                    # OpenVPN 패킷 검출
                    if "OpenVPN" in payload:
                        print("Possible OpenVPN traffic detected!")
                        print("Packet Details:")
                        print(packet.summary())
                        print("=" * 40)
            # WireGuard 패킷 검출
                    if "WireGuard" in payload:
                        print("Possible WireGuard traffic detected!")
                        print("Packet Details:")
                        print(packet.summary())
                        print("=" * 40)

    if packet.haslayer(Ether) and packet[Ether].src != packet[Ether].dst:
        print("Possible Network Sniffing Detected!")
        print("Packet Details:")
        print(packet.summary())
        print("=" * 40)
#################################################################
        
        
        
        detect_land_attack(packet)
        arp_monitor_callback(packet)
        


# 패킷 캡처 종료 함수
def stop_capture():
    print("Press Enter to stop capturing...")
    input()
    stop_event.set()
    sys.exit(0)

# 패킷 캡처 및 종료 스레드 시작
capture_thread = threading.Thread(target=lambda: sniff(filter="ip", prn=packet_callback), daemon=True)
stop_thread = threading.Thread(target=stop_capture)

# 스레드 시작
capture_thread.start()
stop_thread.start()

# 프로그램 종료 대기
try:
    capture_thread.join()
    stop_thread.join()
except KeyboardInterrupt:
    print("Interrupted by user.")
    stop_event.set()
    sys.exit(0)

print("Packet capturing stopped.")
