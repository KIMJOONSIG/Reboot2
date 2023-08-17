###sudo 명령어를 사용하여 파일 실행(ex. sudo python3 protocol_over.py)
###melicious_domain.txt 파일도 다운받아 함께 실행해야 함
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNSRR
import time
import threading
import sys

##########악성 도메인 목록 불러오기############
def load_malicious_domains(file_path):
    with open(file_path, 'r') as file:
        return set(line.strip() for line in file)

malicious_domains = load_malicious_domains("malicious_domains.txt")
#########################################

# 패킷 소스 IP 별 카운트 및 마지막 기록 시간 저장
packet_count = defaultdict(int)
packet_last_time = defaultdict(float)

# 연속 접속 시도 임곗값 및 기간 설정
THRESHOLD = 10  # 임곗값(연속 접속 시도 횟수 임계값)
DURATION = 5  # 기간 (연속 접속 시도 감지 기간) (초)

# 중지 이벤트 객체 생성
stop_event = threading.Event()

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
        
        # TCP 플래그 설명
        flag_desc = ""
        if tcp_flags is not None:
            if tcp_flags.A:
                flag_desc += "ACK "
            if tcp_flags.F:
                flag_desc += "FIN "
            if tcp_flags.S:
                flag_desc += "SYN "
            if tcp_flags.R:
                flag_desc += "RST "
        
        # 비정상 패킷 판별
        is_protocol_abnormal = False
        if protocol == 1:  # ICMP 프로토콜인 경우 (예시)
            is_protocol_abnormal = True
        
        # 비정상 패킷 크기 판별
        is_size_abnormal = False
        if packet_size > 1500:  # 패킷 크기가 1500 바이트를 초과하는 경우
            is_size_abnormal = True
        
        # IP 주소별로 패킷 카운트 및 마지막 시간 기록
        if (timestamp - packet_last_time[src_ip]) > DURATION:
            packet_count[src_ip] = 0
            packet_last_time[src_ip] = timestamp
        
        packet_count[src_ip] += 1
        
        # 패킷 카운트가 임곗값을 초과하면 경고 출력
        if packet_count[src_ip] > THRESHOLD:
            print(f"\033[91m경고: {src_ip}로부터 빈번한 연결 시도가 감지되었습니다.\033[0m")
        
        # 색상 선택
        if is_protocol_abnormal:
            color = "\033[91m"
        elif is_size_abnormal:
            color = "\033[93m"
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
            if flag_desc != "":
                print(f"TCP Flags: {flag_desc}")
            if udp_length is not None:
                print(f"UDP Length: {udp_length}")
        print("-" * 50)
        print("\033[0m")

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