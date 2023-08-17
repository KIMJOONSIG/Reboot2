from scapy.all import sniff, IP, TCP, UDP
import time
import threading
import sys
from collections import defaultdict
import os

# 패킷 캡처 및 지연 시간, 패킷 크기, 프로토콜, 세션 정보 출력

# ###################### 포트 스캔 탐지를 위한 변수들 #######################
port_scan_threshold = 10 # 허용되는 연결 시도 횟수
port_scan_window = 5 # 초
recent_ports = defaultdict(list)

def packet_callback(packet):
    if packet.haslayer(IP):
        timestamp = time.time()
        packet_size = len(packet)
        protocol = packet[IP].proto
        protocol_name = packet[IP].sprintf("%IP.proto%")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        seq_num = 0
        tcp_flags = None
        udp_length = None
        
        if TCP in packet:
            seq_num = packet[TCP].seq
            tcp_flags = packet[TCP].flags
        elif UDP in packet:
            udp_length = packet[UDP].len
        
        # TCP 플래그 확인 및 표시
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
        
        # 비정상적인 패킷 판별 조건을 추가 (ICMP 프로토콜)
        is_protocol_abnormal = False
        if protocol == 1:  # ICMP 프로토콜인 경우 (예시)
            is_protocol_abnormal = True
        
        # 비정상적인 패킷 판별 조건을 추가 (패킷 크기)
        is_size_abnormal = False
        if packet_size > 1500:  # 예: 패킷 크기가 1500 바이트를 초과하는 경우 비정상으로 판별
            is_size_abnormal = True

        # ################## 포트 스캔 감지 로직 추가 ################

        is_port_scan = False
        if TCP in packet and packet[TCP].dport:  # TCP 패킷이며 목적지 포트가 있는 경우
            dst_port = packet[TCP].dport
            recent_ports[src_ip].append((timestamp, dst_port))

            # 최근 연결 시도 횟수 확인
            recent_attempts = [p for t, p in recent_ports[src_ip] if timestamp - t < port_scan_window]
            if len(recent_attempts) >= port_scan_threshold:
                is_port_scan = True
                recent_ports[src_ip] = []  # 초기화
            
            ############### 확실한 포트 스캔 탐지 로직 추가 (TCP 플래그 기반) ###################
            if "SYN" in flag_desc and "ACK" not in flag_desc:  # SYN 스캔 (SYN Scan)
                is_port_scan = True
            elif "FIN" in flag_desc and not any(flag in flag_desc for flag in ["SYN", "ACK", "RST"]):  # FIN flag만 (FIN Scan)])
                is_port_scan = True
            elif not any(flag in flag_desc for flag in ["SYN", "ACK", "FIN" "RST", "PSH", "URG"]): # Null 스캔
                is_port_scan = True
            elif all(flag in flag_desc for flag in ["Fin", "PSH", "URG"]):  #Xmas 스캔
                is_port_scan = True
            elif "ACK" in flag_desc and not any(flag in flag_desc for flag in ["SYN", "FIN", "RST"]):  # ACK 스캔
                is_port_scan = True

            if is_port_scan:
                print(f"\033[95mPort scan detected from {src_ip}!\033[0m")    

        # 색상 선택
        if is_protocol_abnormal:
            color = "\033[91m"  # 빨간색
        elif is_size_abnormal:
            color = "\033[93m"  # 노란색
        else:
            color = "\033[0m"   # 기본색
        
        print(f"{color}Timestamp: {timestamp:.6f}, Packet Size: {packet_size} bytes, Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        if protocol == 6 or protocol == 17:  # TCP 또는 UDP 프로토콜일 때만 출력
            src_port = packet[IP].sport
            dst_port = packet[IP].dport
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
            if seq_num != 0:
                print(f"Sequence Number: {seq_num}")
            if flag_desc != "":
                print(f"TCP Flags: {flag_desc}")
            if udp_length is not None:
                print(f"UDP Length: {udp_length}")  # UDP 패킷 길이 출력
        print("-" * 50)
        print("\033[0m")  # 기본색으로 리셋


# ###################### 종료 로직 수정 #############################
def stop_capture():
    print("Press Enter to stop capturing...")
    input()  # 엔터 키를 대기
    os._exit(0)  # 모든 스레드를 종료 (수정된 부분)

# 패킷 캡처 및 종료 스레드 시작
stop_thread = threading.Thread(target=stop_capture, daemon=True)  # 수정된 부분
stop_thread.start()

try:
    sniff(filter="ip", prn=packet_callback)  # 주 스레드에서 실행 (수정된 부분)
except KeyboardInterrupt:
    print("Interrupted by user.")
##########################################################################