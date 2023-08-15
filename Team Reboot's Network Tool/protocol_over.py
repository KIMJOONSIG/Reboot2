from scapy.all import sniff, IP, TCP
import time
import threading
import sys

# 패킷 캡처 및 지연 시간, 패킷 크기, 프로토콜, 세션 정보 출력
def packet_callback(packet):
    if IP in packet:
        timestamp = time.time()
        packet_size = len(packet)
        protocol = packet[IP].proto
        protocol_name = packet[IP].sprintf("%IP.proto%")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[IP].sport
        dst_port = packet[IP].dport

        seq_num = 0
        if TCP in packet:
            seq_num = packet[TCP].seq
        
        # 비정상적인 패킷 판별 조건을 추가 (ICMP 프로토콜)
        is_protocol_abnormal = False
        if protocol == 1:  # ICMP 프로토콜인 경우 (예시)
            is_protocol_abnormal = True
        
        # 비정상적인 패킷 판별 조건을 추가 (패킷 크기)
        is_size_abnormal = False
        if packet_size > 1500:  # 예: 패킷 크기가 1500 바이트를 초과하는 경우 비정상으로 판별
            is_size_abnormal = True
        
        # 색상 선택
        if is_protocol_abnormal:
            color = "\033[91m"  # 빨간색
        elif is_size_abnormal:
            color = "\033[93m"  # 노란색
        else:
            color = "\033[0m"   # 기본색
        
        print(f"{color}Timestamp: {timestamp:.6f}, Packet Size: {packet_size} bytes, Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}")
        print(f"Sequence Number: {seq_num}")
        print("-" * 50)
        print("\033[0m")  # 기본색으로 리셋

# 엔터 키를 누를 때 프로그램을 종료하는 함수
def stop_capture():
    print("Press Enter to stop capturing...")
    input()  # 엔터 키를 대기
    sys.exit(0)  # 프로그램 종료

# 패킷 캡처 및 종료 스레드 시작
capture_thread = threading.Thread(target=lambda: sniff(filter="ip", prn=packet_callback), daemon=True)
stop_thread = threading.Thread(target=stop_capture)

# 스레드 시작
capture_thread.start()
stop_thread.start()

try:
    capture_thread.join()
    stop_thread.join()
except KeyboardInterrupt:
    print("Interrupted by user.")
    sys.exit(0)

print("Packet capturing stopped.")
