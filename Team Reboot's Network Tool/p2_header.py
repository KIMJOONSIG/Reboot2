from collections import defaultdict
from scapy.all import sniff, IP, TCP

# 각 IP 주소별 연결 요청 횟수 저장
connection_requests = defaultdict(int)

def process_packet(packet):
    # IP 패킷인지 확인
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # 연결 요청 횟수 증가
        connection_requests[src_ip] += 1
        
        # 특정 IP가 일정 횟수 이상 연결을 시도한 경우 경고
        if connection_requests[src_ip] > 10:
            print(f"Suspicious activity detected from {src_ip}!")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"Source IP: {src_ip}\tDestination IP: {dst_ip}\tSource Port: {src_port}\tDestination Port: {dst_port}")
        else:
            print(f"Source IP: {src_ip}\tDestination IP: {dst_ip}")

# 패킷을 캡처하고 process_packet 함수로 분석
sniff(filter="ip", prn=process_packet, count=50)