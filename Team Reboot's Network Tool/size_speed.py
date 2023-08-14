from scapy.all import *
from scapy.layers.inet import *
import time

target_ip = "172.114.203.89"  # 목표 IP 주소
target_port = 443  # 목표 포트 번호
start_time = time.time()

def packet_handler(packet):
    
    packet_size = len(packet)
    max_packet_size = 8 # 스머프 어택 기준

    syn_packet_count = 0
    threshold_syn = 100  # SYN 패킷 수 임계치(syn flooding 판단기준)
    
    ping_packet_count = 0
    threshold_ping = 100  # Ping 패킷 수 임계치
    
    open_connections = {}  # 연결 유지하는 연결 개수를 저장하는 딕셔너리
    max_open_connections = 100  # 최대 연결 개수 임계치, Slowris판별
    
    packet_sizes = []###너무 빠른 속도로 패킷이 오고 있지 않은지 판별
    packet_timestamps = []  # 패킷 전송 시간을 저장하는 리스트
    current_time = time.time()
    max_packet_size_MTU = 1500  # Ethernet MTU 기준

    # 패킷 크기가 너무 크거나 너무 빠른 전송 속도를 판단하는 로직 추가
    word=""
    if packet_size > max_packet_size_MTU:
        word+=f"Potential Large Packet Detected! Packet Size: {packet_size}"+"\n"

    if len(packet_timestamps) > 0:
        time_diff = current_time - packet_timestamps[-1]
        if time_diff < 0.001:  # 예를 들어, 1ms 이하의 시간 간격으로 패킷이 온 경우
            word+=f"Possible Fast Transmission Detected! Time Interval: {time_diff:.6f} seconds"+"\n"

    packet_sizes.append(packet_size)
    packet_timestamps.append(current_time)
    elapsed_time = current_time - start_time

    if elapsed_time > 0:
        send_rate = sum(packet_sizes) / elapsed_time  # 초당 평균 전송량 계산
        word+=f"Packet Size: {packet_size}, Send Rate: {send_rate:.2f} bytes/sec"+"\n"

    


    ####스머프 어택 판별
    if packet_size <= max_packet_size:
        word+=f"Potential Smurf Attack Detected! Packet Size: {packet_size}"+"\n"
    else:
        word+=f"Normal Packet Size: {packet_size}"+"\n"
    ###syn flooding판별+slowris판별
    if TCP in packet:
        
        ##slowris판별용 
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        if packet[TCP].flags == 'S':
            ####syn flooding판별
            syn_packet_count += 1
            word+=f"SYN Packet Detected! Count: {syn_packet_count}"+"\n"
        
            if syn_packet_count > threshold_syn:
                word+=f"Possible SYN Flood Attack Detected!"+"\n"
                
            ######slowris판별
            if src_ip not in open_connections:
                open_connections[src_ip] = 0
            open_connections[src_ip] += 1
            
            if open_connections[src_ip] > max_open_connections:
                word+=f"Possible Slowloris Attack Detected! IP: {src_ip}, Open Connections: {open_connections[src_ip]}"+"\n"

    if ICMP in packet:        
    ###ping flooding 판별
        if packet[ICMP].type == 8:  # ICMP Echo Request 패킷 (Ping)인 경우
            ping_packet_count += 1
            word+=f"Ping Packet Detected! Count: {ping_packet_count}"+"\n"
        
            if ping_packet_count > threshold_ping:
               word+=f"Possible Ping Flooding Detected!"+"\n"
    print(word)
            

    
   


# 패킷 캡처 시작
sniff(filter="tcp or udp or icmp", prn=packet_handler, count=100)
#sniff(filter=f"ip dst {target_ip} and tcp dst port {target_port}", prn=packet_handler, count=100)

print("Packet capture finished.")



