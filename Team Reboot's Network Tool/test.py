from scapy.all import *
import time

# 이전 측정 시간 및 패킷 수 초기화
prev_time = time.time()
prev_packet_count = 0

# 경고를 발생시키는 함수
def raise_alert(packet_count):
    print(f"Alert! Excessive packet rate detected: {packet_count} packets in the last second.")

# land attack을 탐지하는 함수
def detect_land_attack(packet):
    if IP in packet and packet[IP].src == packet[IP].dst:
        raise_alert(1)


# MAC 주소 관리용
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

try:
    while True:
        current_time = time.time()
        elapsed_time = current_time - prev_time

        # 패킷 캡쳐 및 개수 확인
        packets = sniff(count=1000, timeout=1)  # 1초 동안 최대 1000개의 패킷 캡쳐
        packet_count = len(packets)

        # 경고 발생 여부 확인
        if elapsed_time > 0:
            packet_rate = packet_count / elapsed_time
            if packet_rate > 300:  # 평균 300 패킷/초 이상이면 경고 발생
                raise_alert(packet_rate)
	
        for packet in packets:
            # land attack 탐지
            detect_land_attack(packet)
 	    # arp spoofing 탐지
            arp_monitor_callback(packet)

        # 이전 시간값 업데이트
        prev_time = current_time
        prev_packet_count = packet_count

except KeyboardInterrupt:
    print("Packet capture stopped.")
    sys.exit()
