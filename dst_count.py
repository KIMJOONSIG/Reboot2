import pyshark
from collections import Counter

#해당 경로에 있는 pcap 파일 읽어오기
pcap_file = "C:\\Users\\Big\\Desktop\\packet\\0.pcap.HostPair_1-1-38-155_1-2-152-85.pcap"
r_pcap = pyshark.FileCapture(pcap_file)


print("Analyzing -> " + pcap_file.split('\\')[-1])

#목적지 주소를 저장할 리스트
dst_address = []

#총 패킷 수
total_packet = 0

# 각 패킷 반복
for packet in r_pcap:
    total_packet += 1
    if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst'):
        dst_address.append(packet.ip.dst)

#주소별 카운트 계산
address_count = Counter(dst_address)

print("Total Packet -> ", total_packet)

for address, count in address_count.items():
    print(f"DST_Addess: {address}, Count: {count}")