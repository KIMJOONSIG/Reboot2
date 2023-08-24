from scapy.all import *

def packet_callback(packet):
    # 패킷이 IP 레이어를 가지고 있고, 해당 IP의 목적지가 127.0.0.1인지 확인
    if packet.haslayer(IP) and packet[IP].dst == "127.0.0.1":
        print("Detected packet with destination 127.0.0.1:")
        packet.show()  # 패킷의 상세 정보를 출력

if __name__ == "__main__":
    # 목적지 IP 주소가 127.0.0.1인 패킷만 필터링하여 스니핑
    sniff(filter="dst host 127.0.0.1", prn=packet_callback, store=0)