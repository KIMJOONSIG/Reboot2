from scapy.all import *
from scapy.all import sniff, IP, TCP, UDP, DNSRR, Raw,ARP,Ether
def analyze_packet(packet):
    if packet.haslayer(Ether) and packet[Ether].src != packet[Ether].dst:
        print("Possible Network Sniffing Detected!")
        print("Packet Details:")
        print(packet.summary())
        print("=" * 40)

def packet_capture(interface, filter_expression):
    try:
        sniff(iface=interface, filter=filter_expression, prn=analyze_packet)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    interface = "eth0"  # 자신의 네트워크 인터페이스로 변경
    filter_expression = ""  # 필터링 없이 모든 패킷 캡처
    packet_capture(interface, filter_expression)
