from scapy.all import *
from scapy.all import sniff, IP, TCP, UDP
def analyze_packet(packet):
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

def packet_capture(interface, filter_expression):
    try:
        sniff(iface=interface, filter=filter_expression, prn=analyze_packet)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    interface = "eth0"  # 자신의 네트워크 인터페이스로 변경
    filter_expression = "udp port 1194 or udp port 51820"  # OpenVPN 및 WireGuard 포트로 변경
    packet_capture(interface, filter_expression)
