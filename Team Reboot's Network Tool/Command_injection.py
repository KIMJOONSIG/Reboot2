from scapy.all import *
from scapy.all import sniff, IP, TCP, UDP
def analyze_packet(packet):
    if packet.haslayer(TCP):
        payload = packet[TCP].payload
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', errors='ignore')
            # 명령어 삽입 패턴 검사
            if "';" in payload or "&&" in payload:
                print("Possible Command Injection detected!")
                print("Packet Details:")
                print(packet.summary())
                print("Payload:")
                print(payload)
                print("=" * 40)

def packet_capture(interface, filter_expression):
    try:
        sniff(iface=interface, filter=filter_expression, prn=analyze_packet)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    interface = "eth0"  # 자신의 네트워크 인터페이스로 변경
    filter_expression = "tcp port 80"  # 감지하고자 하는 포트로 변경
    packet_capture(interface, filter_expression)
