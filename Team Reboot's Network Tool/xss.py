from scapy.all import *
import re
from scapy.all import sniff, IP, TCP, UDP
def analyze_packet(packet):
    if packet.haslayer(TCP):
        payload = packet[TCP].payload
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', errors='ignore')
            if packet.haslayer(Raw) and "HTTP" in payload:
                http_payload = payload.split('\r\n\r\n')[1]
                # XSS 취약점 패턴 검사
                xss_patterns = ["<script>", "alert(", "onmouseover="]
                for pattern in xss_patterns:
                    if re.search(pattern, http_payload, re.IGNORECASE):
                        print("Possible XSS detected!")
                        print("Packet Details:")
                        print(packet.summary())
                        print("Payload:")
                        print(http_payload)
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
