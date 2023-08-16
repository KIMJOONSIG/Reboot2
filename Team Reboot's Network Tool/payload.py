from scapy.all import *
from scapy.layers.inet import *
import time


def packet_callback(packet):
    payload = packet.payload
    print("Payload:")
    print(payload)
    print("===")

# 패킷 캡처 시작
sniff(filter="", prn=packet_callback, count=100) 


