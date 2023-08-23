from scapy.all import *  # Scapy 라이브러리

def packet_callback(packet):  # 패킷 콜백 함수를 정의, 각 패킷에 대해 이 함수가 호출
    if packet.haslayer(TCP) and packet.haslayer(Raw):  # 패킷이 TCP 레이어 and 원시 데이터(Raw) 레이어를 가지고 있는지 확인
        if packet[TCP].dport == 22 or packet[TCP].sport == 22:  # 패킷이 SSH 포트 (22번)로 가거나 오는지 확인
            print("Possible SSH connection attempt:") # SSH 연결 시도일 가능성이 있는 경우 메시지를 출력
            print(packet.summary()) # 패킷의 요약 정보를 출력
            print(packet[TCP].payload) # packet의 TCP payload를 출력, SSH 연결의 내용
            print("=" * 40) # 구분선을 출력, 각 패킷 정보 사이에 구분
