from scapy.all import sniff, IP
from collections import defaultdict
import threading
from cryptography.fernet import Fernet
import time
import smtplib
from email.mime.text import MIMEText


# 상수 및 초기화
MAX_DICT_SIZE = 1000
fragments = defaultdict(set)
packet_counts = defaultdict(int)
fragmented_packet_counts = defaultdict(int)
ip_ids = defaultdict(list)
last_detected = 0
THRESHOLD = 0.5

# 암호화 키 및 Fernet 객체 생성 (로그 암호화를 위해)
key = Fernet.generate_key()
cipher = Fernet(key)

# 데이터 구조에 대한 락
fragments_lock = threading.Lock()
packet_counts_lock = threading.Lock()
fragmented_packet_counts_lock = threading.Lock()
ip_ids_lock = threading.Lock()

# 로그 암호화 및 저장 함수
def log_encrypted_message(message):
    encrypted_message = cipher.encrypt(f"[{time.ctime()}] {message}".encode())
    with open("network_monitor_encrypted.log", "ab") as log_file:
        log_file.write(encrypted_message + b"\n")

# 딕셔너리 크기 제한 함수
def limit_dict_size(d):
    while len(d) > MAX_DICT_SIZE:
        d.popitem(last=False)

# Teardrop 및 중복 조각 공격 감지 함수
def detect_teardrop_and_overlap(packet):
    global last_detected

    # IP 패킷만 처리
    if IP in packet:
        ip_layer = packet[IP]
        src_dst_pair = (ip_layer.src, ip_layer.dst)

        # 패킷 수 카운트
        with packet_counts_lock:
            packet_counts[src_dst_pair] += 1
        
        # 로그에 패킷 정보 저장
        log_encrypted_message(f"Packet received from {ip_layer.src} to {ip_layer.dst}")

        # IP ID 중복 검사
        with ip_ids_lock:
            ip_ids[src_dst_pair].append(ip_layer.id)
            if ip_ids[src_dst_pair].count(ip_layer.id) > 5:
                now = time.time()
                if now - last_detected > 10:  # 10초 내에 다시 탐지되지 않도록
                    print(f"[{time.ctime()}] Possible attack! Multiple packets with same IP ID from {ip_layer.src} to {ip_layer.dst}")
                    last_detected = now

        # 조각화된 패킷 확인
        if ip_layer.flags == 1 or ip_layer.frag != 0:
            frag_offset = ip_layer.frag
            frag_len = len(ip_layer.payload)

            # Teardrop 공격 조건 확인
            if (frag_offset + frag_len) % 8 != 0:
                print(f"[{time.ctime()}] Possible Teardrop attack detected! Source: {ip_layer.src}, Destination: {ip_layer.dst}, Fragment Offset: {frag_offset}, Fragment Length: {frag_len}, Protocol: {ip_layer.proto}")

            # 중복된 조각 확인
            with fragments_lock:
                if any(offset <= frag_offset < offset + length for (offset, length) in fragments[src_dst_pair]):
                    print(f"[{time.ctime()}] Overlapping fragment detected! Source: {ip_layer.src}, Destination: {ip_layer.dst}, Fragment Offset: {frag_offset}, Protocol: {ip_layer.proto}")
                fragments[src_dst_pair].add((frag_offset, frag_len))

            # 조각화된 패킷의 비율 검사
            with fragmented_packet_counts_lock:
                fragmented_packet_counts[src_dst_pair] += 1
                if fragmented_packet_counts[src_dst_pair] / packet_counts[src_dst_pair] > THRESHOLD:
                    print(f"[{time.ctime()}] High rate of fragmented packets! Source: {ip_layer.src}, Destination: {ip_layer.dst}. Possible attack!")

            # 딕셔너리 크기 제한
            limit_dict_size(packet_counts)
            limit_dict_size(fragmented_packet_counts)
            limit_dict_size(ip_ids)
            limit_dict_size(fragments)

# 별도의 스레드에서 패킷 감지 시작
def start_sniffing():
    try:
        sniff(prn=detect_teardrop_and_overlap, filter="ip", store=0)
    except Exception as e:
        log_encrypted_message(f"Error occurred: {str(e)}")

sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

# 패킷 감지
