# 악성 IP 주소 목록 불러오기
def load_malicious_ips(file_path):
    with open(file_path, 'r') as file:
        return set(line.strip() for line in file)

# Specify the absolute path to the file
malicious_ips = load_malicious_ips(r"C:\Users\USER\Desktop\구름프로젝트2\malicious_IP.txt")

# Evaluate IP 함수 정의
def evaluate_ip(ip_address, logs):
    # 패턴 1: 특정 포트로의 다중 연결 검출
    if detect_multiple_connections(ip_address, logs):
        return True

    # 패턴 2: 비정상적 포트 사용 검출
    if detect_unusual_ports(ip_address, logs):
        return True

    # 패턴 3: 비정상 데이터 전송 검출
    if detect_unusual_data_transfer(ip_address, logs):
        return True

    return False

# 패턴 검출 함수: 동일 IP로의 다수 연결 감지
def detect_patterns(ip_address, logs):
    CONNECTION_THRESHOLD = 5  # 의심을 불러일으킬 연결 수의 임계값
    unique_ports = {}  # 포트 당 연결 수를 추적하기 위한 딕셔너리

    for log in logs:
        _, source_ip, _, port, _ = log.split('|')

        if source_ip.strip() == ip_address:
            port = port.strip()
            if port in unique_ports:
                unique_ports[port] += 1
            else:
                unique_ports[port] = 1

    if len(unique_ports) >= CONNECTION_THRESHOLD:
        return True

    return False

# 패턴 검출 함수: 동일 IP로의 다중 연결 감지
def detect_multiple_connections(ip_address, logs):
    CONNECTION_THRESHOLD = 5  # 의심을 불러일으킬 연결 수의 임계값

    connection_count = 0
    unique_ports = set()

    for log in logs:
        _, source_ip, _, port, _ = log.split('|')

        if source_ip.strip() == ip_address:
            connection_count += 1
            unique_ports.add(port.strip())

    if connection_count >= CONNECTION_THRESHOLD and len(unique_ports) > 1:
        return True

    return False

# 패턴 검출 함수: 비정상적 포트 사용
def detect_unusual_ports(ip_address, logs):
    UNUSUAL_PORTS = {'8080', '9999', '31337', '12345'}  # 비정상적 포트 예시 목록

    for log in logs:
        _, source_ip, _, port, _ = log.split('|')

        if source_ip.strip() == ip_address and port.strip() in UNUSUAL_PORTS:
            return True

    return False

# 패턴 검출 함수: 비정상 데이터 전송
def detect_unusual_data_transfer(ip_address, logs):
    DATA_THRESHOLD = 10000  # 비정상 데이터 전송 임계값 (바이트 단위)

    total_data_transferred = 0

    for log in logs:
        _, source_ip, _, _, data = log.split('|')
        
        if source_ip.strip() == ip_address:
            total_data_transferred += len(data.strip())  # 데이터 길이 계산 (문자열로 가정)

    if total_data_transferred > DATA_THRESHOLD:
        return True

    return False
	
# 행동 기반 탐지 함수: 비정상 동작 감지
def detect_abnormal_behavior(ip_address, logs):
    NORMAL_ACTIVITY_THRESHOLD = 100  # 정상 활동 횟수 임계값
    activity_count = 0

    for log in logs:
        _, source_ip, _, _, _ = log.split('|')

        if source_ip.strip() == ip_address:
            activity_count += 1

    if activity_count < NORMAL_ACTIVITY_THRESHOLD:
        return True

    return False

# 로그 데이터 불러오기
def load_logs(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]
    
logs = load_logs(R"C:\Users\USER\Desktop\구름프로젝트2\network_logs.txt")    

# Suspicious Outbound Traffic 검출 함수 정의
def detect_suspicious_outbound_traffic(ip_address, logs):
    OUTBOUND_THRESHOLD = 10  # 의심스러운 아웃바운드 트래픽 발생 횟수 임계값

    outbound_count = 0
    dest_ip_counts = {}  # 목적지 IP 주소별 트래픽 수를 추적하기 위한 딕셔너리

    for log in logs:
        _, source_ip, dest_ip, _, _ = log.split('|')

        if source_ip.strip() == ip_address:
            if dest_ip.strip() == dest_ip_counts:
                dest_ip_counts[dest_ip.strip()] += 1
            else:
                dest_ip_counts[dest_ip.strip()] = 1
                
    for dest_ip, count in dest_ip_counts.items():
        if count >= OUTBOUND_THRESHOLD:
            return True
    
    return False

# 메인 함수
def main():
    malicious_ips = load_malicious_ips(r"C:\Users\USER\Desktop\구름프로젝트2\malicious_IP.txt")
    logs = load_logs("network_logs.txt")  # 실제 로그 불러오는 방식으로 대체

    for ip in malicious_ips:
        if detect_patterns(ip, logs) or \
           detect_multiple_connections(ip, logs) or \
           detect_unusual_ports(ip, logs) or \
           detect_unusual_data_transfer(ip, logs) or \
           evaluate_ip(ip, logs) or \
           detect_suspicious_outbound_traffic(ip, logs) or \
           detect_abnormal_behavior(ip, logs):
            print("잠재적 위협:", ip)

if __name__ == "__main__":
    main()
