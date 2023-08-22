#로컬 환경에서 aws의 log파일 가져온 후 텔레그램으로 보냄
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from telegram import Bot
import paramiko

# 텔레그램 봇 토큰과 채팅 ID
token = "token" # 텔레그램 봇 토큰
chat_id = "6389282491" # 채팅 ID
bot = Bot(token=token)

# AWS SSH 정보
aws_ssh_key = '/Users/threatexe/Desktop/My Key.pem' # AWS SSH 키 경로
aws_server_ip = '43.202.11.153' # AWS 서버 IP 주소
aws_user = 'goorm-kdt-008' # AWS 사용자 이름
aws_port = 64297 # SSH 포트

# 로그 디렉토리 정보
remote_log_dir = '/tpotce/data/suricata/log' # AWS 서버의 원격 로그 디렉토리
local_log_dir = '/Volumes/Untitled/aws_logs' # 로그를 저장할 로컬 디렉토리

# AWS에 연결하고 로그 다운로드
def download_logs():
    # AWS 서버에 SSH 연결 설정
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(aws_server_ip, username=aws_user, key_filename=aws_ssh_key, port=aws_port)

    # 파일 전송을 위한 SFTP 세션 열기
    sftp = ssh_client.open_sftp()
    
    # 원격 파일 목록 가져오기
    remote_files = sftp.listdir(remote_log_dir)
    # 로컬 파일 목록 가져오기
    local_files = os.listdir(local_log_dir)
    
    # 새 파일만 다운로드(파일 중복 배제 기능)
    for file in remote_files:
        if file not in local_files:
            # AWS 서버에서 로컬 디렉토리로 파일 다운로드
            sftp.get(os.path.join(remote_log_dir, file), os.path.join(local_log_dir, file))

    # SFTP 및 SSH 세션 닫기
    sftp.close()
    ssh_client.close()

# 로그 모니터링
class LogHandler(FileSystemEventHandler):
    # 파일 수정 이벤트 처리
    def on_modified(self, event):
        # 파일이면서 '.log' 확장자를 가지면
        if not event.is_directory and event.src_path.endswith('.log'):
            with open(event.src_path, 'r') as file:
                content = file.read()
                # 로그 파일 내 의심스러운 패턴 확인
                if "suspicious_pattern" in content:
                    # 의심스러운 패턴이 발견되면 텔레그램에 경고 메시지 전송
                    bot.send_message(chat_id=chat_id, text=f"경고! {event.src_path}에 의심스러운 패턴이 발견되었습니다.")

# AWS 서버에서 로그 다운로드
download_logs()

# 로그 모니터링 시작
observer = Observer()
observer.schedule(LogHandler(), path=local_log_dir, recursive=True)
observer.start()

# 프로그램을 계속 실행
try:
    while True:
        pass
except KeyboardInterrupt:
    # KeyboardInterrupt (예: Ctrl+C)를 받으면 관찰자를 중지
    observer.stop()

# 관찰자 스레드가 완료될 때까지 대기
observer.join()
