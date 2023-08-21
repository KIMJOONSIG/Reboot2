import json
import gzip
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from telegram import Bot

# 텔레그램 봇 토큰과 채팅 ID 정의
token = ""  # 여러분의 텔레그램 봇 토큰으로 변경
chat_id = "6389282491"  # 여러분의 채팅 ID로 변경
bot = Bot(token=token)

# 모니터링할 로그 디렉터리 정의
log_dir = '/data/suricata/log'  # 로그 파일 경로로 변경

# 로그 메시지 파싱 함수
def parse_log(log):
    log_json = json.loads(log)
    alert_data = log_json.get('alert', {})
    msg = f"Timestamp: {log_json.get('timestamp', '')}\n"
    msg += f"Alert Category: {alert_data.get('category', '')}\n"
    msg += f"Alert Signature: {alert_data.get('signature', '')}\n"
    msg += f"Alert Severity: {alert_data.get('severity', '')}\n"
    return msg

# 로그 파일 이벤트를 처리하는 사용자 지정 클래스 생성
class LogHandler(FileSystemEventHandler):
    def process(self, event):
        # 이벤트가 디렉터리가 아니고 파일이 '.gz'로 끝나는 경우 확인
        if not event.is_directory and event.src_path.endswith('.gz'):
            # gzipped 파일을 열고 내용 읽기
            with gzip.open(event.src_path, 'rt') as file:
                content = file.read()
                # 로그 파일 내용 파싱
                parsed_log = parse_log(content)
                # 로그 파일 내용을 지정된 텔레그램 채팅으로 보내기
                bot.send_message(chat_id=chat_id, text=f"{event.src_path} 파일에 다음 로그 내용이 있습니다:\n{parsed_log}")

    # 파일이 수정될 때 이벤트 처리
    def on_modified(self, event):
        self.process(event)

    # 파일이 생성될 때 이벤트 처리
    def on_created(self, event):
        self.process(event)

# 로그 디렉터리를 모니터링하는 관찰자 생성
observer = Observer()
# 사용자 지정 LogHandler와 로그 디렉터리 경로를 지정하여 관찰자 예약
observer.schedule(LogHandler(), path=log_dir, recursive=True)
# 관찰자 시작
observer.start()

# 키보드 인터럽트 (Ctrl+C)로 중단될 때까지 스크립트를 실행
try:
    while True:
        pass
except KeyboardInterrupt:
    observer.stop()

# 관찰자 스레드를 메인 스레드에 조인
observer.join()
