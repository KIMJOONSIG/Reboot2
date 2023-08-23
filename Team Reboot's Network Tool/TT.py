import paramiko
from telegram import Bot

# SCP 설정
hostname = "3.38.48.8"  # AWS T-Pot IP 주소
port = 64295  # SSH 포트 번호
username = "admin"
private_key_path = "key2.pem"  # 키 경로

# 로그 파일 경로
remote_log_path = "/path/to/elasticpot/logs"  # T-Pot에서 로그 파일의 경로
local_log_path = "/path/to/save/logs/on/local"  # 로컬에서 로그를 저장할 경로

# 텔레그램 설정
token = "YOUR_BOT_TOKEN"
chat_id = "YOUR_CHAT_ID"
bot = Bot(token=token)

# AWS에서 로그 파일 가져오기
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_client.connect(hostname, port=port, username=username, key_filename=private_key_path)

sftp = ssh_client.open_sftp()
sftp.get(remote_log_path, local_log_path)
sftp.close()
ssh_client.close()

# 로그 파일 파싱 및 텔레그램 메시지 전송
with open(local_log_path, 'r') as file:
    for line in file:
        # 로그 파싱 로직 (예제에서는 각 줄을 그대로 보냄)
        parsed_log = line.strip()
        bot.send_message(chat_id=chat_id, text=parsed_log)
