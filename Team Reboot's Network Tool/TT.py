import os
import paramiko
import requests
import json

# SCP 설정
hostname = "3.36.218.150"
port = 64295
username = "admin"
private_key_path = "/Users/threatexe/Desktop/keykey.pem"

# 로그 파일 경로
remote_log_directory = "/data/suricata/log"
local_log_directory = "/Volumes/Untitled/aws_logs"
last_size_file = os.path.join(local_log_directory, "last_size.txt")  # 마지막 크기 저장 파일

# 텔레그램 설정
token = ""
chat_id = "6389282491"
telegram_api_url = f"https://api.telegram.org/bot{token}/sendMessage"

def parse_log(log):
    try:
        data = json.loads(log)

        # Severity를 기준으로 필터링
        # Severity가 2인 경우만 알림을 전송

        if 'alert' in data and data['alert'].get('severity') in [1, 2]:  
            msg = f"Timestamp: {data.get('timestamp')}\n"
            msg += f"Event Type: {data.get('event_type')}\n"
            msg += f"Source IP: {data.get('src_ip', 'N/A')}\n"
            msg += f"Source Port: {data.get('src_port', 'N/A')}\n"
            msg += f"Destination IP: {data.get('dest_ip', 'N/A')}\n"
            msg += f"Destination Port: {data.get('dest_port', 'N/A')}\n"
            msg += f"Alert: {data['alert'].get('signature', 'N/A')}\n"
            msg += f"Category: {data['alert'].get('category', 'N/A')}\n"
            msg += f"Severity: {data['alert'].get('severity', 'N/A')}\n"

            return msg
        else:
            return None 
        
    except Exception as e:
        return f"Error parsing the log: {log}. Error: {e}"  # 에러 내용도 함께 출력

def send_message(parsed_log):
    payload = {
        "chat_id": chat_id,
        "text": parsed_log
    }
    response = requests.post(telegram_api_url, data=payload)
    return response.json()

# 마지막 크기 가져오기
try:
    with open(last_size_file, 'r') as f:
        last_size = int(f.read())
except:
    last_size = 0

# AWS에서 eve.json 로그 파일 가져오기
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_client.connect(hostname, port=port, username=username, key_filename=private_key_path)

sftp = ssh_client.open_sftp()

eve_json_remote_path = os.path.join(remote_log_directory, "eve.json")
eve_json_local_path = os.path.join(local_log_directory, "eve.json")

# 원격 서버에서 로컬 디렉터리로 eve.json 가져오기
sftp.get(eve_json_remote_path, eve_json_local_path)

# 새로 추가된 로그만 파싱 및 텔레그램 메시지 전송
with open(eve_json_local_path, 'r') as file:
    file.seek(last_size)  # 이전 크기부터 시작
    for line in file:
        parsed_log_content = parse_log(line.strip())  # 로그 파싱 추가
        if parsed_log_content:
            send_message(parsed_log_content)  # 파싱된 로그 내용 전송

# 현재 크기 저장
with open(last_size_file, 'w') as f:
    f.write(str(os.path.getsize(eve_json_local_path)))

sftp.close()
ssh_client.close()
