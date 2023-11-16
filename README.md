# 🌈 Team Reboot Second Project
- ☁ 구름(goorm) 정보 보호 전문가 양성 마스터 클래스 과정 1기의 goorm Team Project: 네트워크 패킷 분석 시스템 개발
<br>

## 📂 프로젝트 개요

- **과제 주제:** 네트워크 패킷 분석 시스템 개발
- **과제 기간:** 2023.08.15 ~ 2023.08.28
- **과제 설명:** 파이썬 코드를 활용한 패킷 캡처 및 분석 시스템 개발과 지능형 위협 감지 알림 시스템 개발

<br>

## 🛠️ Technical Skills

### 📒 Languages
<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white"/> 

### 📗 Tools
<img src="https://img.shields.io/badge/Visual Studio Code-007ACC?style=for-the-badge&logo=visualstudiocode&logoColor=white"/> <img src="https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white"/> <img src="https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white"/>
<br><img src="https://img.shields.io/badge/Security Onion-000000?style=for-the-badge&logo=aHR0cHM6Ly9zZWN1cml0eW9uaW9uc29sdXRpb25zLmNvbS9sb2dvL2xvZ28tc28tZGFyay5zdmc="/> <img src="https://img.shields.io/badge/Suricata-ff7f00?style=for-the-badge&logo=aHR0cHM6Ly9zdXJpY2F0YS5pby93cC1jb250ZW50L3VwbG9hZHMvMjAyMi8wMS9Mb2dvSG9yaXotU3VyaWNhdGFGaW5hbC00LXRyYW5zbHVjZW50LnBuZw=="/> <img src="https://img.shields.io/badge/Telegram-26A5E4?style=for-the-badge&logo=telegram&logoColor=white"/> <img src="https://img.shields.io/badge/Tpot-ff3399?style=for-the-badge&logo=&logoColor=white"/>

### 📙 Communication
<img src="https://img.shields.io/badge/Slack-4A154B?style=for-the-badge&logo=slack&logoColor=white"/> <img src="https://img.shields.io/badge/Notion-000000?style=for-the-badge&logo=notion&logoColor=white"/> 

<br>

## 💻 조원 소개

<table>
  <tr>
    <th align="center">이름</th>
    <th align="center">역할</th>
    <th align="center">맡은 부분</th>
  </tr>
  <tr>
    <td align="center">박서경</td>
    <td align="center">조장</td>
    <th align="center">Command-based injection Attack * OpenVPN * WireGuard Packet Detection
    <br> Syn Flooding, Slowris, XSS Attack Detection </th>
  </tr>
    <tr>
    <td align="center">김준식</td>
    <td align="center">조원</td>
    <th align="center">Directory listing Http * Malicious Domain Detection
    <br> Telegram threat alarm system using T-pot and Customizing Surikata Rules
 </th>
  </tr>
      <tr>
    <td align="center">김기연</td>
    <td align="center">조원</td>
    <th align="center">Land Attack * ARP spoofing * Packet Over-Averaging Detection</th>
  </tr>
  <tr>
    <td align="center">이근희</td>
    <td align="center">조원</td>
    <th align="center">Security Onion log output</th>
  </tr>
  <tr>
    <td align="center">김문정</td>
    <td align="center">조원</td>
    <th align="center">Port scan Detection </th>
  </tr>
    <tr>
    <td align="center">조인철</td>
    <td align="center">조원</td>
    <th align="center">SSH Remote Control Attempts * Incoming packets with destination 127.0.0.1 Detection</th>
  </tr>
</table>

<br>

## ☝️ [파이썬 코드를 활용한 패킷 캡처 및 분석 시스템 개발](https://github.com/KIMJOONSIG/Reboot2/tree/main/Team%20Reboot's%20Network%20Tool/Network%20Packet%20Analysis%20System)
- 개요: 네트워크 패킷을 캡처하여 다양한 유형의 네트워크 공격을 탐지하는 기능을 제공합니다. 시스템은 파이썬을 기반으로 하며, 특히 네트워크에서 발생하는 다양한 유형의 악성 활동을 탐지하기 위한 여러 기능을 갖추고 있습니다.
- 주요 기능
  1. 패킷 캡처
     - 네트워크 트래픽을 실시간으로 캡처하여 분석합니다
  2. 패킷을 이용한 공격 탐지 목록
     - melicious domain
     - land attack
     - ARP spoofing
     - scaaner
     - ssh 연결
     - get post연결
     - 목적지가 127.0.0.1 탐지
     - directory listing
     - XSS
     - Command_injection
     - VPN
     - Network sniffing
-  Repository 구조
  
```bash
Network Packet Analysis System
│
├── code
│   └── reboot-all.py  # 주요 코드 파일
└──── malicious_domains.txt # 악성 도메인 목록

```

- 기능 구성
   <table>
        <tr>
              <th>Port Scanner Detect</th>
              <th>Packet Size and Speed</th>
        </tr>
        <tr>
          <td valign="top"><img src="https://github.com/KIMJOONSIG/Reboot2/assets/129662947/12c5c865-d2cb-4b01-8d32-adac88ecb5e5"></td>
          <td valign="top"><img src="https://github.com/KIMJOONSIG/Reboot2/assets/129662947/1e8bed00-4999-46ad-ac46-b79ded99ff48"></td>
        </tr>
        </table>
<br>


## ✌️ [지능형 위협 감지 및 알림 시스템](https://github.com/KIMJOONSIG/Reboot2/tree/main/Team%20Reboot's%20Network%20Tool/Telegram%20threat%20alarm%20system%20using%20T-pot)
- 개요: 최첨단 네트워크 보안 도구를 통해 위협을 실시간으로 모니터링하고 사용자에게 알림을 제공하는 포괄적인 솔루션입니다. T-POT와 Suricata를 기반으로 한 감지 엔진을 통해 다양한 위협 패턴을 탐지하며, 텔레그램 봇과의 통합을 통해 언제 어디서나 알림을 받을 수 있습니다. 이 시스템은 효율적인 네트워크 보안 관리를 도구로, 사용자가 위협에 신속하게 대응할 수 있게 도와줍니다.
- 주요 기능 :
  1. 실시간 위협 감지: T-POT와 Suricata를 통해 네트워크 트래픽을 지속적으로 모니터링하고, 의심스러운 활동이나 위협을 즉시 탐지.
  2. 텔레그램 봇 알림: 위협이 감지되면 사용자에게 텔레그램 봇을 통해 실시간 알림을 전송합니다. 사용자는 언제 어디서나 위협 알림을 확인할 수 있습니다.
  3. 맞춤형 룰셋 구성: 특정 조건 또는 위협 유형에 대한 알림을 받을 수 있습니다.
  4. 자세한 로그 정보: T-pot의 Elastick으로 시각화 된 자세한 로그 정보 확인 가능
- 환경 구성:
  - [T-pot 설치](https://github.com/telekom-security/tpotce) -> Telegram bot 만들기 -> [TT.py](https://github.com/KIMJOONSIG/Reboot2/blob/main/Team%20Reboot's%20Network%20Tool/Telegram%20threat%20alarm%20system%20using%20T-pot/TT.py)로 T-pot과 Telegram을 연결하여 나만의 실시간 위협 감지 시스템 구축
- Repository 구조
```bash
Telegram threat alarm system using T-pot
│
├── code
│   └── TT.py  # 주요 코드 파일
└──── suricata_rules # suricata_rules

```

- 기능 구성
  <table>
        <tr>
              <th>Telegram Bot</th>
              <th>Telegram log 전송</th>
                <th>Elastic을 이용한 로그 시각화</th>
        </tr>
  <tr>
    <td valign="top"><img src="https://github.com/KIMJOONSIG/BUSTAGO/assets/129662947/9b485721-8755-4cce-9201-a0efd1a4b395"></td>
    <td valign="top"><img src="https://github.com/KIMJOONSIG/BUSTAGO/assets/129662947/f72f8d9d-32ae-4cc5-9f71-df71217d5bae"></td>
    <td valign="top"><img src="https://github.com/KIMJOONSIG/BUSTAGO/assets/129662947/ce88c50f-16ea-4501-b4e7-d61f66e8fb5e"></td>
  </tr>
  </table>
<br>




