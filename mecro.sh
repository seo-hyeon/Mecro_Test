#!/bin/bash
echo "1234" | sudo -S your_command

# 필요한 패키지 설치
echo "필요한 패키지를 설치합니다..."
pip3 install scapy paramiko requests

# GitHub에서 파이썬 파일 다운로드
echo "파이썬 파일을 다운로드합니다..."
curl -O https://raw.githubusercontent.com/seo-hyeon/Mecro_Test/refs/heads/main/mecro.py

# mecro.py 실행
echo "mecro.py를 실행합니다..."
python3 mecro.py
