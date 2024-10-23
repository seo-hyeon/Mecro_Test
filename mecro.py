from scapy.all import ARP, Ether, srp
import paramiko
import socket
import ipaddress
import json
import requests

# def generate_private_ips():
#     private_ips = []

#     network = ipaddress.ip_network('172.16.0.0/12')
#     # 모든 IP 주소 출력
#     for ip in network:
#         private_ips.append(str(ip))

#     return private_ips

def send_to_discord(content):
    print("전송 시작")
    webhook_url = "https://discord.com/api/webhooks/1297527399268876288/DcPDYJNPM6mvV8iQ879HfBo5r8B1qdpIAy2AlZAUwCzgSvKD1XHldCWHjP5YuEYKQgWO" 
    headers = {
        "Content-Type": "application/json"
    } 
    data = {
        "content": content
    }
    requests.post(webhook_url, json=data, headers=headers)

def scan_network(ip):
    print(ip)
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def check_ssh(ip):
    port = 22
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)  # 2초 대기
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def ssh_connect(ip):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip)
        print(f"Successfully connected to {ip}")
        client.close()
    except Exception as e:
        print(f"Failed to connect to {ip}: {e}")

if __name__ == "__main__":
    # all_private_ips = generate_private_ips()
    all_private_ips = ['172.20.21.192/26']
    all_devices = []
    log_lines = ""

    print("활성 장비 스캔 중...")
    for ip in all_private_ips:
        devices = scan_network(ip)
        print(devices)
        all_devices.extend(devices)

    print("\n활성 장비 목록:")
    for device in all_devices:
        try:
            log_lines += f"\nIP: {device['ip']}, MAC: {device['mac']}\n"
            
            if check_ssh(device['ip']):
                ssh_status = f"SSH 포트가 열려있습니다: {device['ip']}. SSH 접속 시도 중..."
                log_lines += "\n" + ssh_status
                ssh_connect(device['ip'])
            else:
                ssh_status = f"SSH 포트가 닫혀있습니다: {device['ip']}"
                log_lines += "\n" + ssh_status
        except:
            continue
    
    send_to_discord(log_lines)
