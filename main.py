import ipaddress
import os
import subprocess
import json
import re
import time

import requests


def is_reportable_address(ip_str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        # プライベートIPアドレスならfalse
        if ip.is_private:
            return False
        else:
            return True
    except ValueError:
        # 不正なIPアドレス形式の場合はFalseを返す
        return False


# journalctlコマンドを実行して出力を取得
command = 'journalctl -xe -o json --grep "UFW BLOCK" --no-pager _TRANSPORT=kernel --since "3 minute ago"'
output = subprocess.check_output(command, shell=True, text=True)


# SRCとDPTを格納する辞書
src_and_dpt = {}

# JSONをパースしてSRCとDPTを抽出し、辞書に格納
for line in output.strip().split('\n'):
    try:
        data = json.loads(line)
        if "MESSAGE" in data:
            message = data["MESSAGE"]
            match_src = re.search(r"SRC=([0-9.]+)", message)
            match_dpt = re.search(r"DPT=(\d+)", message)
            if match_src and match_dpt:
                src_ip = match_src.group(1)
                dpt_port = int(match_dpt.group(1))
                # SRCが辞書に存在する場合、DPTのリストに追加
                if src_ip in src_and_dpt:
                    src_and_dpt[src_ip].append(dpt_port)
                else:
                    # SRCが辞書に存在しない場合、新しいエントリを作成
                    src_and_dpt[src_ip] = [dpt_port]
    except:
        pass


# 結果を出力
for ip, dport in src_and_dpt.items():
    print(ip)
    if is_reportable_address(ip):
        print("Reporting! ;)")
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        url = "https://api.abuseipdb.com/api/v2/report"
        categories = "14,18"
        comment = f"Port scanning ({ip} -> :{dport})"

        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

        params = {
            "ip": ip,
            "categories": categories,
            "comment": comment
        }

        response = requests.post(url, params=params, headers=headers)

        print(response.status_code)
        if response.status_code == 429:
            print("Skipped")
            time.sleep(2)
        elif response.status_code != 200:
            raise Exception
        else:
            time.sleep(2)

