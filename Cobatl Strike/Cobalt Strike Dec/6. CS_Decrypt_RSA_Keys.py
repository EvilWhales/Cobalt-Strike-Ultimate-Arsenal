import base64
import javaobj.v2 as javaobj
from colorama import init, Fore, Style
import json
import os
import sys

init(autoreset=True)  # 初始化自动重置颜色

filename = ".cobaltstrike.beacon_keys"
# 检测文件是否存在
if not os.path.exists(filename):
    print(f"{Fore.RED}{Style.BRIGHT}[ERROR]{Style.RESET_ALL} 未找到 {Fore.CYAN}{Style.BRIGHT}{filename}{Style.RESET_ALL} 文件，请确认当前目录是否包含该文件！")
    sys.exit(1)   # 退出程序，返回错误码 1

# 读取并解析 Java 序列化对象
with open(filename, "rb") as fd:
    pobj = javaobj.load(fd)

def format_key(key_data, key_type):
    """
    输出到终端使用 PEM 格式
    """
    key_data = bytes(map(lambda x: x & 0xFF, key_data))
    formatted_key = f"-----BEGIN {key_type} KEY-----\n"
    formatted_key += base64.encodebytes(key_data).decode()
    formatted_key += f"-----END {key_type} KEY-----"
    return formatted_key, key_data  # 同时返回 PEM 和原始 bytes


# ------- 1) 生成 PEM 和原始 bytes -------
private_pem, private_bytes = format_key(
    pobj.array.value.privateKey.encoded.data, "PRIVATE"
)
public_pem, public_bytes = format_key(
    pobj.array.value.publicKey.encoded.data, "PUBLIC"
)

# ------- 2) 保存十六进制到 JSON -------
data = {
    "Private_Key_Hex": private_bytes.hex(),
    "Public_Key_Hex": public_bytes.hex()
}

json_path = "keys.json"

# 如果文件存在，读取并更新；不存在则创建新字典
if os.path.isfile(json_path):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            existing = json.load(f)
    except (json.JSONDecodeError, ValueError):
        existing = {}  # 文件损坏时重建
else:
    existing = {}  # 文件不存在 → 创建新的

# 更新或追加字段
for k, v in data.items():
    existing[k] = v

# 写回 JSON（保持其它字段不变）
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(existing, f, indent=4, ensure_ascii=False)

# ------- 3) 终端打印 -------
print("\n" + Fore.RED + Style.BRIGHT + private_pem)
print("\n" + Fore.CYAN + Style.BRIGHT + public_pem)
print(Fore.GREEN + Style.BRIGHT + "\n已保存十六进制密钥到 ./keys.json ✔")
