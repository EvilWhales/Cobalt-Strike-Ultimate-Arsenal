#!/usr/bin/env python3
"""
CobaltStrike Task Decrypt
使用方式:
    CS_Task_AES_Decrypt.py -A <AES密钥hex> -H <HMAC密钥hex> -S <Hex任务数据>
    
    CS_Task_AES_Decrypt.py -A <AES密钥hex> -H <HMAC密钥hex> -F <Hex任务数据文件>
"""

import argparse
import hmac
import binascii
import base64
import struct
import hexdump
from Crypto.Cipher import AES
from colorama import init, Fore, Style


# ---------------------------------------------------------------------
# HMAC 签名校验
# ---------------------------------------------------------------------
def compare_mac(mac, mac_verif):
    if mac == mac_verif:
        return True
    if len(mac) != len(mac_verif):
        print("invalid MAC size")
        return False

    result = 0
    for x, y in zip(mac, mac_verif):
        result |= x ^ y
    return result == 0


# ---------------------------------------------------------------------
# AES-CBC 解密
# ---------------------------------------------------------------------
def decrypt(encrypted_data, iv_bytes, signature, aes_key, hmac_key):
    mac_local = hmac.new(hmac_key, encrypted_data, digestmod="sha256").digest()[:16]

    if not compare_mac(mac_local, signature):
        print(Fore.WHITE + Style.BRIGHT + "❌ HMAC 校验失败!")
        return None

    cipher = AES.new(aes_key, AES.MODE_CBC, iv_bytes)
    return cipher.decrypt(encrypted_data)


# ---------------------------------------------------------------------
# 大端读取 4 字节整数
# ---------------------------------------------------------------------
def readInt(buf):
    return struct.unpack(">L", buf[0:4])[0]


# ---------------------------------------------------------------------
# 主逻辑
# ---------------------------------------------------------------------
def main():
    init(autoreset=True)
    
    parser = argparse.ArgumentParser(description="Beacon 元数据解析器")

    parser.add_argument("-A", "--aeskey", required=True,
                        help="AES 密钥（Hex 形式）")
    parser.add_argument("-H", "--hmackey", required=True,
                        help="HMAC 密钥（Hex 形式）")

    # -S 和 -F只能二选一
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-S", "--session", help="完整 HEX 数据流")
    group.add_argument("-F", "--file", help="从文件读取 HEX 数据流")

    args = parser.parse_args()

    # 解析密钥
    try:
        AES_KEY = binascii.unhexlify(args.aeskey)
        HMAC_KEY   = binascii.unhexlify(args.hmackey)
    except:
        print(Fore.WHITE + Style.BRIGHT + "❌ AES/HMAC 密钥必须是 Hex 格式")
        return

    # -----------------------------------------------------------------
    # 解析 Hex 的任务数据
    # -----------------------------------------------------------------
    
    # 处理 HEX 数据来源：命令行 或 文件
    if args.session:
        hex_data = args.session.strip().replace(" ", "").replace("\n", "")
    else:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                hex_data = f.read().strip()
        except:
            print(Fore.WHITE + Style.BRIGHT + f"❌ 读取文件失败: {args.file}")
            return
    
    try:
        enc_data = binascii.unhexlify(hex_data)
    except Exception as e:
        print(Fore.WHITE + Style.BRIGHT + "❌ 输入内容必须是 Hex 格式")
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR]{Style.RESET_ALL} 错误：", e)
        return

    print(Fore.YELLOW + Style.NORMAL + "\n开始解析数据包：")
    print("数据包总长度: {} bytes".format(len(enc_data)))

    # 尾 16 字节 = HMAC 截断
    if len(enc_data) < 16:
        print(Fore.WHITE + Style.BRIGHT + "❌ 数据过短，不包含 HMAC")
        return

    signature = enc_data[-16:]
    encrypted_data = enc_data[:-16]

    # 默认 CobaltStrike IV
    iv_bytes = b"abcdefghijklmnop"

    # 解密
    dec = decrypt(encrypted_data, iv_bytes, signature, AES_KEY, HMAC_KEY)
    if dec is None:
        return

    # 解析头部
    counter = readInt(dec)
    decrypted_len = readInt(dec[4:])

    print("时间戳 / Counter: {}".format(counter))
    print("任务数据包长度: {}".format(decrypted_len))

    data = dec[8:]
    print("数据包内容（Hexdump）：")
    hexdump.hexdump(data)

    # ======= 循环解析多个 Task =======
    offset = 0
    task_index = 1

    while offset + 8 <= len(data):
        Task_Sign = data[offset:offset+4]
        Task_len  = int.from_bytes(data[offset+4:offset+8], "big")

        print(Fore.YELLOW + Style.NORMAL + "\n---- Task #{} ----".format(task_index))
        print("任务类型: 0x{}".format(Task_Sign.hex()))
        print("任务正文长度: {}".format(Task_len))

        # 越界检查
        if offset + 8 + Task_len > len(data):
            print(Fore.WHITE + Style.BRIGHT + "❌ 任务长度越界，停止解析。")
            break

        Task_body = data[offset+8:offset+8+Task_len]

        # 保存任务
        fname = f"./task/task_{task_index}.bin"
        with open(fname, "wb") as f:
            f.write(Task_body)

        print("任务正文已保存到 {} ✔".format(fname))
        print("任务内容（Hexdump）：")
        hexdump.hexdump(Task_body)

        # 下一个任务
        offset += (8 + Task_len)
        task_index += 1

    # 剩余未解析
    if offset < len(data):
        print(Fore.YELLOW + Style.NORMAL + "\n未解析的剩余数据：")
        hexdump.hexdump(data[offset:])


if __name__ == "__main__":
    main()
