#!/usr/bin/env python3
"""
CobaltStrike Task Decrypt
使用方式:
    Beacon_Task_return_AES_Decrypt -A <AES密钥hex> -H <HMAC密钥hex> -S <Hex任务数据>
    
    Beacon_Task_return_AES_Decrypt -A <AES密钥hex> -H <HMAC密钥hex> -F <Hex任务数据文件>
"""

import argparse
import binascii
import struct
import hmac
from Crypto.Cipher import AES
import hexdump
from colorama import init, Fore, Style


def compare_mac(mac, mac_verif):
    """Constant-time HMAC compare"""
    if len(mac) != len(mac_verif):
        return False
    r = 0
    for a, b in zip(mac, mac_verif):
        r |= a ^ b
    return r == 0


def decrypt_block(ciphertext, signature, aes_key, hmac_key):
    """Decrypt one CS block"""
    # HMAC check
    calc_mac = hmac.new(hmac_key, ciphertext, digestmod="sha256").digest()[:16]
    if not compare_mac(calc_mac, signature):
        print(Fore.WHITE + Style.BRIGHT + "❌ HMAC 校验失败!")
        return None

    iv = b"abcdefghijklmnop"
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def main():
    init(autoreset=True)  # 初始化颜色
    
    parser = argparse.ArgumentParser(description="CS 多段 HEX 数据解析器")

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
        aes_key = binascii.unhexlify(args.aeskey)
        hmac_key = binascii.unhexlify(args.hmackey)
    except:
        print(Fore.WHITE + Style.BRIGHT + "❌ AES/HMAC 密钥必须是 Hex 格式")
        return

    # 处理 HEX 数据来源：命令行 或 文件
    if args.session:
        hex_data = args.session.strip()
    else:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                hex_data = f.read().strip()
        except:
            print(Fore.WHITE + Style.BRIGHT + f"❌ 读取文件失败: {args.file}")
            return

    # 确保输入是 HEX
    try:
        buf = binascii.unhexlify(hex_data)
    except Exception as e:
        print(Fore.WHITE + Style.BRIGHT + "❌ 输入内容必须是 Hex 格式")
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR]{Style.RESET_ALL} 错误：", e)
        return

    pos = 0
    block_index = 1

    while pos < len(buf):

        # 不足 4 字节，就结束
        if pos + 4 > len(buf):
            break

        # 读取长度字段
        block_len = struct.unpack(">I", buf[pos:pos + 4])[0]
        pos += 4

        print(Fore.YELLOW + Style.NORMAL + f"\n==============================")
        print(Fore.YELLOW + Style.NORMAL + f"解析第 {block_index} 段：总长度 = {block_len} 字节")
        print(Fore.YELLOW + Style.NORMAL + "------------------------------")

        # 检查是否越界
        if pos + block_len > len(buf):
            print("长度越界，停止解析")
            break

        block = buf[pos:pos + block_len]
        pos += block_len

        # 后 16 bytes = signature
        signature = block[-16:]
        ciphertext = block[:-16]

        print(f"密文（{len(ciphertext)} 字节）: {ciphertext.hex()}")
        print(f"签名（16 字节）: {signature.hex()}")

        # 解密
        dec = decrypt_block(ciphertext, signature, aes_key, hmac_key)
        if dec is None:
            print("解密失败")
            block_index += 1
            continue
            
            
        result_len = int.from_bytes(dec[4:8], "big")
        result = dec[8:8 + result_len]
        
        print("\n解密结果（Hexdump）：")
        hexdump.hexdump(dec)

        print("\n受控端返回结果(GBK 解码):")
        try:
            print(Fore.CYAN + Style.BRIGHT + result.decode("gbk", errors="ignore"))
        except:
            print("无法 GBK 解码")

        block_index += 1


if __name__ == "__main__":
    main()
