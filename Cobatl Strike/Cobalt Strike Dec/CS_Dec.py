import os
import json
import subprocess
from colorama import init, Fore, Style

def run_cmd(cmd_list):
    """安全执行命令"""
    try:
        subprocess.run(cmd_list, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR]{Style.RESET_ALL} 命令执行失败：{e}")
    except Exception as e:
        print(f"{Fore.RED}{Style.BRIGHT}[ERROR]{Style.RESET_ALL} 错误：{e}")

def load_keys():
    """读取 keys.json 中 AES/HMAC 密钥"""
    if not os.path.exists("keys.json"):
        return None, None

    try:
        with open("keys.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("AES_Key_Hex"), data.get("HMAC_Key_Hex")
    except:
        return None, None

def check_beacon_keys_file():
    """检查 .cobaltstrike.beacon_keys 是否存在"""
    return os.path.exists(".cobaltstrike.beacon_keys")

def check_hex_file():
    """检查 hex.txt 是否存在"""
    return os.path.exists("hex.txt")

def main_menu():
    init(autoreset=True)
    
    while True:
        print(Fore.WHITE + Style.BRIGHT + "\n====== 主菜单 ======")
        print(Fore.WHITE + Style.BRIGHT + "1. Checksum8 规则检查")
        print(Fore.WHITE + Style.BRIGHT + "2. 解析 Beacon 程序配置")
        print(Fore.WHITE + Style.BRIGHT + "3. 解密 Beacon 元数据")
        print(Fore.WHITE + Style.BRIGHT + "4. 解密 C2 服务器下发的任务")
        print(Fore.WHITE + Style.BRIGHT + "5. 解密受控端返回的结果")
        print(Fore.WHITE + Style.BRIGHT + "6. 提取当前目录 .cobaltstrike.beacon_keys 文件公私钥")
        print(Fore.WHITE + Style.BRIGHT + "q. 退出程序")
        print(Fore.WHITE + Style.BRIGHT + "====================")

        choice = input("请输入操作编号：").strip().lower()

        # --------------------------------------------------------------
        # 1. checksum8
        # --------------------------------------------------------------
        if choice == "1":
            print(Fore.BLUE + Style.BRIGHT + "\n======= TIPS =======")
            print(Fore.BLUE + Style.BRIGHT + "介绍：受控端运行后门程序后会主动向 C2 服务器发起请求，其 URI 符合 Checksum8 规则。")
            print(Fore.BLUE + Style.BRIGHT + "操作：请在下方直接输入该 URI，例如：/cRRV。")
            print(Fore.BLUE + Style.BRIGHT + "====================")
            
            run_cmd(["python", "1. Checksum8.py"])
            continue

        # --------------------------------------------------------------
        # 2. 解析 Beacon 程序配置
        # --------------------------------------------------------------
        elif choice == "2":
            print(Fore.BLUE + Style.BRIGHT + "\n======= TIPS =======")
            print(Fore.BLUE + Style.BRIGHT + "介绍：")
            print(Fore.BLUE + Style.BRIGHT + '  · 受控端在运行后门程序后，C2 服务器会返回完整的 Stager Beacon 文件。')
            print(Fore.BLUE + Style.BRIGHT + '  · 本脚本用于解析该文件，以获取 Beacon 配置（如 RSA 公钥、C2 监听端口、回调 URI 等信息）。')
            
            print(Fore.BLUE + Style.BRIGHT + '\n操作：')
            print(Fore.BLUE + Style.BRIGHT + '  1. 请在 Wireshark 中将对应的数据包导出为原始数据（“显示为 → 原始数据”），并保存为 out.vir；')
            print(Fore.BLUE + Style.BRIGHT + '  2. 随后在下方输入该文件的路径。')
            print(Fore.BLUE + Style.BRIGHT + "====================\n")
            
            filename = input(".vir 文件存储路径（默认当前目录下的 out.vir）：").strip()
            if filename == "":
                filename = "out.vir"
            run_cmd(["python", "2. 1768.py", filename])
            continue

        # --------------------------------------------------------------
        # 3. 解密 Beacon 元数据
        # --------------------------------------------------------------
        elif choice == "3":
            print(Fore.BLUE + Style.BRIGHT + "\n======= TIPS =======")
            print(Fore.BLUE + Style.BRIGHT + "介绍：")
            print(Fore.BLUE + Style.BRIGHT + '  · 受控端会按照设定的心跳周期向 C2 服务器发送请求，其 Beacon 元数据（如 Beacon 生成的 AES 密钥、受控端信息等）')
            print(Fore.BLUE + Style.BRIGHT + '    会使用 C2 的 RSA 公钥加密，并置于 Cookie 字段中，再经过 Base64 编码。')
            print(Fore.BLUE + Style.BRIGHT + '  · 本脚本用于解密该 Cookie 中的密文。')
            
            print(Fore.BLUE + Style.BRIGHT + '\n操作：')
            print(Fore.BLUE + Style.BRIGHT + '  1. 请先获取 RSA 私钥！将 C2 服务器中的 .cobaltstrike.beacon_keys 文件复制到当前目录，或手动输入十六进制的 RSA 私钥；')
            print(Fore.BLUE + Style.BRIGHT + '  2. 根据提示输入待解密的 Cookie 密文。')
            print(Fore.BLUE + Style.BRIGHT + "====================")
            
            print(Fore.WHITE + Style.BRIGHT + "\n1. 使用当前目录的 .cobaltstrike.beacon_keys 文件（自动提取 RSA 私钥）")
            print(Fore.WHITE + Style.BRIGHT + "2. 手动输入 RSA 私钥（Hex）")
            mode = input("请选择方式（默认 1）：").strip()

            if mode == "" or mode == "1":
                if not check_beacon_keys_file():
                    print(Fore.WHITE + Style.BRIGHT + "❌ 当前目录未找到 .cobaltstrike.beacon_keys！")
                    continue

                metadata_b64 = input("请输入需要解密的 Beacon 元数据（Base64 编码）：").strip()

                run_cmd([
                    "python", "3. CS_Decrypt_Metadata.py",
                    "-f", ".cobaltstrike.beacon_keys",
                    metadata_b64
                ])
                continue

            elif mode == "2":
                rsa_hex = input("请输入十六进制 RSA 私钥：").strip()
                metadata_b64 = input("请输入 Beacon 元数据密文（Base64 编码）：").strip()

                run_cmd([
                    "python", "3. CS_Decrypt_Metadata.py",
                    "-p", rsa_hex,
                    metadata_b64
                ])
                continue

            else:
                print(Fore.WHITE + Style.BRIGHT + "❌ 无效选项")
                continue

        # --------------------------------------------------------------
        # 4. 解密 C2 下发任务
        # --------------------------------------------------------------
        elif choice == "4":
            print(Fore.BLUE + Style.BRIGHT + "\n======= TIPS =======")
            print(Fore.BLUE + Style.BRIGHT + "介绍：")
            print(Fore.BLUE + Style.BRIGHT + '  · C2 服务器会将下发的操作指令经过 AES 加密后，置于受控端心跳包的响应数据中。')
            print(Fore.BLUE + Style.BRIGHT + '  · 本脚本用于对心跳包响应密文进行解密。')
            
            print(Fore.BLUE + Style.BRIGHT + '\n操作：')
            print(Fore.BLUE + Style.BRIGHT + '  1. 请先获取 AES 与 HMAC 密钥！执行第 3 步自动提取，或在当前目录的 keys.json 中手动填写对应的十六进制密钥；')
            print(Fore.BLUE + Style.BRIGHT + '  2. 按提示输入心跳响应的原始 Hex 数据。若数据较长，可将其复制到当前目录下的 hex.txt 文件中。')
            print(Fore.BLUE + Style.BRIGHT + "====================")
            
            aes, hmac = load_keys()
            if not aes or not hmac:
                print(Fore.WHITE + Style.BRIGHT + "❌ 请先执行第 3 步获取 AES/HMAC 密钥，或手动补充 keys.json")
                continue

            print(Fore.WHITE + Style.BRIGHT + "\n1. 手动输入心跳响应的原始 Hex 数据流")
            print(Fore.WHITE + Style.BRIGHT + "2. 存储 Hex 数据流的文件")
            mode = input("请选择方式（默认 1）：").strip()
            
            if mode == "" or mode == "1":
                hex_stream = input("请输入响应中 C2 服务器下发任务的 Hex 数据流：").strip()
                run_cmd([
                    "python", "4. CS_Task_AES_Decrypt.py",
                    "-A", aes,
                    "-H", hmac,
                    "-S", hex_stream
                ])
                continue

            elif mode == "2":
                filename = input("请输入要分析的文件路径（默认当前目录下的 hex.txt）：").strip()
                if filename == "":
                    if not check_hex_file():
                        print(Fore.WHITE + Style.BRIGHT + "❌ 当前目录未找到 hex.txt！")
                        continue
                    filename = "hex.txt"
                
                run_cmd([
                    "python", "4. CS_Task_AES_Decrypt.py",
                    "-A", aes,
                    "-H", hmac,
                    "-F", filename
                ])
                continue

            else:
                print(Fore.WHITE + Style.BRIGHT + "❌ 无效选项")
                continue

        # --------------------------------------------------------------
        # 5. 解密受控端返回的结果
        # --------------------------------------------------------------
        elif choice == "5":
            print(Fore.BLUE + Style.BRIGHT + "\n======= TIPS =======")
            print(Fore.BLUE + Style.BRIGHT + "介绍：")
            print(Fore.BLUE + Style.BRIGHT + '  · 受控端在执行完任务后，会将结果数据经 AES 加密后放入回调包 POST 请求体中。')
            print(Fore.BLUE + Style.BRIGHT + '  · 本脚本用于解密回调包中携带的密文数据。')
            
            print(Fore.BLUE + Style.BRIGHT + '\n操作：')
            print(Fore.BLUE + Style.BRIGHT + '  1. 请先获取 AES 与 HMAC 密钥！执行第 3 步自动提取，或在当前目录的 keys.json 中手动填写对应的十六进制密钥；')
            print(Fore.BLUE + Style.BRIGHT + '  2. 根据提示输入回调包请求体的原始 Hex 数据。若数据较长，可将其复制到当前目录下的 hex.txt 文件中。')
            print(Fore.BLUE + Style.BRIGHT + "====================")
            
            aes, hmac = load_keys()
            if not aes or not hmac:
                print(Fore.WHITE + Style.BRIGHT + "❌ 请先执行第 3 步获取 AES/HMAC 密钥，或手动补充 keys.json")
                continue

            print(Fore.WHITE + Style.BRIGHT + "\n1. 手动输入 Hex 数据流")
            print(Fore.WHITE + Style.BRIGHT + "2. 存储 Hex 数据流的文件")
            mode = input("请选择方式（默认 1）：").strip()

            if mode == "" or mode == "1":
                hex_stream = input("请输入受控端返回的 Hex 数据流：").strip()
                run_cmd([
                    "python", "5. Beacon_Task_return_AES_Decrypt.py",
                    "-A", aes,
                    "-H", hmac,
                    "-S", hex_stream
                ])
                continue
            
            elif mode == "2":
                filename = input("请输入要分析的文件路径（默认当前目录下的 hex.txt）：").strip()
                if filename == "":
                    if not check_hex_file():
                        print(Fore.WHITE + Style.BRIGHT + "❌ 当前目录未找到 hex.txt！")
                        continue
                    filename = "hex.txt"

                run_cmd([
                    "python", "5. Beacon_Task_return_AES_Decrypt.py",
                    "-A", aes,
                    "-H", hmac,
                    "-F", filename
                ])
                continue

            else:
                print(Fore.WHITE + Style.BRIGHT + "❌ 无效选项")
                continue
            
        # --------------------------------------------------------------
        # 6. 提取公私钥
        # --------------------------------------------------------------
        elif choice == "6":
            if not check_beacon_keys_file():
                print(Fore.WHITE + Style.BRIGHT + "❌ 当前目录不存在 .cobaltstrike.beacon_keys")
                continue

            run_cmd(["python", "6. CS_Decrypt_RSA_Keys.py"])
            continue

        # --------------------------------------------------------------
        # q. 退出
        # --------------------------------------------------------------
        elif choice == "q":
            print("退出程序。")
            break

        else:
            print(Fore.WHITE + Style.BRIGHT + "❌ 无效输入，请重新选择。")



if __name__ == "__main__":
    main_menu()
