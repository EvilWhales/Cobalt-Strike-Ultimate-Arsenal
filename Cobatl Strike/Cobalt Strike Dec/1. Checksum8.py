from colorama import init, Fore, Style

init(autoreset=True)  # 初始化自动重置颜色

def checksum8(text):
    if len(text) < 4:
        return 0
    text = text.replace("/", "")
    total = sum(ord(c) for c in text)
    return total % 256

def main():
    user_input = input("\n请输入要计算 checksum8 的字符串：")
    result = checksum8(user_input)

    print(f'\n字符串 "{Fore.CYAN}{user_input}{Style.RESET_ALL}" 的 checksum8 值为：'
          f'{Fore.CYAN}{Style.BRIGHT}{result}')

    # 判断是否符合规则
    if result in (92, 93):
        print(Fore.GREEN + Style.BRIGHT + "\n符合 checksum8 规则 ✔")
    else:
        print(Fore.RED + Style.BRIGHT + "\n不符合 checksum8 规则 ❌")

if __name__ == "__main__":
    main()
