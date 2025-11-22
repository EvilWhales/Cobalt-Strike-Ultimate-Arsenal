# encoding:utf-8
import argparse
import time
from dingtalkchatbot.chatbot import DingtalkChatbot

parser = argparse.ArgumentParser(description='Beacon Info')
parser.add_argument('--computername')
parser.add_argument('--internalip')
parser.add_argument('--externalip')
parser.add_argument('--username')
args = parser.parse_args()

internalip = args.internalip
externalip = args.externalip
computername = args.computername
username = args.username

content = f"""## <font color=Red>CobaltStrike 上线提醒</font>\n
**主机名: {computername}**\n
**内网IP: {internalip}**\n
**回连IP: {externalip}**\n
**用户名: {username}**\n
**上线时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}**\n
"""

webhook = 'https://oapi.dingtalk.com/robot/send?access_token=xxx' // TODO 进行替换

xiaoding = DingtalkChatbot(webhook)
xiaoding.send_markdown(title="CS上线", text=content)
