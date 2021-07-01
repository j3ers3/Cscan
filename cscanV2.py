#!/usr/bin/env python3
# encoding:utf8
import sys
import argparse
from socket import gethostbyname
from netaddr import IPNetwork
import requests
from time import time
import asyncio
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

__author__ = "nul1"
__update__ = "2021/07/01"
__version__ = "v2.1.1"
"""
C段扫描，指定web端口和非web端口，获取标题，版本信息
"""

Ports_web = [80, 88, 443, 7001, 8000, 8008, 8888, 8080, 8088, 8089, 8161, 9090]
# Ports_web = [8080,6443]
Ports_other = [21, 22, 445, 1100, 1433, 1434, 1521, 3306, 3389, 6379, 8009, 9200, 11211, 27017, 50070]

COUNT = 0
TIMEOUT_HTTP = 5
TIMEOUT_SOCK = 0.8
PATH = ''

user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36"

purp = '\033[95m'
blue = '\033[94m'
red = '\033[31m'
yellow = '\033[93m'
green = '\033[96m'
end = '\033[0m'


def banner():
    print(red + """
                        ..:::::::::..
                  ..:::aad88x8888baa:::..
              .::::d:?88888xxx888?::8b::::.
            .:::d8888:?888xxxxx??a888888b:::.
          .:::d8888888a8888xxxaa8888888888b:::.
         ::::dP::::::::88888x88888::::::::Yb::::
        ::::dP:::::::::Y888888888P:::::::::Yb::::
       ::::d8::::x::::::Y8888888P:::::x:::::8b::::
      .::::88::::::::::::Y88888P::::::::::::88::::.
      :::::Y8baaaaaaaaaa88P:T:Y88aaaaaaaaaad8P:::::
      :::::::Y88888888888P::|::Y88888888888P:::::::
      ::::::::::::::::888:::|:::888::::::::::::::::
      `:::::::::::::::8888888888888b::::::::::::::'
       :::::::::::::::88888888888888::::::::::::::
        :::::::::::::d88888888888888:::::::::::::
         ::::::::::::88::88::88:::88::::::::::::
          `::::::::::88::88::88:::88::::::::::'
            `::::::::88::88::P::::88::::::::'
              `::::::88::88:::::::88::::::'
                 ``:::::::::::::::::::''
                      ``:::::::::''""" + purp + """

    =================   WEB Info Scan  ==================
    =================   Code by {0}  ==================
    =================          {1}  ==================
    +++++++++++++++++++++++++++++++++++++++++++++++++++++
""".format(__author__, __version__) + end)


def save(save_file, content):
    with open(save_file, 'a') as f:
        try:
            f.writelines(content + '\n')
        except Exception as e:
            pass


def get_info(url, keyword):
    try:
        r = requests.get(url, headers={'UserAgent': user_agent}, timeout=TIMEOUT_HTTP, verify=False,
                         allow_redirects=True)

        soup = BeautifulSoup(r.content, "lxml")

        # HTTP头信息分析
        info_code = "[" + red + str(r.status_code) + end + "]"
        info_title = " [" + blue + soup.title.string.replace('\n', '').replace('\r', '').replace('\t',
                                                                                                 '') + end + "]" if soup.title else " []"
        info_len = " [" + purp + str(len(r.content)) + end + "]"
        if 'Server' in r.headers:
            info_server = " [" + yellow + r.headers['Server']
            info_server += " " + r.headers['X-Powered-By'] + end + "]" if 'X-Powered-By' in r.headers else "]"
        else:
            info_server = " []"

        result = info_code + info_title + info_server + info_len

        # HTTP内容，关键字匹配
        key = " [Found]" if keyword and keyword in r.text else ""

        return result + key

    except Exception as e:
        # print(e)
        return "[" + green + "open" + end + "]"


# 将域名转化为ip
def url_to_ip(url):
    domain = url.split('/')[0] if '://' not in url else url.split('//')[1].split('/')[0]
    domain = domain.split(':')[0] if ':' in domain else domain  # fix domain
    try:
        ip = gethostbyname(domain)
        return ip
    except Exception as e:
        return False


"""
先用异步网络请求判断端口是否存在，如果存在
    如果是web端口：
        获取http头信息
    非web端口：
        直接输出
"""


async def connet(ip, sem, keyword):
    global COUNT
    async with sem:
        for port in Ports:
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=TIMEOUT_SOCK)

                if writer:
                    # 对非web端口直接返回
                    if port in Ports_other:
                        url = str(ip) + ":" + str(port)
                        info = "[" + green + "open" + end + "]"

                    # 对web端口调用get_info()处理
                    else:
                        protocol = "http" if port not in [443, 8443] else "https"
                        url = "{0}://{1}:{2}{3}".format(protocol, ip, port, PATH)
                        info = get_info(url, keyword)

                    sys.stdout.write("%-28s %-30s\n" % (url, info))
                    COUNT += 1

            except Exception as e:
                # print(e)
                pass


async def connet2(url, sem):
    global COUNT
    # ToDo
    url = url + PATH
    async with sem:
        ip, info = url_to_ip(url), get_info(url)
        try:
            if ip:
                sys.stdout.write("%-28s %-28s %-30s\n" % (url, ip, info))
                COUNT += 1

        except Exception as e:
            # print(e)
            pass


async def scan(mode, x, t, keyword):
    time_start = time()

    # 加入信号量用于限制并发数
    sem = asyncio.Semaphore(t)

    tasks = []

    if mode == 'ips':
        ips = [str(ip) for ip in IPNetwork(x)]
        for ip in ips:
            tasks.append(asyncio.create_task(connet(ip, sem, keyword)))
        await asyncio.wait(tasks)

    '''
    文件格式支持ip、域名
    '''
    if mode == 'file':
        with open(x, 'r') as f:
            for line in f.readlines():
                line = line.rstrip()
                if len(line) != 0:
                    url = line if '://' in line else 'http://' + line
                    tasks.append(asyncio.create_task(connet2(url, sem)))

        await asyncio.wait(tasks)

    print(blue + "\nFound {0} in {1} seconds\n".format(COUNT, time() - time_start))


def main():
    global Ports, PATH

    parser = argparse.ArgumentParser(
        usage='\ncscan -i 192.168.0.1/24 -t 100\ncscan -f url.txt -t 100\ncscan -i 192.168.0.1/24 -t 100 -q -web -path /actuator',
        description="CScan V2",
    )

    parser.add_argument("-i", dest="ips",
                        help="Use ip segment (192.168.0.1/24)")
    parser.add_argument("-f", dest="file",
                        help="Use ip or domain file")
    parser.add_argument("-t", dest="threads", type=int, default=60,
                        help="Set thread (default 60)")
    # parser.add_argument("-o", dest="output",
    #                    help="Specify output file default output.txt")
    parser.add_argument("-q", dest="silent", action="store_true",
                        help="Silent mode")
    parser.add_argument("-web", dest="web", action="store_true",
                        help="Only scan web ports")
    parser.add_argument("-path", dest="path",
                        help="Request path (example '/phpinfo.php')")
    parser.add_argument("-k", dest="keyword", help="Specify keyword")

    args = parser.parse_args()

    Ports = Ports_web if args.web else Ports_web + Ports_other

    if args.silent is False:
        banner()

    if args.ips is None and args.file is None:
        print(red + "[x] cscan -h" + end)
        sys.exit(0)

    if args.path:
        PATH = args.path

    if args.ips:
        print(yellow + 'Target: ' + blue + args.ips + purp + ' | ' + yellow + 'Threads: ' + blue + str(
            args.threads) + end)
        print(yellow + 'Ports: ' + blue + str(Ports) + end + '\n')
        try:
            asyncio.run(scan('ips', args.ips, args.threads, args.keyword))
        except KeyboardInterrupt:
            print(red + "\nCTRL+C detected, Exit..." + end)

    if args.file:
        print(yellow + 'Target: ' + blue + args.file + purp + ' | ' + yellow + 'Threads: ' + blue + str(
            args.threads) + end + '\n')
        try:
            asyncio.run(scan('file', args.file, args.threads))
        except KeyboardInterrupt:
            print(red + "\nCTRL+C detected, Exit..." + end)


if __name__ == '__main__':
    main()
