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

__author__ = "whois"
__update__ = "2020/06/07"
__version__ = "v2.0.1"
"""
C段扫描，指定web端口和非web端口，获取标题，版本信息

"""

Ports_web = [80, 88, 7001, 8009, 8080, 8443]
# Ports_web = [80, 81, 82, 88, 89, 443, 5000, 5001, 7001, 7070, 7777, 7788, 8000, 8001, 8002, 8008, 8080, 8081, 8088, 8089, 8090, 8443, 8888, 8899]

Ports_other = [445, 1433, 1434, 1521, 3306, 3389]

Ports = Ports_other + Ports_web

count = 0

user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36"

purp = '\033[95m'
blue = '\033[94m'
red = '\033[31m'
yellow = '\033[93m'
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
                      ``:::::::::''""" + yellow + """

    =================   WEB Info Scan  ==================
    =================   Code by {0}  ==================
    =================          {1}  ==================
    +++++++++++++++++++++++++++++++++++++++++++++++++++++
                      
""".format(__author__, __version__) + end)


def get_info(url):
    try:
        r = requests.get(url, headers={'UserAgent': user_agent}, timeout=6, verify=False, allow_redirects=True)
        
        soup = BeautifulSoup(r.content, "lxml")

        info = "[" + red + str(r.status_code) + end + "] " 

        info += blue + soup.title.string.replace('\n', '').replace('\r', '').replace('\t', '') + end if soup.title else "No title"

        if 'Server' in r.headers:
            info += " " + yellow + r.headers['Server'] + end
        if 'X-Powered-By' in r.headers:
            info += " " + purp + r.headers['X-Powered-By'] + end

        return info
    except Exception as e:
        print(e)
        pass


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
先判断端口是否存在，如果存在
    端口为80，协议http，如果端口443，协议https
如果不存在
    继续
"""
async def connet(ip, sem):
    global count

    async with sem:
        for port in Ports:
            #print(port)
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1)

                if writer:
                    # 非web端口
                    if port in Ports_other:
                        url = str(ip) + ":" + str(port)
                        info = blue + "open" + end

                    # web端口
                    else:
                        if port in [443]:
                            protocol = "https"
                        else:
                            protocol = "http"
                        url = "{0}://{1}:{2}".format(protocol, ip, port)

                        info = get_info(url)

                    sys.stdout.write("%-28s %-30s\n" % (url, info))

                    count += 1

            except Exception as e:
                #print(e)
                pass
            

async def connet2(url, sem):
    global count

    async with sem:
        ip, info = url_to_ip(url), get_info(url)
        try:
            if ip:
                sys.stdout.write("%-28s %-28s %-28s\n" % (url, ip, info))
                count += 1

        except Exception as e:
            # print(e)
            pass


async def scan(mode, x, t):
    time_start = time()

    # 加入信号量用于限制并发数
    sem = asyncio.Semaphore(t)

    tasks = []

    if mode == 'ips':
        ips = [str(ip) for ip in IPNetwork(x)]
        for ip in ips:
            tasks.append(asyncio.create_task(connet(ip, sem)))
        await asyncio.wait(tasks)

    '''
    文件格式支持ip、域名
    1.1.1.1:80
    baidu.com:443
    http:/1.1.1.1
    http://www.baidu.com
    '''
    if mode == 'file':
        with open(x, 'r') as f:
            for line in f.readlines():
                line = line.rstrip()
                if len(line) != 0:
                    url = line if '://' in line else 'http://' + line
                    tasks.append(asyncio.create_task(connet2(url, sem)))
                    
        await asyncio.wait(tasks)

    print(blue + "\nFound {0} in {1} seconds\n".format(count, time() - time_start))



def main():
    banner()

    parser = argparse.ArgumentParser(
        usage='\ncscan -i 192.168.0.1/24 -t 100\ncscan -f url.txt -t 100',
        description="CScan V2",
    )

    parser.add_argument("-i", dest="ips",
                        help="Use ip segment (192.168.0.1/24)")
    parser.add_argument("-f", dest="file",
                        help="Use ip or domain file")
    parser.add_argument("-t", dest="threads", type=int, default=60,
                        help="Set thread (default 60)")
    parser.add_argument("-o", dest="save",
                        help="save")

    args = parser.parse_args()

    if args.ips is None and args.file is None:
        print(red + "[x] cscan -h" + end)
        exit(0)

    if args.ips:
        asyncio.run(scan('ips', args.ips, args.threads))
        
    if args.file:
        asyncio.run(scan('file', args.file, args.threads))


if __name__ == '__main__':
    main()
