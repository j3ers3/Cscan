#!/usr/bin/env python3
# encoding:utf8
import sys
import argparse
import socket
import ipaddr
import requests
from time import time
from threading import Thread
from bs4 import BeautifulSoup

if sys.version_info.major == 2:
    from Queue import Queue
else:
    from queue import Queue

requests.packages.urllib3.disable_warnings()

__author__ = "whois"
__update__ = "2019/06/30"
"""
C段web扫描，选取几个web端口，获取标题，版本信息

ToDo
    通过bing接口反查域名
    加入路径扫描
    归纳ip和端口
    多线程优化
"""

Ports_web = [80, 88, 7001, 8000, 8009, 8888, 8080, 8443]
# Ports_web = [80, 81, 82, 88, 89, 443, 5000, 5001, 7001, 7070, 7777, 7788, 8000, 8001, 8002, 8008, 8080, 8081, 8088, 8089, 8090, 8443, 8888, 8899]

# Ports_other = []
Ports_other = [21, 22, 445, 1433, 1434, 1521, 3306, 3389, 6379]

Ports = Ports_other + Ports_web

Threads = 45
count = 0

user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.73 Safari/537.36"

purp = '\033[95m'
blue = '\033[94m'
red = '\033[31m'
yellow = '\033[93m'
end = '\033[0m'

queue = Queue()


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
    =================   Code by whois  ==================
    =================          v1.2    ==================
    +++++++++++++++++++++++++++++++++++++++++++++++++++++
                      
""" + end)


def get_info(url):
    try:
        # 页面的跳转没解决
        r = requests.get(url, headers={'UserAgent': user_agent}, timeout=6, verify=False, allow_redirects=True)
        # pip install lxml
        soup = BeautifulSoup(r.content, 'lxml')

        info = blue + soup.title.string + end if soup.title else "No title"

        if 'Server' in r.headers:
            info += "\t" + yellow + r.headers['Server'] + end
        if 'X-Powered-By' in r.headers:
            info += "\t" + purp + r.headers['X-Powered-By'] + end

        return info
    except Exception as e:
        pass


def get_ip(url):
    domain = url.split('/')[0] if '://' not in url else url.split('//')[1].split('/')[0]
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return False


def do_cscan(ip):
    global count
    for port in Ports:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.settimeout(0.6)
            s.connect((str(ip), port))

            if port in Ports_other:
                url = str(ip) + ":" + str(port)
                info = blue + "open" + end

            else:
                protocol = "http" if port not in [443, 8443] else "https"
                url = "{0}://{1}:{2}".format(protocol, ip, port)

                url = "{protocol}://{ip}:{port}".format(protocol=protocol, ip=ip, port=port)

                info = get_info(url)

            if info is None:
                pass
            else:
                sys.stdout.write("%-28s %-30s\n" % (url, info))
                count += 1 

            s.close()

        except Exception as e:
            s.close()
            continue


def do_file(url):
    ip, info = get_ip(url), get_info(url)

    try:
        if ip:
            sys.stdout.write("%-28s %-30s %-32s\n" % (url, ip, info))

    except Exception as e:
        # print(e)
        pass


def scan_cscan():
    while not queue.empty():
        do_cscan(queue.get())

def scan_file():
    while not queue.empty():
        do_file(queue.get())

def cscan(ips):
    ips = ipaddr.IPNetwork(ips)

    for ip in ips:
        queue.put(ip)

    time_start = time()

    threads_list = []
    threads = Threads

    for i in range(threads):
        t = Thread(target=scan_cscan)
        t.start()
        threads_list.append(t)

    for i in range(threads):
        threads_list[i].join()

    time_end = time() - time_start
    print(blue + "\nFound {0} ports in {1} seconds\n".format(count, time_end))


def files(file):

    with open(file, 'r') as f:
        for line in f.readlines():
            line = line.rstrip()
            if len(line) != 0:
                url = line if '://' in line else 'http://' + line
                # print(url)
                queue.put(url)

    time_start = time()

    threads_list = []
    threads = Threads

    for i in range(threads):
        t = Thread(target=scan_file)
        t.start()
        threads_list.append(t)

    for i in range(threads):
        threads_list[i].join()

    time_end = time() - time_start
    print(blue + "\nFound {0} ports in {1} seconds\n".format(count, time_end))


if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser(
        usage='cscan -i 1.1.1.1/24',
        description="Cscan V1",
    )

    parser.add_argument("-i", dest="ips",
                        help="Use ip segment (192.168.0.1/24)")
    parser.add_argument("-f", dest="file",
                        help="Use ip or domain file")
    parser.add_argument("-o", dest="save",
                        help="save")

    args = parser.parse_args()

    if args.ips is None and args.file is None:
        print(red + "[x] cscan -h" + end)
        exit(0)

    if args.ips:
        print(yellow + 'Target: ' + blue + args.ips + purp + ' | ' + yellow + 'Threads: ' + blue + str(Threads) + end + '\n')
        cscan(args.ips)

    if args.file:
        files(args.file)
