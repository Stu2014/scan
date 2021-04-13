#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2021/3/30 10:18 上午
# @Author  : Pickmea.
# @Email   : h4ckst5@qq.com
# @File    : temppro.py.py

import requests
import random
import queue
import warnings,sys
from threading import Thread
from urllib.parse import urlparse
warnings.filterwarnings("ignore")

httpQueue = queue.Queue()

def get_url(site):
    while True:
        try:
            hosts = httpQueue.get(timeout=0.1)
        except:
            break
        try:
            host = hosts[0]
            port = hosts[1]
            proxies_http = {
                "http": "http://{}:{}".format(host, port),
                "https": "https://{}:{}".format(host, port),
            }

            # res = requests.get("http://httpbin.org/ip", proxies=proxies_http, timeout=5, verify=False).text
            response = requests.get(site, proxies=proxies_http, timeout=5, verify=False).text
            print("try {}{}".format(site,proxies_http))
            if 'check that this domai' in response:
                print(response, '----', host)
        except Exception as e:
            # print(e)
            pass


def get_host_port(filename, site):
    for x in open(filename,'r'):
        url = x.strip().split(':')
        port = url[1]
        host = url[0]
        # print(host,port)
        httpQueue.put([host, port])
    proxy_threads = []
    for x in range(30):
        p = Thread(target=get_url, args=(site,))
        proxy_threads.append(p)
        p.start()

    for p in proxy_threads:
        p.join()

# http
def addhttp(x):
    if x.find('http') >= 0:
        pass
    else:
        x = 'http://' + x + '/'
    return x

if __name__ == '__main__':
    # filename = sys.argv[1]#存在http协议
    filename = '1.txt'#代理地址 格式127.0.0.1:8080
    sites = '2.txt'# 访问的地址 baidu.com
    for x in open(sites, 'r'):
        site = addhttp(x.strip())
        get_host_port(filename, site)
