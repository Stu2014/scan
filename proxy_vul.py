#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/9/16 4:48 下午
# @Author  : Stu.
# @Email   : h4ckst5@qq.com
# @File    : http_proxy_vuln.py
# 扫描代理模块

import requests
import random
import queue
import warnings,sys
from threading import Thread
from urllib.parse import urlparse
warnings.filterwarnings("ignore")

httpQueue = queue.Queue()

def get_url():
    while True:
        try:
            hosts = httpQueue.get(timeout=0.1)
        except:
            break
        host = hosts[0]
        port = hosts[1] or 80
        proxies_http = {
            "http": "http://{}:{}".format(host, port),
            "https": "https://{}:{}".format(host, port),
        }
        # print(host+str(port)+'\n')
        random_str_ = random_str(8)
        try:
            response = requests.get("https://"+str(host)+'.'+str(port)+'.'+random_str_+".f4c8e390.dnslog.link/", proxies=proxies_http, timeout=5, verify=False)
            if getdnslog(random_str_) == "True":
                print("[200] {}:{} {}".format(host, port, random_str_))
                with open("result.txt", 'a') as f:
                    f.write("[http-proxy]"+host+':'+str(port)+' '+random_str_+'\n')
        except Exception as e:
            print(e)
            pass

# 查看dnslog状态
def getdnslog(random_str):
    dns_check = "https://admin.dnslog.link/api/web/f4c8e390/%s/" % random_str  # token 替换为http://admin.dnslog.link平台字符串
    res = requests.get(dns_check, timeout=5, verify=False)
    return res.text.strip()

# 取得随机数
def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("QWERTYUIOPASDFGHJKLZXCVBNM1234567890"))
    return str(str1)

def get_host_port(filename):
    for x in open(filename,'r'):
        url = x.strip()
        port = urlparse(url).port
        host = urlparse(url).hostname
        httpQueue.put([host, port])
    proxy_threads = []
    for x in range(30):
        p = Thread(target=get_url)
        proxy_threads.append(p)
        p.start()

    for p in proxy_threads:
        p.join()
if __name__ == '__main__':
    filename = sys.argv[1]#存在http协议
    get_host_port(filename)

