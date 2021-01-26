#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2021/1/25 4:36 下午
# @Author  : Pickmea.
# @Email   : h4ckst5@qq.com
# @File    : infoweak.py

# 信息扫描
import queue
from urllib.parse import urlparse
from threading import Thread
import HackRequests
import warnings
warnings.filterwarnings("ignore")

all_que = queue.Queue()
hack = HackRequests.hackRequests()

def scan_tral():
    while True:
        try:
            testurl = all_que.get(timeout=0.1).strip('\r').strip('\n')
        except:
            break
        try:
            if testurl.endswith('/'):
                pass
            else:
                testurl += '/'
            xx = urlparse(testurl).netloc
            # print(host)
            raw = '''
GET / HTTP/1.1
Host: {}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:84.0) Gecko/20100101 Firefox/84.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Referer: {}
            ''' .format(xx, testurl)
            # print(raw)
            hh = hack.httpraw(raw)
            res = (hh.log['response'])
            # if hh.status_code != 302 and hh.status_code != 404 and hh.status_code != 200 and hh.status_code != 301:
            #     print("code error: ", testurl, "\n", hh.log, "\n", hh.status_code)
            if res.find('Illegal character') >= 1:
                print("[vuln:]",testurl)
        except Exception as e:
            # print(e)
            pass

def start_mul(file):
    for x in open(file):
        x = x.strip()
        if x.find('http') >= 0:
            pass
        else:
            x = 'https://' + x.strip() + '/'
        all_que.put(x)
    urlth = []
    for x in range(30):
        p = Thread(target=scan_tral)
        urlth.append(p)
        p.start()

    for paa in urlth:
        paa.join()
# file = sys.argv[1]
if __name__ == '__main__':
    filename = sys.argv[1]
    # filename = 'http_url.txt'
    start_mul(filename)
