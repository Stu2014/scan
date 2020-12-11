#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/8/19 下午1:55
# @Author  : Stu.
# @Email   : h4ckst5@qq.com
# @des     : 目录穿越扫描
# @File    : travelvuln_check.py
import queue, requests
from threading import Thread
import sys
import warnings
warnings.filterwarnings("ignore")

all_que = queue.Queue()
def scan_tral():
    while True:
        try:
            testurl = all_que.get(timeout=0.1)
        except:
            break
        # print("testing", testurl)
        try:
            res1 = requests.get(testurl+'/qpalzmqpalzm.js',timeout=10,verify=False)
            res2 = requests.get(testurl+'/a/..;/..;/', timeout=10,verify=False)
            code1 = res1.status_code
            code2 = res2.status_code
            if code1 == 404 and code2 == 400:
                with open("result.txt", 'a') as f:
                    f.write("[travel vulned]"+testurl+'\n')
                print("travel vulned", testurl)
        except Exception as e:
            print(e)
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
    start_mul(filename)


