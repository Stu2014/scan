#coding:utf-8
import dns.resolver
import requests,json,sys

vuldomain=""
tokenurl="https://oapi.dingtalk.com/robot/send?access_token="
headers ={"Content-Type": "application/json"}

#检测是否配置spf
def check_vul(url):
    global vuldomain
    try:
        A = str(dns.resolver.query(url,"txt").response)
        if A.find("v=spf") >= 0:
            pass
        else:
            vuldomain+=url+"\n"
            # print(vuldomain)
            return True
    except dns.resolver.NoAnswer:
        vuldomain+=url+"\n"
    except dns.exception.Timeout:
        pass


#提醒
def sendresult(vuldomain):
    # vuldomain
    ding={
        "msgtype": "text", 
        "text": {
            "content": "以下spf未配置，请检查!\n%s" % vuldomain
        }
    }
    res=requests.post(url=tokenurl,data=json.dumps(ding),headers=headers)


if __name__ == '__main__':
    if sys.argv == 1:
        print("python spfcheck.py targets.txt")
    else:
        file=sys.argv[1]
    for url in open(file) :
        check_vul(url.strip())
    if vuldomain.strip() != '':
        sendresult(vuldomain)
    else:
        pass
