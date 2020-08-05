#coding:utf-8
import dns.resolver
import requests,json,sys
import argparse

vuldomain=""
#token 配置关键字spf
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
        return True
    except dns.exception.Timeout:
        return False
    except:
        return False


#提醒
def sendresult(vuldomain):
    # vuldomain
    ding={
        "msgtype": "text",
        "text": {
            "content": "以下spf未配置，请检查!\n%s" % vuldomain
        }
    }
    try:
        res=requests.post(url=tokenurl,data=json.dumps(ding),headers=headers)
    except:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                    description='SPF NOT SET Scanner.By Stu.',
                                    usage='spfcheck.py [optional]')
    parser.add_argument('-f',metavar='File',type=str,default='url.txt',help='Put Web url in url.txt')
    parser.add_argument('-u',metavar='Url',type=str,help='Put a Web url')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    if args.u is None:
      for url in open(args.f) :
          check_vul(url.strip())
    else:
        check_vul(args.u)
    if vuldomain.strip() != '':
        sendresult(vuldomain)
