#-*- coding:utf-8 -*-
#Author: Vulkey_Chen


import datetime
import urllib.request
import gevent, sys, re
from gevent import monkey
gevent.monkey.patch_all()

nowTime = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')

poc = "http://httpbin.org/ip"

def useProxy(site):
	try:
		res = urllib.request.urlopen(poc, proxies={'http': site}).read()
		return res
	except:
		return getIP()

def getIP():
	res = urllib.request.urlopen(poc).read()
	return res

def getSite(filename):
	f = open(filename)
	res = []
	for line in f:
		if line.find("http") >= 0:
			pass
		else:
			line = "http://"+line
		res.append(line.replace("\n",""))
	return res

def isIP(ip):
    compileIP = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if compileIP.match(ip):
        return True
    else:
        return False

def isVul(site):
	resA = getIP()
	#print resA
	resB = useProxy(site)
	#print resB
	if resA == resB or not isIP(resB):
		print("\033[1;33m[INFO]\033[0m No Vulnerability!")
	else:
		with open("proxy_vul_"+str(nowTime)+".txt","a") as f:
			f.write(str(site)+"--"+str(resB)+"\n")
		print("\033[1;31m[INFO]\033[0m Existing Vulnerability!")
		print("\033[1;36m[INFO]\033[0m Site:[ {0} ] -> RealIP:[ {1} ]".format(site, resB))


if __name__ == '__main__':
	if len(sys.argv)==2:
		tasks = [gevent.spawn(isVul, url) for url in getSite(sys.argv[1])]
		gevent.joinall(tasks)
	else:
		print("python proxy_vul.py domain.txt")
