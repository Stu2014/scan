import mmh3
import requests
 
response = requests.get('http://baidu.co/favicon.ico')
favicon = response.content.encode('base64')
hash = mmh3.hash(favicon)
print hash
'''
http.favicon.hash:11111
''''
