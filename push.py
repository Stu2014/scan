#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/6/27 下午3:33
# @Author  : Stu.
# @File    : push.py
import json
import requests


# 钉钉推送，token添加关键字，扫描、vuln
def push_dingding(dingtoken, jobstatus=None, vul_type=None, job_url=None, vuln_url=None, test=None):
    if dingtoken:
        headers = {"Content-Type": "application/json"}
        dingtoken_url = "https://oapi.dingtalk.com/robot/send?access_token=" + dingtoken;

        if test == 1:
            ding_json = {
                "msgtype": "text",
                "text": {
                    "content": "测试扫描器推送token可用"
                }
            }
        elif jobstatus == 1 and job_url:
            ding_json = {
                "msgtype": "text",
                "text": {
                    "content": "%s 域名端口扫描任务完成 ,请及时查看" % job_url
                }
            }
        elif vuln_url and vul_type:
            ding_json = {
                "msgtype": "text",
                "text": {
                    "content": "[vuln find] vuln type: %s ,vuln url: %s" % (vul_type, vuln_url)
                }
            }
        try:
            res = requests.post(url=dingtoken_url, data=json.dumps(ding_json), headers=headers)
        except Exception as e:
            print("钉钉推送错误：", e)
            pass
    else:
        pass


# 微信server酱推送 访问http://sc.ftqq.com/3.version获取secret
def push_wx(secret, jobstatus=None, vul_type=None, job_url=None, vuln_url=None, test=None):
    if secret:
        wx_url = "http://sc.ftqq.com/" + secret + ".send";print(wx_url)

        if test == 1:
            wx_json = {
                "text": "扫描器测试微信推送",
                "desp": "扫描器测试微信推送正文"
            }
        elif jobstatus == 1 and job_url:
            wx_json = {
                "text": "扫描任务完成",
                "desp": "%s 域名端口扫描任务完成 ,请及时查看" % job_url
            }
        elif vuln_url and vul_type:
            wx_json = {
                "text": "漏洞报告",
                "desp": "[vuln find] vuln type: %s ,vuln url: %s" % (vul_type, vuln_url)
            }
        try:
            res = requests.post(url=wx_url, data=wx_json)
            print(res.text)
        except Exception as e:
            print("微信推送错误：", e)
            pass
    else:
        pass


if __name__ == '__main__':
    dingtoken = ""
    secret = ""
    # 钉钉推送，token添加关键字，扫描、vuln
    # 测试是否可用 传入token,test=1
    push_dingding(dingtoken, test=1)

    # 扫描任务完成 传入dingtoken，jobstatus，job_url
    push_dingding(dingtoken=dingtoken, jobstatus=1, job_url="http://baidu.com")

    # 扫描发现漏洞，传入dingtoken,vul_type,vuln_url
    push_dingding(dingtoken, vul_type="sqlinjection", vuln_url="http://baidu.com")

    # 微信推送
    push_wx(secret=secret, test=1)
    push_wx(secret=secret, jobstatus=1, job_url="http://baidu.com")
    push_wx(secret=secret, vul_type="sqlinjection", vuln_url="http://baidu.com")
