#!/usr/bin/python
# -*- encoding:utf-8 -*-
import hashlib
import uuid
import re
from tornado.httpserver import HTTPServer
import tornado.web
from tornado.ioloop import IOLoop
import os
import requests
from urllib import request as reqt
from tornado.options import define, parse_command_line, options
from tornado.web import Application

session = requests.session()

session.verify = False

def get_token(md5str):

    m1 = hashlib.md5()
    m1.update(md5str.encode("utf-8"))
    token = m1.hexdigest()
    return token


class indexHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")


class Notify_URLHandler(tornado.web.RequestHandler):
    def get(self):
        print(self.request.body)
        xml1 = str(self.request.body, encoding='utf-8')
        print("cml", xml1)
        pattertn = re.compile(r'out_trade_no><!\[CDATA\[(.*?)]]></out_trade_no')

        out_trade_no = pattertn.findall(xml1)[0]

        print(out_trade_no)
        appid = ''
        mch_id = ''
        body = ""

        key = ''

        nonce_str = str(uuid.uuid4()).replace('-', "")[:-3]

        signA = "appid=%s&mch_id=%s&nonce_str=%s&out_trade_no=%s" % (appid, mch_id, nonce_str, out_trade_no)

        print(signA)
        strSignTmp = signA + "&key=" + key
        sign = get_token(strSignTmp).upper()

        xml = '''<xml>
               <appid>%s</appid>
               <mch_id>%s</mch_id>
               <nonce_str>%s</nonce_str>
               <out_trade_no>%s</out_trade_no>
               <sign>%s</sign>
            </xml>''' % (appid,mch_id,nonce_str, out_trade_no, sign)

        url = 'https://api.mch.weixin.qq.com/pay/orderquery'
        headers = {
            'Accept-Language': 'zh-CN,en-US;q=0.8',
            # 'Content-Type': 'application/json'
            # "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept": "application/xml;charset=UTF-8",
        }
        # 我用requests 出现乱码，用urllib
        req = reqt.Request(url, headers=headers, data=xml.encode())  # POST方法
        #
        page = reqt.urlopen(req).read()
        print(page)
        page = page.decode('utf-8')
        #
        print(page)

        pattertn2 = re.compile(r'trade_state_desc><!\[CDATA\[(.*?)]]></trade_state_desc')

        trade_state_desc = pattertn2.findall(page)[0]
        print(trade_state_desc)
        if trade_state_desc == '支付成功':
            print("匹配成功")
            #######################
            # 这里处理自己需要的处理的
            #######################




        self.write("")

    def post(self):
        print(self.request.body)
        self.write("")
    # 微信回调函数



class Notify_wxHandler(tornado.web.RequestHandler):
    def get(self):

        total_fee = "20"
        # 金额

        appid = 'appid'
        mch_id = 'mch_id'
        body = "微信Demo"
        key = ''
        host = "域名 "
        # 微信填写的备案域名
        nonce_str = str(uuid.uuid4()).replace('-', "")[:-3]
        # 生成随机字符串
        notify_url = 'http://{}/Notify_URL'.format(host)
        # 回调函数
        wap_name = '腾讯充值'
        wap_name.encode('utf-8')
        scene_info = {
            "h5_info": {"type": "Wap", "wap_url": "http://{}/Notify_wx".format(host), "wap_name": wap_name}}
        out_trade_no = get_token(nonce_str)
        # md5 加密生成订单编号
        ip = self.request.remote_ip
        # x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        # print(self.request.META)
        # if x_forwarded_for:
        #     spbill_create_ip = x_forwarded_for.split(',')[0]  # 所以这里是真实的ip
        # else:
        #     spbill_create_ip = self.request.META.get('REMOTE_ADDR')  # 这里获得代理ip
        # 此处 为django获取ip的方法

        total_amount = str(int(float(total_fee) * 100))
        trade_type = 'MWEB'
        signA = "appid=%s&body=%s&mch_id=%s&nonce_str=%s&notify_url=%s&out_trade_no=%s&scene_info=%s&spbill_create_ip=%s&total_fee=%s&trade_type=%s" % (
            appid, body, mch_id, nonce_str, notify_url, out_trade_no, scene_info, ip, total_amount,
            trade_type)
        print(signA)
        strSignTmp = signA + "&key=" + key
        sign = get_token(strSignTmp).upper()
        # 进行MD5加密
        print(sign)
        post_data = "<xml>"
        for i in (signA + "&sign=" + sign).split("&"):
            xml1 = i.split("=")[0]
            xml2 = i.split("=")[1]
            post_data = post_data + '<' + xml1 + '>' + xml2 + '</' + xml1 + '>'
        post_data = post_data + '</xml>'
        # 组合xml请求
        print(post_data)
        # post_data.encode('utf-8')
        headers = {'Content-Type': 'binary'}
        # 解决post_data 中文编码问题
        url = "https://api.mch.weixin.qq.com/pay/unifiedorder"
        res = requests.post(url, data=post_data.encode(), headers=headers, verify=False)
        # 提交订单信息
        # res.text.encode('utf-8')
        print(res.text.encode('latin_1').decode('utf8'))
        pattern = re.compile("<mweb_url><!\[CDATA\[(.*?)]]></mweb_url")

        redicrt_url = pattern.findall(res.text)[0]
        # 匹配微信回调函数，调用微信app进行支付
        self.redirect(redicrt_url)
        # 重定向至微信




if __name__ == '__main__':

    define("port", default=8001, help="默认端口8000")
    parse_command_line()
    app = Application(
        [
            (r'/index', indexHandler),
            (r'/Notify_wx', Notify_wxHandler),
            (r'/Notify_URL', Notify_URLHandler),
        ],
        # 项目配置信息
        # 网页模板
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        # 静态文件
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        # debug=False
    )
    # 部署
    server = HTTPServer(app)
    server.listen(options.port)

    # 轮询监听
    IOLoop.current().start()
