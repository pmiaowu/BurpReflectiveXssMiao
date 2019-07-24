#!/usr/bin/python
# -*- coding: utf-8 -*-

from application.CustomScanIssue import CustomScanIssue
import config.xss as XssConfig
import bootstrap.helpers as helpers
import re
import sys
import urllib

reload(sys)
sys.setdefaultencoding('utf8')

class XssScan():

    def __init__(self, _callbacks, _helpers, baseRequestResponse, insertionPoint, tags):
        self._callbacks = _callbacks
        self._helpers  = _helpers
        self.baseRequestResponse = baseRequestResponse
        self.insertionPoint = insertionPoint
        self.tags = tags

    def scan(self):
        # 获取请求的信息
        request = self.baseRequestResponse.getRequest()
        analyzedRequest, req_headers, req_method, req_parameters = self.getRequestInfo(request)

        # 只允许白名单类型的请求进行xss注入
        if self.insertionPoint.getInsertionPointType() not in self.tags.getScanTypeList():
            return

        # 判断当前请求包 参数是否为空
        # 为空的话,也没必要进行xss检测了
        if not req_parameters:
            return
        
        # 判断是否get参数
        # https://portswigger.net/burp/extender/api/burp/IScannerInsertionPoint.html
        # insertionPoint支持的方法查看这里
        if self.insertionPoint.getInsertionPointType() not in [0, 1]:
            return

        # 获取响应的信息
        res_headers, res_status_code, res_stated_mime_type, res_bodys = self.getResponseInfo(self.baseRequestResponse.getResponse())

        # 判断此次请求是否有“资格”成为xss
        # 如果浏览器遇到了一个不认识的后缀,会根据返回内容进行猜测
        # 例如: 
        #   url: http://xss.test/xxxx.xxx
        #
        #   file_name: xxxx.xxx  
        #   content: <script>alert(1);</script>
        # 那么打开浏览器会发现执行了xss
        # 
        # 优点: 但是加上这个判断,在前后端分离的情况可以提高检测的效率
        # 缺点: 可能会错过一些其他情况造成的“反射Xss”漏洞
        if res_stated_mime_type != 'HTML':
            return
        
        # 初步xss检测
        if self.preliminaryXssScan() == False:
            return 

        # 普通xss扫描
        self.xssDetect()

        # 其他xss扫描
        self.otherXssDetect()

    # 初步xss检测
    def preliminaryXssScan(self):
        # 请求在插入点包含我们的注入测试
        # checkRequest = 完整的HTTP请求
        # buildRequest(填写payload)
        checkRequest = self.insertionPoint.buildRequest(XssConfig.xss_test_payload)

        # 发送请求,获取响应
        checkRequestResponse = self._callbacks.makeHttpRequest(self.baseRequestResponse.getHttpService(), checkRequest)

        # 获取响应的信息
        new_res_headers,new_res_status_code, res_stated_mime_type, new_res_bodys,  = self.getResponseInfo(checkRequestResponse.getResponse())

        # 判断payload是否出现过
        if new_res_bodys.find(XssConfig.xss_test_payload) <= -1:
            return False

        self.new_res_bodys = new_res_bodys

        return True

    # 普通xss扫描
    def xssDetect(self):
        new_res_body_list = re.findall(XssConfig.html_regex, self.new_res_bodys.encode('utf-8'))

        # 用于其它xss匹配使用
        test_body = self.new_res_bodys

        for html in new_res_body_list:
            test_body = test_body.replace(html,'')

            if html.find(XssConfig.xss_test_payload) <= -1:
                continue

            # 确认加载的payload
            xss_payload_list = []
            xss_type = ''

            if len(re.findall(XssConfig.xss_regex_3, html)) >= 1 or len(re.findall(XssConfig.xss_regex_4, html)) >= 1:
                xss_type = 'pseudo-protocol'
                xss_payload_list = XssConfig.xss_payload_3
            else:
                xss_type = 'dom'
                if len(re.findall(XssConfig.xss_regex_1, html)) >= 1:
                    xss_payload_list = XssConfig.xss_payload_1
                else:
                    xss_payload_list = XssConfig.xss_payload_2

            for payload in xss_payload_list:
                checkRequest = self.insertionPoint.buildRequest(payload)

                # 发送请求,获取响应
                checkRequestResponse = self._callbacks.makeHttpRequest(self.baseRequestResponse.getHttpService(), checkRequest)

                # 获取响应的信息
                new_res_headers,new_res_status_code, res_stated_mime_type, new_res_bodys,  = self.getResponseInfo(checkRequestResponse.getResponse())

                if new_res_bodys.find(payload) >= 0:

                    if xss_type == 'dom':
                        # 判断payload是否给转义了
                        if new_res_bodys.find(helpers.addslashes(payload)) >= 0:
                            break
                        
                        # 判断是否给转成html实体
                        if new_res_bodys.find(helpers.htmlspecialchars(payload, 'ENT_QUOTES')) >= 0:
                            break

                    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
                    new_analyzed_request, new_req_headers, new_req_method, new_req_parameters = self.getRequestInfo(checkRequest)
                    # 获取请求包返回的服务信息
                    host, port, protocol, is_https = self.getServerInfo(self.baseRequestResponse.getHttpService())
                    req_url = self.getRequestUrl(protocol, port, new_req_headers)

                    self.xssIssuePayload = payload
                    self.checkRequestResponse = checkRequestResponse

                    print('')
                    print('===================================')
                    print(u'你好呀~ (≧ω≦*)喵~')
                    print(u'这边检测到一处反射xss呢 喵~')
                    print(u'漏洞url: %s' % (req_url))
                    print(u'请求方法: %s' % (new_req_method))
                    print(u'参数: %s=%s' % (self.insertionPoint.getInsertionPointName(), payload))
                    print('===================================')
                    print('') 
                    break

        self.test_body = test_body

    # 其他类型的xss扫描
    def otherXssDetect(self):
         # 匹配所有其他的xss
        test_body = self.test_body.replace(XssConfig.xss_test_payload,'<xss>'+XssConfig.xss_test_payload+'</xss>')
        if len(re.findall(XssConfig.xss_regex_2, test_body.encode('utf-8'))) >= 1:
            for payload in XssConfig.xss_payload_4:
                checkRequest = self.insertionPoint.buildRequest(payload)

                # 发送请求,获取响应
                checkRequestResponse = self._callbacks.makeHttpRequest(self.baseRequestResponse.getHttpService(), checkRequest)

                # 获取响应的信息
                new_res_headers,new_res_status_code, res_stated_mime_type, new_res_bodys,  = self.getResponseInfo(checkRequestResponse.getResponse())

                if new_res_bodys.find(payload) >= 0:
                    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
                    new_analyzed_request, new_req_headers, new_req_method, new_req_parameters = self.getRequestInfo(checkRequest)
                    # 获取请求包返回的服务信息
                    host, port, protocol, is_https = self.getServerInfo(self.baseRequestResponse.getHttpService())
                    req_url = self.getRequestUrl(protocol, port, new_req_headers)

                    self.xssIssuePayload = payload
                    self.checkRequestResponse = checkRequestResponse

                    print('')
                    print('===================================')
                    print(u'你好呀~ (≧ω≦*)喵~')
                    print(u'这边检测到一处反射xss呢 喵~')
                    print(u'漏洞url: %s' % (req_url))
                    print(u'请求方法: %s' % (new_req_method))
                    print(u'参数: %s=%s' % (self.insertionPoint.getInsertionPointName(), payload))
                    print('===================================')
                    print('')
                    break

    # 漏洞问题输出
    def CustomScanIssueExport(self):
        xssIssuePayload = getattr(self, "xssIssuePayload", None)
        if xssIssuePayload != None:
            # 报告这件事
            return [CustomScanIssue(
                self.baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(self.baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(self.checkRequestResponse, None, [])],
                'ReflectiveXss',
                self.insertionPoint.getInsertionPointName() + ' = ' + urllib.quote_plus(xssIssuePayload, safe=""),
                "High")]

    # 获取请求url
    def getRequestUrl(self, protocol, port, req_headers):
        link = req_headers[0].split(' ')[1]
        host = req_headers[1].split(' ')[1]
        return protocol + '://' + host + ':' + str(port) + link

    # 获取请求的信息
    # 请求头,请求方法,请求参数
    def getRequestInfo(self, request):
        analyzedRequest = self._helpers.analyzeRequest(request)

        # 请求中包含的HTTP头信息
        req_headers = analyzedRequest.getHeaders()
        # 获取请求方法
        req_method = analyzedRequest.getMethod()  
        # 请求参数列表
        req_parameters = analyzedRequest.getParameters()

        return analyzedRequest, req_headers, req_method, req_parameters

    # 获取响应的信息
    # 响应头,响应内容,响应状态码
    def getResponseInfo(self, response):
        analyzedResponse = self._helpers.analyzeResponse(response)

        # 响应中包含的HTTP头信息
        res_headers = analyzedResponse.getHeaders()
        # 响应中包含的HTTP状态代码
        res_status_code = analyzedResponse.getStatusCode()
        # 响应中返回的数据返回类型
        res_stated_mime_type = analyzedResponse.getStatedMimeType()
        # 响应中返回的正文内容
        res_bodys = response[analyzedResponse.getBodyOffset():].tostring() 

        return res_headers, res_status_code, res_stated_mime_type, res_bodys

    # 获取请求包返回的服务信息
    def getServerInfo(self, httpService):

        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        is_https = False
        if protocol == 'https':
            is_https = True

        return host, port, protocol, is_https