#!/usr/bin/python
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IScannerCheck

from application.XssScan import XssScan
from application.tag import tag

import sys

reload(sys)
sys.setdefaultencoding('utf8')

NAME = u'反射型xss检测插件'
VERSION = '1.0.6'

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        # 保留对回调对象的引用
        self._callbacks = callbacks

        # 获取扩展助手对象
        self._helpers = callbacks.getHelpers()

        # 设置扩展名
        callbacks.setExtensionName(NAME)

        # 将自己注册为自定义扫描器检查
        callbacks.registerScannerCheck(self)

        # 界面加载
        self.tags = tag(self._callbacks, NAME)
        self.tags.tagLoad()

        print(u'%s加载成功' % (NAME))
        print(u'版本: %s' % (VERSION))
        print(u'作者: P喵呜-phpoop')
        print(u'QQ: 3303003493')
        print(u'GitHub: https://github.com/pmiaowu')
        print(u'Blog: https://www.yuque.com/pmiaowu')
        print(u'===================================')
        print('')

    # 被动扫描时，执行
    def doPassiveScan(self, baseRequestResponse):
        pass

    # 主动扫描时，执行
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # xss扫描
        XssScanClass = XssScan(self._callbacks, self._helpers, baseRequestResponse, insertionPoint, self.tags)
        XssScanClass.scan()
        return XssScanClass.CustomScanIssueExport()

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # 当为同一个URL报告多个问题时，将调用此方法
        # 路径由相同的扩展提供检查。我们从中返回的值
        # 我们将通过这个方法来确定是否合并多个问题
        # 防止重复发送
        #
        # 由于问题的细节足以确定我们的问题是不同的，
        # 如果两个问题具有相同的细节，则只报告现有问题
        # 否则报告两个问题
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0