#!/usr/bin/python
# -*- coding: utf-8 -*-

# 允许的请求方法
method = {'GET', 'POST'}

# 匹配html标签dom节点
# 例如: <a>xxx</a> <div>xxx</div> 匹配成功
html_regex = r'<.*?>'

# 测试是否有xss的标识
xss_test_payload = 'reflective-test-payload'

# 匹配所有给 (双引号+变量:xss_test_payload) 包含的数据
# 例如: <img src="变量:xss_test_payload"> 匹配成功
xss_regex_1 = r'<.*?\"(.*?'+xss_test_payload+'.*?)*\".*?>'

# 匹配所有在 “<xss></xss>” 这个标签的里面数据
# 例如: <xss>xxx<</xss> 匹配成功
xss_regex_2 = r'<xss>.*?</xss>'

# 判断payload点是否在可使用js伪协议的地方
xss_regex_3 = r'<a.*?href="'+xss_test_payload+'".*?>'

# xss测试脚本

# 所有是html标签dom节点的,并且匹配的上(正则变量:xss_regex_1),都会调用它,进行xss匹配
xss_payload_1 = ['"><img src=test_payload_1_1>', '"<img src=test_payload_1_2>', '"test=pMiaoGo_1_3']

# 所有是html标签dom节点的,并且匹配不上(正则变量:xss_regex_1),都会调用它,进行xss匹配
xss_payload_2 = ['\'"><img src=test_payload_2_1>', '\'"<img src=test_payload_2_2>', '\'"test=pMiaoGo_2_3', '\'test=pMiaoGo_2_4']

# 所有支持伪协议的都会调用
xss_payload_3 = ['javascript:alert(1)']

# 所有不是html标签dom节点的,都会调用它,进行xss匹配
xss_payload_4 = ['\'";alert(1);">a<a xx=payload_3_1>']