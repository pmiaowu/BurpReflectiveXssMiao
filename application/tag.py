#!/usr/bin/python
# -*- coding: utf-8 -*-

from burp import ITab

from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt import Insets
from java.awt import Color
from java.awt import Font

from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JCheckBox
from javax.swing import JTabbedPane

import config.xss as XssConfig

class tag(ITab):
    def __init__(self, callbacks, name):
        self._callbacks = callbacks
        self.name = name

    def getTabCaption(self):
        return self.name

    def getUiComponent(self):
        return self.tabs

    def setFontItalic(self, label):
        label.setFont(Font(label.getFont().getName(), Font.ITALIC, label.getFont().getSize()))

    def setFontBold(self, label):
        label.setFont(Font('Serif', Font.BOLD, label.getFont().getSize()))

    # 配置界面添加    
    def tagLoad(self):
        # 创建窗口 开始
        self.tabs = JTabbedPane()

        self.scan_type_settings = JPanel(GridBagLayout())
        
        c = GridBagConstraints()

        # 界面选项卡加载
        self.tag_1(c)
        self.tag_2(c)

        # 添加选项卡
        self.tabs.addTab(u'扫描类型设置', self.scan_type_settings)
        
        self._callbacks.customizeUiComponent(self.tabs)
        self._callbacks.addSuiteTab(self)

    # 选项卡1-标签1-ui
    def tag_1(self, c):
        # 创建 检查框
        self.is_scan_get_start_box = JCheckBox(u'是否扫描GET类型的参数(推荐打勾)', XssConfig.IS_SCAN_GET_START)
        self.setFontBold(self.is_scan_get_start_box)
        self.is_scan_get_start_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 1
        self.scan_type_settings.add(self.is_scan_get_start_box, c)

        # 在窗口添加一句话
        is_scan_get_start_box_lbl = JLabel(u'打勾-启动, 不打勾-关闭')
        self.setFontItalic(is_scan_get_start_box_lbl)
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 2
        self.scan_type_settings.add(is_scan_get_start_box_lbl, c)

    # 选项卡1-标签2-ui
    def tag_2(self, c):
        # 创建 检查框
        self.is_scan_post_start_box = JCheckBox(u'是否扫描POST类型的参数(推荐打勾)', XssConfig.IS_SCAN_POST_START)
        self.setFontBold(self.is_scan_post_start_box)
        self.is_scan_post_start_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 3
        self.scan_type_settings.add(self.is_scan_post_start_box, c)

        # 在窗口添加一句话
        is_scan_post_start_box_lbl = JLabel(u'打勾-启动, 不打勾-关闭')
        self.setFontItalic(is_scan_post_start_box_lbl)
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 4
        self.scan_type_settings.add(is_scan_post_start_box_lbl, c)

    def getScanTypeList(self):
        type_list = []

        if self.is_scan_get_start_box.isSelected():
            type_list.append(0)
        if self.is_scan_post_start_box.isSelected():
            type_list.append(1)

        return type_list