# 简介

Xss喵-一只为了作者默默检测Xss注入的Burpsuite插件喵  (●´∀｀●)嘿嘿嘿

一只可怜兮兮还不知道自己唯一使命的Burpsuite插件 (°ー°〃)愣住

此插件会检测所有的GET/POST参数并且进行xss fuzz

注意: 该插件只会在以下几个burp模块运行
- Burp Scanner模块

# 免责声明
该工具仅用于安全自查检测

由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。

本人拥有对此工具的修改和解释权。未经网络安全部门及相关部门允许，不得善自使用本工具进行任何攻击活动，不得以任何方式将其用于商业目的。

# 功能

用于检测隐藏的反射XSS

# 安装过程

在安装使用之前,请安装作者的基础转发插件: https://github.com/pmiaowu/BurpHttpForwardRequests

![](./readme/images/1.png)
![](./readme/images/2.png)

# 配置项

![](./readme/images/13.png)

# 测试代码

![](./readme/images/3.png)

# 运行例子

![](./readme/images/4.png)
![](./readme/images/5.png)
![](./readme/images/6.png)
![](./readme/images/7.png)
![](./readme/images/8.png)
![](./readme/images/9.png)
![](./readme/images/10.png)
![](./readme/images/11.png)
![](./readme/images/12.png)