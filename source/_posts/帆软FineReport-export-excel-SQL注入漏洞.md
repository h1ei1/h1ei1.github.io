---
title: 帆软FineReport export_excel SQL注入漏洞
date: 2025-12-25 12:00:00
tags:
  - 漏洞分析
---

##### 环境搭建：
双击安装V11 版本，输入申请的激活码：05627014-b2c87aec1-85b3-bdc4fd925c5d

下载地址：https://pan.baidu.com/s/1eyqzpZMeY_2a-ji0JVv60Q 提取码: ph8r

漏洞调试可修改 bin/designer.bat 文件，添加 JVM 调试参数，保存后重启 FineReport

-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766049083752-8ca798f2-a38d-47d9-891f-1bb278d75d75.png)

访问 http://ip:8075/webroot/decision

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766049101859-598bbfa0-fc38-4ff0-ad0a-cc6e8d424859.png)

##### 漏洞分析：
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766388776846-0bdfc5e7-bfc1-43c1-aa0c-fa3c750250a5.png)

根据漏洞描述查找包含 /export/excel 的路由

com.fr.nx.app.web.controller.NXController#largedsExcelExportV9

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766384541711-5e2d36e0-0c4f-44a5-915d-ae52f7b8bd2e.png)

继续跟进 com.fr.web.controller.AbstractRequestService#handle -> com.fr.nx.app.direct.AbstractExportHandler#handleRequest -> com.fr.nx.app.web.v9.handler.handler.largeds.LargeDatasetExcelExportHandler#doHandle，此处会调用 this.initCreator 初始化 WorkbookDataCreator（Excel创建工作器）

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766387722568-661db8bd-f8fe-47bd-940f-ced92e9b30de.png)

继续跟进，从HTTP请求中获取参数 __parameters__ 参数，调用 this.getEntity 从请求中解析导出配置实体，然后调用 this.dealParam 方法处理导出参数

com.fr.nx.app.web.v9.handler.handler.largeds.LargeDatasetExcelExportHandler#initCreator

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766387950911-05daf0bb-80c3-49dd-aa86-498a96b6aa75.png)

this.getEntity 方法会获取请求头 params 的值并解析为 LargeDatasetExcelExportJavaScript 对象

com.fr.nx.app.web.v9.handler.handler.largeds.LargeDatasetExcelExportHandler#getEntity

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766388351737-80be2585-d66a-4643-9690-5b7e40cfec0d.png)

继续跟进 this.dealParam 方法，调用 ParameterProvider[] var9 = var3.getParameters(); 从XML配置中获取参数数组并进行一系列处理，当满足参数值是Formula 类型时会调用 evalValue 方法

com.fr.nx.app.web.v9.handler.handler.largeds.LargeDatasetExcelExportHandler#dealParam

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766389249852-80de2f53-1f13-41a2-9eb5-d803796f5991.png)

evalValue（com.fr.script.Calculator#evalValue）方法会调用 parse 使用 ANTLR 生成的词法分析器（FRLexer）和语法解析器（FRParser）将字符串解析成结构化的抽象语法树（AST），可以调用 SQL 函数执行恶意的命令

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766390767843-07b7408d-acd7-4f7a-a503-82382c2f1547.png)


##### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1766391081994-d896f3ab-fe52-4914-bd58-8d4d0c4cf156.png)
