---
title: 用友 U8Cloud NCCloudGatewayServlet 命令执行漏洞
date: 2025-10-10 12:00:00
tags:
  - 漏洞分析
---

##### 环境搭建：
漏洞未使用数据库功能，直接运行 u8csetup.bat 安装

再运行 startup.bat 启动服务即可

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753864667034-f8d5b8e5-db78-4083-88d6-3e4b80d7eb8b.png?x-oss-process=image%2Fwatermark%2Ctype_d3F5LW1pY3JvaGVp%2Csize_47%2Ctext_cWF4Y2VydA%3D%3D%2Ccolor_FFFFFF%2Cshadow_50%2Ct_80%2Cg_se%2Cx_10%2Cy_10%2Fwatermark%2Ctype_d3F5LW1pY3JvaGVp%2Csize_47%2Ctext_cWF4Y2VydA%3D%3D%2Ccolor_FFFFFF%2Cshadow_50%2Ct_80%2Cg_se%2Cx_10%2Cy_10%2Fwatermark%2Ctype_d3F5LW1pY3JvaGVp%2Csize_47%2Ctext_cWF4Y2VydA%3D%3D%2Ccolor_FFFFFF%2Cshadow_50%2Ct_80%2Cg_se%2Cx_10%2Cy_10)

##### 漏洞分析：
查看漏洞补丁，修改了 GateWayUtil.class 和 ServletForGW.class 文件·，新增了 GWWhiteCtrlUtil.class 文件

https://security.yonyou.com/#/patchInfo?identifier=9695976d67dd4786badf91df6cb6578c
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760001913651-b1ef1b24-277a-4be2-9b20-d7fc751afcca.png)

对比 GateWayUtil.class 文件，在 checkGateWayToken 增加了校验，原先只是简单的判断和 /resources/nccloud/nccloudgateway.properties 文件中的 nccloud.gateway.nctoken 值是否相等，该值是硬编码。

com.yonyou.nccloud.gateway.adapter.GateWayUtil
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1758762497739-f9c4affb-91f9-4c4c-9bbe-bdd469e4f252.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1758762680174-49fd3d70-0a46-44be-9ff4-2162ba1bef84.png)

使用代码中的加密代码输出为：TJ6RT-3FVCB-DPYP8-XF7QM-96FV3

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1758765051154-576fbee3-402d-4a74-b84e-2a538b8c4e93.png)

继续对比 ServletForGW.class 文件，增加了GWWhiteCtrlUtil.getInstance().checkAuthority(serviceClassName, argValues) 对传入的 serviceClassName 和 argValues 进行检查

com.yonyou.nccloud.gateway.adaptor.servlet.ServletForGW#callNCService
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760002882701-eb8b0f6f-7e79-4175-8ce4-727141f5077f.png)

跟进该方法调用了 checkBlackITFAuthority 方法，将 com.ufida.zior.console.IActionInvokeService 和 nc.bs.pub.util.ProcessFileUtils 加入了黑名单

com.yonyou.nccloud.gateway.adapter.util.GWWhiteCtrlUtil#checkBlackITFAuthority
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760003157515-f5e66562-cea6-4df4-b6d1-ef4c15b844b2.png)

跟进 com.ufida.zior.console.IActionInvokeService 的具体实现类，没有校验直接通过反射进行功能调用。

com.ufida.zior.console.ActionInvokeService#exec
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760003488569-94c79615-aaae-41a7-9559-0e3a30f1c046.png)

com.ufida.zior.console.ActionExecutor#exec
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760003637200-5e63d947-ee48-4a04-80fa-d5983a8df904.png)

跟进 nc.bs.pub.util.ProcessFileUtils，可以看到 openFile 和deleteFile 方法都是传入文件路径后直接命令进行拼接。

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760003774328-cb3a976c-6f7b-42cd-8ee7-a48501e7c037.png)

继续查看 ServletForGW#doAction 方法，硬编码身份验证后将用户输入转化为 JsonObject 对象，然后调用 callNCService 方法

com.yonyou.nccloud.gateway.adaptor.servlet.ServletForGW#doAction
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760061561269-a769f995-fb6d-4c45-8b44-ec96334d3c1a.png)

从 json 中取出一系列参数然后调用 MethodUtils.invokeMethod 方法，最终达到反射调用某个服务类方法的效果

com.yonyou.nccloud.gateway.adaptor.servlet.ServletForGW#callNCService
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760061709561-019d74a1-c04a-4c1c-9187-5702130e4a11.png)

org.apache.commons.beanutils.MethodUtils#invokeMethod
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760061843290-faf45b62-f88d-4d50-84fa-8287dfcd5a08.png)

结合上述的两个黑名单类即可实现命令执行的效果。

##### 漏洞复现：

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760062650307-3706b231-36da-4f52-a807-01d638463faa.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1760062621945-e8b7ffbb-1118-4e4e-8f7a-ab865c0095b4.png)
