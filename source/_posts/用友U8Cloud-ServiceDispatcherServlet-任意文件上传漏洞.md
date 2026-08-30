---
title: 用友U8Cloud ServiceDispatcherServlet 任意文件上传漏洞
date: 2025-07-30 12:00:00
tags:
  - 漏洞分析
---

##### 环境搭建：
漏洞未使用数据库功能，直接运行 u8csetup.bat 安装

再运行 startup.bat 启动服务即可

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753864667034-f8d5b8e5-db78-4083-88d6-3e4b80d7eb8b.png)

##### 漏洞分析：
根据漏洞描述：可知是 ServiceDispatcherServlet 并且存在相关鉴权的绕过

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753865124347-b44bf37f-e442-4290-83a2-74f2a1a9ed6a.png)

根据漏洞补丁对比：修复了一个文件上传方法 nc.impl.hr.tools.trans.FileTransImpl#uploadFile

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753865268974-496c7880-32bb-4469-9ad5-ef7c3f74d65d.png)

在 web.xml 中查找 ServiceDispatcherServlet 对应关系

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753865543854-3dad695c-4ef0-40c8-85c5-6005c629553d.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753865583169-6c66c88b-0b36-4258-b4f7-20156d95ab02.png)

跟进到主要的处理方法，invInfo 通过 readObject() 方法从 HTTP 请求的输入流中反序列化生成，在经过 TokenUtil 权限校验后，通过反射机制动态调用对应的业务方法。

nc.bs.framework.comn.serv.ServiceDispatcher#execCall
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753866206731-3411b3bf-3157-4754-9b75-1f2213882471.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753866425644-7b2b4d18-63bb-4e36-bf2a-d5a1c7554850.png)

跟进权限校验 TokenUtil.getInstance().vertifyToken() 方法，使用 getTokenSeed() 和传入的 userCode 进行相关加密操作然后和传入的 token 对比。

nc.bs.framework.server.token.TokenUtil#vertifyTokenIllegal
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753867508806-fd643ad9-848d-451d-bafc-1a9155a77e2a.png)

而 getTokenSeed() 获取的是 /ierp/bin/token/tokenSeed.conf 文件中的硬编码字符串。

nc.bs.framework.server.token.TokenUtil#TokenUtil
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753867800859-a256aa2b-c5e6-4602-a5b0-20cad9e86fe2.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753867960872-47e450c6-3dc2-4347-afa5-3b99fb13ad73.png)

继续跟进this.invokeBeanMethod()方法，当moudle为空，就会反射调用传入的方法。

nc.bs.framework.comn.serv.ServiceDispatcher#invokeBeanMethod
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753868272875-d51dc3d4-2385-478b-8a98-83038f5a6ac8.png)

结合补丁的 nc.itf.hr.tools.IFileTrans.uploadFile 方法构造恶意的InvocationInfo对象就可以实现文件上传。
##### 漏洞复现：
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1753870142085-9c538552-94c3-40f4-91d2-372a74ba0ced.png)
