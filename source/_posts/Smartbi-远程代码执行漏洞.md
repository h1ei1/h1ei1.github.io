---
title: Smartbi 远程代码执行漏洞
date: 2025-08-19 12:00:00
tags:
  - 漏洞分析
---

##### 环境搭建：
搭建参考：https://wiki.smartbi.com.cn/pages/viewpage.action?pageId=114987452

访问 http://ip:18080/smartbi/vision/index.jsp
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755588641674-bcb8ee17-3c8f-444f-83de-8ecdd9997f75.png)

##### 漏洞分析：
下载漏洞补丁：

https://www.smartbi.com.cn/patchinfo
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755588856199-0f7d2243-4a5b-430d-b40a-65ec28318d14.png)

使用如下脚本解密，得到压缩文件后解压

```plain
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode

def decrypt_aes_file(input_file, output_file, key=b'1234567812345678', iv=b'1234567812345678'):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_file, 'rb') as f_in:
        encrypted_data = f_in.read()
        decoded_data = b64decode(encrypted_data)
        decrypted_data = unpad(cipher.decrypt(decoded_data), AES.block_size)
    with open(output_file, 'wb') as f_out:
        f_out.write(decrypted_data)

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', type=str, default="patch.patches", help="Path to file name.")
args = parser.parse_args()

filename = "decrypted-"+args.file+".zip"

decrypt_aes_file(args.file, filename)
print("[+] OutPut: " + filename)
```

查看 patch.patchs 补丁文件，根据漏洞描述猜测权限绕过发生在 /vision/share.jsp 文件中

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755596816281-12dc96d2-3b60-4017-8acd-c99c4ef0301e.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755591275192-47ff09e4-e17c-48e2-b21b-e86431e79775.png)

继续跟进，只需要满足条件 shareService.isPublicShareResourceByShareType(resid, sharetype)，并且让 JSONObject result = shareService.getShareRestrictByShareType(resid, sharetype) 的结果为 false 就可以直接调用 UserManagerModule.getInstance().autoLoginByPublicUser() 来获取合法Session。

/smartbi/vision/share.jsp
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755593001979-16f625bc-ec88-492e-96ae-379bfefb2e5c.png)

继续跟进 shareService.isPublicShareResourceByShareType(resid, sharetype)，满足根据 relateid (也就是resid) 查询到的 shareRecord 不为空且 Publicshared 为1就会返回 true

smartbi.module.socialcontactshare.SocialContactShareService#isPublicShareResourceByShareType
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755594000764-8eaf950e-455c-4668-a6c0-8cf337bf6af8.png)

在 smartbi 数据库 t_share_record 表中查询两个满足条件的 relateid 值：96a0a9d0b86f90d5416d013f4cfe2f23 和 b904ab9f5a84712a672523a7b4881ee4

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755594269616-337566c0-419f-4fde-bb55-f9e48daf90e8.png)

继续跟进 shareService.getShareRestrictByShareType(resid, sharetype)，当 shareType 为空就调用 this.shareRestrict(relateid, (String)null, (String)null, (String)null)

smartbi.module.socialcontactshare.SocialContactShareService#getShareRestrictByShareType
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755594757746-bc245619-7a29-44d5-a319-555dd828bb5f.png)

在 shareRestrict() 方法的条件判断中 shareRecord.getCode() 获取数据库 t_share_record 表中的值为空，所以最终返回false。

smartbi.module.socialcontactshare.SocialContactShareService#shareRestrict
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755594965203-983f9e54-3ef4-4565-8f54-6bd854ca1919.png)

最终使用以下http请求获得合法 public 用户 Session

```plain
GET /smartbi/vision/share.jsp?resid=b904ab9f5a84712a672523a7b4881ee4 HTTP/1.1
Host: 192.168.211.252:18080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36
```

在 patch.patchs 6月份的补丁中搜索到了一个明显的关键字

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755596087704-b83f7262-46c2-4605-97a7-4dd6799a47f4.png)

搜索相关方法，可以看到不需要admin权限，并直接调用js引擎执行了传入的表达式。

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755596189952-4fbc1ec3-e094-477e-afdb-1561abc4b66f.png)

而 Smartbi 的smartbi.framework.rmi.RMIServlet 可以通过 smartbi.framework.rmi.ClientService#executeInternal 反射调用任何方法，不再赘述。

##### 漏洞复现：
![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755596537825-5e1bfa86-dd49-4430-a56d-707047d4dbfc.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755596553790-26198ab3-9dbd-43e1-8239-b45b74bd1f08.png)

![](https://cdn.nlark.com/yuque/0/2025/png/22387372/1755596568667-5bcdf486-3628-4130-8ee5-7b57c0f7989a.png)
