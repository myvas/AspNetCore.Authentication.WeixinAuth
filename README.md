# AspNetCore.WeixinOAuth
好消息！现在可以在.netcore 2.0下工作了，请参考Demo程序。

非常感谢您的关注！

## 程序配置
配置文件：appsettings.json，或secrets.json，后者若有配置则替换前者。
```csharp
{
  "WeixinOAuth:AppId": "wx02056e2b2b9cc4ef",
  "WeixinOAuth:AppSecret": "c175a359cd383213906bc3aa346fff2f"
}
```

## 微信公众号配置

### 当使用公众平台测试账号时：开发/开发者工具/公众平台测试号/进入/...
- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好授权回调页面域名（例如weixinoauth.myvas.com）。

### 当使用正式平台账号时：/开发/接口权限/...
- 开通功能：/网页服务/网页授权获取用户基本信息。
- 设置好网页授权域名（例如weixinoauth.myvas.com）。
- 将文件MP_verify_xxxxxxxxx.txt上传至wwwroot目录下。

## Demo程序
- Demo程序部署在：http://weixinoauth.myvas.com
OS: debian.8-x64

- 测试号二维码在这里：http://mmbiz.qpic.cn/mmbiz_jpg/lPe5drS9euRQR1eCK5cGXaibHYL6vBR4pGLB34ju2hXCiaMQiayOU8w5GMfEH7WZsVNTnhLTpnzAC9xfdWuTT89OA/0
测试人员须扫码关注这个公众号。

## 测试工具
- 微信开发者工具 v1.01.1711160
下载地址：https://mp.weixin.qq.com/debug/wxadoc/dev/devtools/download.html

- IDE
Visual Studio 2017 version 15.3 and aspnetcore 2.0
