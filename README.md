# AspNetCore.WeixinOAuth
An OAuth client middleware to Tencent WeChat (AKA Weixin) Authorization Server.

## Configuration
Configuration Files: appsettings.json or secrets.json

For WeixinOAuth:
```csharp
{
  "WeixinOAuth:AppId": "wx02056e2b2b9cc4ef",
  "WeixinOAuth:AppSecret": "c175a359cd383213906bc3aa346fff2f"
}
```

For WeixinOpen
```csharp
{
  "WeixinOpen:AppId": "wx................",
  "WeixinOpen:AppSecret": "................................"
}
```

## ConfigureServices

```csharp
services.AddAuthentication()
//For serve with  with mp.weixin.qq.com account, to automatic challenge in WeChat built-in browser, or WeChat DevTools.
.AddWeixinOAuth(options => 
{
    options.AppId = Configuration["WeixinOAuth:AppId"];
    options.AppSecret = Configuration["WeixinOAuth:AppSecret"];
	options.SaveTokens = true;
}
// For serve with open.weixin.qq.com account, to scan a WeChat QR code to sign in.
.AddWeixinOpen(options => 
{
    options.AppId = Configuration["WeixinOpen:AppId"];
    options.AppSecret = Configuration["WeixinOpen:AppSecret"];
    options.SaveTokens = true;
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

## Demo
- Deploy on a debian.8-x64 server: http://weixinoauth.myvas.com

- QrCode: http://mmbiz.qpic.cn/mmbiz_jpg/lPe5drS9euRQR1eCK5cGXaibHYL6vBR4pGLB34ju2hXCiaMQiayOU8w5GMfEH7WZsVNTnhLTpnzAC9xfdWuTT89OA/0

All users must be subscribers for that Open WeChat Service Account.

## IDE & Dev Tools
* [微信开发者工具 v1.01.1711160](https://mp.weixin.qq.com/debug/wxadoc/dev/devtools/download.html)

- IDE
Visual Studio 2017 version 15.3 and aspnetcore 2.0
