# AspNetCore.Authentication
An serials of OAuth2.0 client middlewares to OAuth2.0 Servers.
- Tencent Weixin Open (open.weixin.qq.com)
- Tencent Weixin Auth (mp.weixin.qq.com)
- Tencent QQ Connect (connect.qq.com)

## Demo Online
- http://demo.auth.myvas.com (debian.8-x64)

- Qrcode to enter the demo weixin service account:
![alt QrCode](http://mmbiz.qpic.cn/mmbiz_jpg/lPe5drS9euRQR1eCK5cGXaibHYL6vBR4pGLB34ju2hXCiaMQiayOU8w5GMfEH7WZsVNTnhLTpnzAC9xfdWuTT89OA/0)

## How to Use
### NuGet
https://www.nuget.org/packages/AspNetCore.Authentication.WeixinAuth
https://www.nuget.org/packages/AspNetCore.Authentication.WeixinOpen
https://www.nuget.org/packages/AspNetCore.Authentication.QQ

### Startup/ConfigureServices()
```csharp
services.AddAuthentication()
    //微信网页登录，须mp.weixin.qq.com账号，微信内置浏览器用户访问网站时自动登入网站。（Scope: 静默方式snsapi_base, 用户确认方式snsapi_userinfo）
    .AddWeixinAuth(options => 
    {
        options.AppId = Configuration["WeixinAuth:AppId"];
        options.AppSecret = Configuration["WeixinAuth:AppSecret"];
        options.UseSilentMode = Configuration["WeixinAuth:UseSilentMode"]; //使用静默方式无须用户确认，无UserInfo信息。默认不使用静默方式。
        options.SaveTokens = true;
    }
    // 微信开放平台登录：须open.weixin.qq.com账号网站应用接入，用户扫描微信二维码并确认后登入网站。
    .AddWeixinOpen(options => 
    {
        options.AppId = Configuration["WeixinOpen:AppId"];
        options.AppSecret = Configuration["WeixinOpen:AppSecret"];
        options.SaveTokens = true;
    }
    // 腾讯QQ登录：须connect.qq.com账号网站应用接入，用户点击“QQ登录”图标按钮后使用QQ账号登入网站。
    .AddQQ(options => 
    {
        options.AppId = Configuration["QQ:AppId"];
        options.AppKey = Configuration["QQ:AppSecret"];
    };
```

## How to Build
* Visual Studio 2017 v15.8.2+
* [.NET Core SDK v2.1.403+](https://www.microsoft.com/net/download)

## Dev Tools
* [微信开发者工具 v1.02.1806080](https://mp.weixin.qq.com/debug/wxadoc/dev/devtools/download.html)

# 微信公众号配置介绍

### 当使用公众平台测试账号时：
开发/开发者工具/公众平台测试号/进入/...
- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好授权回调页面域名：例如，weixinoauth.myvas.com。

### 当使用正式平台账号时：
开发/接口权限/...
- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好网页授权域名：例如，weixinoauth.myvas.com。
- 将文件MP_verify_xxxxxxxxx.txt上传至wwwroot目录下。
