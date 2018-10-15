# Myvas.AspNetCore.Authentication
A series of Authentication client middlewares.
- WeixinOpen for https://open.weixin.qq.com
- WeixinAuth for https://mp.weixin.qq.com
- QQConnect for https://connect.qq.com

## NuGet
https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.WeixinAuth
https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.WeixinOpen
https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.QQConnect

## Demo Online
- http://demo.auth.myvas.com (debian.8-x64)
- Qrcode to enter the demo weixin service account:

![alt QrCode](http://mmbiz.qpic.cn/mmbiz_jpg/lPe5drS9euRQR1eCK5cGXaibHYL6vBR4pGLB34ju2hXCiaMQiayOU8w5GMfEH7WZsVNTnhLTpnzAC9xfdWuTT89OA/0)

## How to Use
### ConfigureServices
```csharp
services.AddAuthentication()
    //微信网页登录，须mp.weixin.qq.com账号，微信内置浏览器用户访问网站时自动登入网站。（Scope: 静默方式snsapi_base, 用户确认方式snsapi_userinfo）
    .AddWeixinAuth(options => 
    {
        options.AppId = Configuration["WeixinAuth:AppId"];
        options.AppSecret = Configuration["WeixinAuth:AppSecret"];

        options.SilentMode = false; // default is true
    }
    // 微信开放平台登录：须open.weixin.qq.com账号网站应用接入，用户扫描微信二维码并确认后登入网站。
    .AddWeixinOpen(options => 
    {
        options.AppId = Configuration["WeixinOpen:AppId"];
        options.AppSecret = Configuration["WeixinOpen:AppSecret"];
    }
    // 腾讯QQ登录：须connect.qq.com账号网站应用接入，用户点击“QQ登录”图标按钮后使用QQ账号登入网站。
    .AddQQConnect(options => 
    {
        options.AppId = Configuration["QQConnect:AppId"];
        options.AppKey = Configuration["QQConnect:AppKey"];

        QQConnectScopes.TryAdd(options.Scope,
            QQConnectScopes.get_user_info,
            QQConnectScopes.list_album, //需要额外开通权限，暂未实现
            QQConnectScopes.upload_pic, //需要额外开通权限，暂未实现
            QQConnectScopes.do_like); //需要额外开通权限，暂未实现
    };
```

### ConfigureServices
```csharp
    app.UseAuthentication();
```

## How to Build
* Visual Studio 2017 v15.8.7+ and dotnet-sdk-2.1.403

## Dev Tools
* [微信开发者工具 v1.02.1806080](https://mp.weixin.qq.com/debug/wxadoc/dev/devtools/download.html)

# 微信开放平台/微信公众平台/QQ开放平台配置

### WeixinAuth
（1）微信公众平台-测试账号
/开发/开发者工具/公众平台测试号/...
- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好授权回调页面域名：例如，demo.auth.myvas.com。

（2）微信公众平台-正式账号
/开发/接口权限/...
- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好网页授权域名：例如，demo.auth.myvas.com。
- 将文件MP_verify_xxxxxxxxx.txt上传至wwwroot目录下。

### WeixinOpen
(TODO:在此添加配置说明)

### QQConnect
(TODO:在此添加配置说明）

