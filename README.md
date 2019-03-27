# AspNetCore.Authentication.WeixinAuth
An ASP.NET Core authentication middleware: WeixinAuth for https://mp.weixin.qq.com （微信公众平台/微信网页授权登录）

微信公众号/微信网页授权登录，须mp.weixin.qq.com账号，微信内置浏览器用户访问网站时自动登入网站。

* nuget: https://www.nuget.org/packages/AspNetCore.Authentication.WeixinAuth
* github: https://github.com/myvas/AspNetCore.Authentication.WeixinAuth

# Brothers and sisters
## AspNetCore.Authentication.WeixinOpen
An ASP.NET Core authentication middleware: WeixinOpen for https://open.weixin.qq.com (微信开放平台/微信扫码登录)


微信开放平台/微信扫码登录：须open.weixin.qq.com账号网站应用接入，用户使用微信扫码并确认后登入网站。

* nuget: https://www.nuget.org/packages/AspNetCore.Authentication.WeixinOpen
* github: https://github.com/myvas/AspNetCore.Authentication.WeixinOpen


# AspNetCore.Authentication.QQConnect
An ASP.NET Core authentication middleware: QQConnect for https://connect.qq.com (腾讯QQ互联/QQ登录）

腾讯QQ互联/QQ登录：用户通过点击“QQ登录”图标按钮，或使用手机QQ扫码登入网站。

* nuget: https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.QQConnect
* github: https://github.com/myvas/AspNetCore.Authentication.QQConnect

## Demo Online
* github: https://github.com/myvas/AspNetCore.Authentication.Demo
* demo: https://demo.auth.myvas.com

![alt https://demo.auth.myvas.com Weixin QrCode](http://mmbiz.qpic.cn/mmbiz_jpg/lPe5drS9euRQR1eCK5cGXaibHYL6vBR4pGLB34ju2hXCiaMQiayOU8w5GMfEH7WZsVNTnhLTpnzAC9xfdWuTT89OA/0)

## How to Use
### 微信公众平台
https://mp.weixin.qq.com

（1）微信公众平台-测试账号

/开发/开发者工具/公众平台测试号/...

- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好授权回调页面域名：例如，auth.myvas.com。

（2）微信公众平台-正式账号

/开发/接口权限/...

- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好网页授权域名：例如，auth.myvas.com。
- 将文件MP_verify_xxxxxxxxx.txt上传至wwwroot目录下。

### ConfigureServices
```csharp
services.AddAuthentication()
    //微信网页登录，须mp.weixin.qq.com账号，微信内置浏览器用户访问网站时自动登入网站。
    .AddWeixinAuth(options => 
    {
        options.AppId = Configuration["WeixinAuth:AppId"];
        options.AppSecret = Configuration["WeixinAuth:AppSecret"];

        options.SilentMode = false; // default is true
    };
```

### Configure
```csharp
    app.UseAuthentication();
```

### Dev
* .NET Core SDK 2.1.505