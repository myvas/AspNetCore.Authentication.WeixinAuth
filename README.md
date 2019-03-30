# AspNetCore.Authentication.WeixinAuth
An ASP.NET Core authentication middleware: WeixinAuth for https://mp.weixin.qq.com （微信公众平台/网页授权身份验证）

微信公众平台/网页授权获取用户信息，须在微信公众平台（mp.weixin.qq.com）上开通服务号，并认证。___订阅号无网页授权权限，即使是已认证的订阅号也不行！___

用户在微信客户端中访问网页时，可以通过此组件Challenge后获取用户的OpenId或UnionId，据此可以识别用户。

---
说明：

(1)同一用户在同一微信公众号中多次订阅/退订后，OpenId不变。

(2)同一用户在不同微信公众号中的OpenId是不一样的。

(3)若同时运营了多个微信公众号，可以在微信开放平台上开通开发者账号，并在“管理中心/公众账号”中将这些公众号添加进去，就可以获取到同一用户在这些公众号中保持一致的UnionId。
---

* nuget: https://www.nuget.org/packages/AspNetCore.Authentication.WeixinAuth
* github: https://github.com/myvas/AspNetCore.Authentication.WeixinAuth

# AspNetCore.Authentication Family
## 1.AspNetCore.Authentication.WeixinOpen
An ASP.NET Core authentication middleware: WeixinOpen for https://open.weixin.qq.com (微信开放平台/微信扫码登录)

微信开放平台/微信扫码登录：须在微信开放平台（open.weixin.qq.com）上开通账号，并添加网站应用。

用户使用微信扫码并确认后登入网站。

* nuget: https://www.nuget.org/packages/AspNetCore.Authentication.WeixinOpen
* github: https://github.com/myvas/AspNetCore.Authentication.WeixinOpen

## 2.AspNetCore.Authentication.QQConnect
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
