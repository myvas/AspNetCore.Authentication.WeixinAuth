# Authentication Family
## 1.QQConnect
An ASP.NET Core authentication middleware: QQConnect for https://connect.qq.com (腾讯QQ互联平台/QQ登录）

腾讯QQ互联平台/QQ登录：须腾讯QQ互联平台（connect.qq.com）账号，用户通过点击“QQ登录”图标按钮，或使用手机QQ扫码登入网站。

* nuget: https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.QQConnect
* github: https://github.com/myvas/AspNetCore.Authentication.QQConnect


## 2.WeixinOpen
An ASP.NET Core authentication middleware: WeixinOpen for https://open.weixin.qq.com (微信开放平台/微信扫码登录)


微信开放平台/微信扫码登录：须微信开放平台(open.weixin.qq.com)账号，用户使用微信扫码并确认后登入网站。

* nuget: https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.WeixinOpen
* github: https://github.com/myvas/AspNetCore.Authentication.WeixinOpen

## 3.WeixinAuth
An ASP.NET Core authentication middleware: WeixinAuth for https://mp.weixin.qq.com （微信公众平台/网页授权登录）

微信公众平台/网页授权登录，须微信公众平台（mp.weixin.qq.com）已认证的服务号（或测试号），用户在微信客户端访问网站时自动登入网站。

* nuget: https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.WeixinAuth
* github: https://github.com/myvas/AspNetCore.Authentication.WeixinAuth

# How to Use
## Configure
```csharp
    app.UseAuthentication();
```

## ConfigureServices
1.QQConnect: 腾讯QQ互联平台(https://connect.qq.com)
创建应用（网站应用，移动应用），并指定网站回调地址（例如：https://www.myvas.com/signin-qqconnect )，记下AppId和AppKey。


```csharp
services.AddAuthentication()
    .AddQQConnect(options => 
    {
        options.AppId = Configuration["QQConnect:AppId"];
        options.AppKey = Configuration["QQConnect:AppKey"];

        options.CallbackPath = "/signin-qqconnect"; //默认

        QQConnectScopes.TryAdd(options.Scope,
            QQConnectScopes.get_user_info,
            QQConnectScopes.list_album, //需要额外开通权限，暂未实现
            QQConnectScopes.upload_pic, //需要额外开通权限，暂未实现
            QQConnectScopes.do_like); //需要额外开通权限，暂未实现
    };
```

2.WeixinOpen: 微信开放平台(https://open.weixin.qq.com)
创建网站应用，配置授权回调域（例如：auth.myvas.com )，记下AppId，获取AppSecret。


```csharp
services.AddAuthentication()
    .AddWeixinOpen(options => 
    {
        options.AppId = Configuration["WeixinOpen:AppId"];
        options.AppSecret = Configuration["WeixinOpen:AppSecret"];

        options.CallbackPath = "signin-weixinopen"; //默认
    };
```

3.WeixinAuth: 微信公众平台(https://mp.weixin.qq.com)

微信公众平台/网页授权获取用户信息，须在微信公众平台（mp.weixin.qq.com）上开通服务号，并认证。
___订阅号无网页授权权限，即使是已认证的订阅号也不行！___
用户在微信客户端中访问网页时，可以通过此组件Challenge后获取用户的OpenId或UnionId，据此可以识别用户。

（1）微信公众平台-测试账号/开发/开发者工具/公众平台测试号/...

- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好授权回调页面域名：例如，auth.myvas.com。

（2）微信公众平台-已认证服务号/开发/接口权限/...

- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置好网页授权域名：例如，auth.myvas.com。
- 将文件MP_verify_xxxxxxxxx.txt上传至wwwroot目录下。


```csharp
services.AddAuthentication()
    .AddWeixinAuth(options => 
    {
        options.AppId = Configuration["WeixinAuth:AppId"];
        options.AppSecret = Configuration["WeixinAuth:AppSecret"];

        options.SilentMode = false; // default is true
    };
```


```
说明：

(1)同一用户在同一微信公众号即使重复多次订阅/退订，其OpenId也不会改变。

(2)同一用户在不同微信公众号中的OpenId是不一样的。

(3)若同时运营了多个微信公众号，可以在微信开放平台上开通开发者账号，并在“管理中心/公众账号”中将这些公众号添加进去，就可以获取到同一用户在这些公众号中保持一致的UnionId。
```

# Dev
* [.NET Core SDK 2.1 LTS](https://dotnet.microsoft.com/download/dotnet-core/2.1) 2.1.802
* 下载[微信开发者工具](https://mp.weixin.qq.com/debug/wxadoc/dev/devtools/download.html)


# Demo Online
* github: https://github.com/myvas/AspNetCore.Authentication.Demo
* demo: https://demo.auth.myvas.com

![alt https://demo.auth.myvas.com Weixin QrCode](http://mmbiz.qpic.cn/mmbiz_jpg/lPe5drS9euRQR1eCK5cGXaibHYL6vBR4pGLB34ju2hXCiaMQiayOU8w5GMfEH7WZsVNTnhLTpnzAC9xfdWuTT89OA/0)
