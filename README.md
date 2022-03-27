# Myvas.AspNetCore.Authentication Family
* QQConnect: [Here](https://github.com/myvas/AspNetCore.Authentication.QQConnect)
* WeixinOpen: [Here](https://github.com/myvas/AspNetCore.Authentication.WeixinOpen)
* WeixinAuth: _this repo_

# What's this?
An ASP.NET Core authentication middleware for https://mp.weixin.qq.com （微信公众平台/网页授权登录）
* 须微信公众平台（mp.weixin.qq.com）已认证的服务号（或测试号）。
* 用户可在微信客户端访问网站时自动登入网站。换而言之，用户在微信客户端中访问网页时，可以通过此组件Challenge获取用户的OpenId或UnionId，据此可以识别用户。

# How to Use?
## 0.Create account
（1）在微信公众平台(https://mp.weixin.qq.com)上创建账号。

微信公众平台/网页授权获取用户信息，须在微信公众平台（mp.weixin.qq.com）上开通服务号，并认证。  
___注意：订阅号无网页授权权限，即使是已认证的订阅号也不行！___

（2）配置功能权限：微信公众平台-已认证服务号/开发/接口权限/...
- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置网页授权域名：例如，auth.myvas.com。
- 将文件MP_verify_xxxxxxxxx.txt上传至`wwwroot`目录下。

（3）当然，也可以在公众平台测试号上测试：微信公众平台-测试账号/开发/开发者工具/公众平台测试号/...
- 开通功能：网页服务/网页授权获取用户基本信息。
- 设置授权回调页面域名：例如，auth.myvas.com。

## 1.nuget
* [Myvas.AspNetCore.Authentication.WeixinAuth](https://www.nuget.org/packages/Myvas.AspNetCore.Authentication.WeixinAuth)

## 2.Configure
```csharp
    app.UseAuthentication();
```


## 3.ConfigureServices
```csharp
services.AddAuthentication()
    // using Myvas.AspNetCore.Authentication;
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
* [.NET Core SDK 6.0](https://dotnet.microsoft.com/en-us/download/dotnet/6.0)
* [微信开发者工具](https://mp.weixin.qq.com/debug/wxadoc/dev/devtools/download.html)

# Demo
* [Here](https://demo.auth.myvas.com)
