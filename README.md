# AspNetCore.WeixinOAuth
An OAuth client middleware to Tencent WeChat (AKA Weixin) Authorization Server.

# Demo
http://weixinoauth.myvas.com

## NuGet
```csharp
> dotnet add package AspNetCore.WeixinOAuth
```

## Configuration
Configuration Files: appsettings.json -> secrets.json -> appsettings.{EnvironmentName}.json

Here "A -> B" means "values in A will be replaced by B with the same key"

For WeixinAuth/mp.weixin.qq.com:
```csharp
{
  "WeixinAuth:AppId": "wx................",
  "WeixinAuth:AppSecret": "................................"
}
```

For WeixinOpen/open.weixin.qq.com
```csharp
{
  "WeixinOpen:AppId": "wx................",
  "WeixinOpen:AppSecret": "................................"
}
```

## ConfigureServices

```csharp
services.AddAuthentication()
//For mp.weixin.qq.com account, a common use case is to automatic challenge in WeChat built-in browser or WeChat DevTools.
.AddWeixinOAuth(options => 
{
    options.AppId = Configuration["WeixinAuth:AppId"];
    options.AppSecret = Configuration["WeixinAuth:AppSecret"];
    options.SaveTokens = true;
}
// For open.weixin.qq.com account, a common use case is to scan a WeChat QR code to sign in.
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

- QrCode: ![alt QrCode](http://mmbiz.qpic.cn/mmbiz_jpg/lPe5drS9euRQR1eCK5cGXaibHYL6vBR4pGLB34ju2hXCiaMQiayOU8w5GMfEH7WZsVNTnhLTpnzAC9xfdWuTT89OA/0)

All users must be subscribers for that Open WeChat Service Account.

## IDE & Dev Tools
* [微信开发者工具 v1.02.1806080](https://mp.weixin.qq.com/debug/wxadoc/dev/devtools/download.html)

- IDE
Visual Studio 2017 version 15.7.3 and aspnetcore 2.1
