using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Myvas.AspNetCore.Authentication;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace UnitTest.TestServers
{
	internal class TestServerBuilder
    {
        public static readonly string DefaultAuthority = @"https://login.microsoftonline.com/common";
        public static readonly string TestHost = @"https://example.com";
        public static readonly string Challenge = "/challenge";
        public static readonly string ChallengeWithOutContext = "/challengeWithOutContext";
        public static readonly string ChallengeWithProperties = "/challengeWithProperties";
        public static readonly string Signin = "/signin";
        public static readonly string Signout = "/signout";

        public static WeixinAuthOptions CreateWeixinOpenOptions() =>
            new WeixinAuthOptions
			{
                AppId = "Test Id",
                AppSecret = "Test Secret"
                //o.SignInScheme = "auth1";//WeixinOpenDefaults.AuthenticationScheme
            };

        public static WeixinAuthOptions CreateWeixinOpenOptions(Action<WeixinAuthOptions> update)
        {
            var options = CreateWeixinOpenOptions();
            update?.Invoke(options);
            return options;
        }

        public static TestServer CreateServer(Action<WeixinAuthOptions> options)
        {
            return CreateServer(options, handler: null, properties: null);
        }

        public static TestServer CreateServer(
            Action<WeixinAuthOptions> options,
            Func<HttpContext, Task> handler,
            AuthenticationProperties properties)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseAuthentication();
                    app.Use(async (context, next) =>
                    {
                        var req = context.Request;
                        var res = context.Response;

                        if (req.Path == new PathString(Challenge))
                        {
                            await context.ChallengeAsync(WeixinAuthDefaults.AuthenticationScheme);
                        }
                        else if (req.Path == new PathString(ChallengeWithProperties))
                        {
                            await context.ChallengeAsync(WeixinAuthDefaults.AuthenticationScheme, properties);
                        }
                        else if (req.Path == new PathString(ChallengeWithOutContext))
                        {
                            res.StatusCode = 401;
                        }
                        else if (req.Path == new PathString(Signin))
                        {
                            await context.SignInAsync(WeixinAuthDefaults.AuthenticationScheme, new ClaimsPrincipal());
                        }
                        else if (req.Path == new PathString(Signout))
                        {
                            await context.SignOutAsync(WeixinAuthDefaults.AuthenticationScheme);
                        }
                        else if (req.Path == new PathString("/signout_with_specific_redirect_uri"))
                        {
                            await context.SignOutAsync(
                                WeixinAuthDefaults.AuthenticationScheme,
                                new AuthenticationProperties() { RedirectUri = "http://www.example.com/specific_redirect_uri" });
                        }
                        else if (handler != null)
                        {
                            await handler(context);
                        }
                        else
                        {
                            await next();
                        }
                    });
                })
                .ConfigureServices(services =>
                {
                    services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                        .AddCookie()
                        .AddWeixinAuth(options);
                });

            return new TestServer(builder);
        }
    }


}
