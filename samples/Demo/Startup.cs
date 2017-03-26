using System.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Text;
using System;
using AspNetCore.WeixinOAuth;

namespace Myvas.AspNetCore.Authentication.WeixinOAuth.Sample
{
    public class Startup
    {
        public IConfiguration Configuration { get; set; }

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json");

            if (env.IsDevelopment())
            {
                // For more details on using the user secret store see http://go.microsoft.com/fwlink/?LinkID=532709
                builder.AddUserSecrets<Startup>();
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options => options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Information);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                LoginPath = new PathString("/login")
            });

            var appId = Configuration["weixin:appid"];
            var appSecret = Configuration["weixin:appsecret"];
            bool useAdvancedScope = false;
            try { useAdvancedScope = Convert.ToBoolean(Configuration["weixin:useadvancedscope"]); } catch { }
            bool useQrcode = false;
            try { useQrcode = Convert.ToBoolean(Configuration["weixin:useqrcode"]); } catch { }
            app.UseWeixinOAuth(options =>
            {
                options.AppId = appId;
                options.AppSecret = appSecret;
                options.Scope.Add(WeixinOAuthScopes.snsapi_userinfo);
                options.SaveTokens = true;
                //AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpointQrcode,
            });

            // Choose an authentication type
            app.Map("/login", signoutApp =>
            {
                signoutApp.Run(async context =>
                {
                    var authType = context.Request.Query["authscheme"];
                    if (!string.IsNullOrEmpty(authType))
                    {
                        // By default the client will be redirect back to the URL that issued the challenge (/login?authtype=foo),
                        // send them to the home page instead (/).
                        await context.Authentication.ChallengeAsync(authType, new AuthenticationProperties() { RedirectUri = "/" });
                        return;
                    }

                    context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("Choose an authentication scheme: <br>");
                    foreach (var type in context.Authentication.GetAuthenticationSchemes())
                    {
                        await context.Response.WriteAsync("<a href=\"?authscheme=" + type.AuthenticationScheme + "\">" + (type.DisplayName ?? "(suppressed)") + "</a><br>");
                    }
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            // Sign-out to remove the user cookie.
            app.Map("/logout", signoutApp =>
            {
                signoutApp.Run(async context =>
                {
                    context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                    await context.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("You have been logged out. Goodbye " + context.User.Identity.Name + "<br>");
                    await context.Response.WriteAsync("<a href=\"/\">Home</a>");
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            // Display the remote error
            app.Map("/error", errorApp =>
            {
                errorApp.Run(async context =>
                {
                    context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                    await context.Response.WriteAsync("<html><body>");
                    await context.Response.WriteAsync("An remote failure has occurred: " + context.Request.Query["FailureMessage"] + "<br>");
                    await context.Response.WriteAsync("<a href=\"/\">Home</a>");
                    await context.Response.WriteAsync("</body></html>");
                });
            });

            app.Run(async context =>
                 {
                     // CookieAuthenticationOptions.AutomaticAuthenticate = true (default) causes User to be set
                     var user = context.User;

                     // This is what [Authorize] calls
                     // var user = await context.Authentication.AuthenticateAsync(AuthenticationManager.AutomaticScheme);

                     // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                     // var user = await context.Authentication.AuthenticateAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                     // Deny anonymous request beyond this point.
                     if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                     {
                         // This is what [Authorize] calls
                         // The cookie middleware will intercept this 401 and redirect to /login
                         await context.Authentication.ChallengeAsync();

                         // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
                         // await context.Authentication.ChallengeAsync(MicrosoftAccountDefaults.AuthenticationScheme);

                         return;
                     }

                     // Display user information
                     context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
                     await context.Response.WriteAsync("<html><body>");
                     await context.Response.WriteAsync("Hello " + (context.User.Identity.Name ?? "anonymous") + "<br>");
                     foreach (var claim in context.User.Claims)
                     {
                         await context.Response.WriteAsync(claim.Type + ": " + claim.Value + "<br>");
                     }

                     await context.Response.WriteAsync("Tokens:<br>");

                     await context.Response.WriteAsync("Access Token: " + await context.Authentication.GetTokenAsync("access_token") + "<br>");
                     await context.Response.WriteAsync("Refresh Token: " + await context.Authentication.GetTokenAsync("refresh_token") + "<br>");
                     await context.Response.WriteAsync("Token Type: " + await context.Authentication.GetTokenAsync("token_type") + "<br>");
                     await context.Response.WriteAsync("expires_at: " + await context.Authentication.GetTokenAsync("expires_at") + "<br>");
                     await context.Response.WriteAsync("<a href=\"/api/anonymousvisitor\">Anonymous Visitor</a><br>");
                     await context.Response.WriteAsync("<a href=\"/api/authorizedvisitor\">Authorized Visitor</a><br>");
                     await context.Response.WriteAsync("<a href=\"/logout\">Logout</a><br>");
                     await context.Response.WriteAsync("</body></html>");
                 });
        }
    }
}