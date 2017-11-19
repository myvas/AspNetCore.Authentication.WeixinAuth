using AspNetCore.WeixinOAuth.Demo.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Demo
{
    public class Startup
    {
        private readonly ILogger _logger;
        private IHostingEnvironment HostingEnvironment { get; }
        private IConfiguration Configuration { get; }

        private IConfiguration BuildConfiguration(IHostingEnvironment env)
        {
            var hostingConfigurationBuilder = new ConfigurationBuilder()
                .AddEnvironmentVariables(prefix: "ASPNETCORE_")
                //.AddEnvironmentVariables()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true)
                .AddJsonFile("logging.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"logging.{env.EnvironmentName}.json", optional: true, reloadOnChange: true)
                .AddUserSecrets<Startup>(true);

            return hostingConfigurationBuilder.Build();
        }

        public Startup(IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<Startup>();

            HostingEnvironment = env;
            _logger.LogDebug($"EnvironmentName: {env.EnvironmentName}");

            var configuration = BuildConfiguration(env);
            Configuration = configuration;
            _logger.LogDebug($"WeixinOAuth:AppId: {Configuration["WeixinOAuth:AppId"]}");
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<AppDbContext>(options =>
                options.UseInMemoryDatabase("WeixinOAuthInMemory"));
            services.AddMvc();

            services.AddIdentity<AppUser, IdentityRole>(config =>
                {
                    config.SignIn.RequireConfirmedPhoneNumber = true;
                })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
                {
                    options.Password = new PasswordOptions()
                    {
                        //RequiredLength = 8,
                        RequireLowercase = false,
                        RequireUppercase = false,
                        RequireNonAlphanumeric = false,
                        RequireDigit = false
                    };
                    options.Lockout = new LockoutOptions()
                    {
                        AllowedForNewUsers = false,
                        DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30),
                        MaxFailedAccessAttempts = 10
                    };

                    options.User.RequireUniqueEmail = false;

                    options.SignIn.RequireConfirmedPhoneNumber = false;
                    options.SignIn.RequireConfirmedEmail = false;
                });

            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/Account/Logout";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
                options.ExpireTimeSpan = TimeSpan.FromDays(150);
                options.SlidingExpiration = true;
                options.Cookie.HttpOnly = true;
                options.Cookie.Expiration = TimeSpan.FromDays(150);
            });

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = WeixinOAuthDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = WeixinOAuthDefaults.AuthenticationScheme;
                })
                .AddWeixinOAuth(options =>
                {
                    options.AppId = Configuration["WeixinOAuth:AppId"];
                    options.AppSecret = Configuration["WeixinOAuth:AppSecret"];
                    options.Scope.Add(WeixinOAuthScopes.snsapi_base);
                    options.Scope.Add(WeixinOAuthScopes.snsapi_userinfo);
                    options.SaveTokens = true;
                    options.Events = new Events.WeixinOAuthEvents()
                    {
                        OnCreatingTicket = async x =>
                        {
                            await Task.FromResult(0);
                            _logger.LogInformation("WeixinOAuth.OnCreatingTicket");
                        },
                        OnRemoteFailure = async x =>
                        {
                            await Task.FromResult(0);
                            _logger.LogInformation("WeixinOAuth.OnRemoteFailure");
                        },
                        OnTicketReceived = async context =>
                        {
                            await Task.FromResult(0);
                            _logger.LogInformation($"WeixinOAuth.OnTicketReceived: {context.Scheme.Name}");
                        },
                        OnRedirectToAuthorizationEndpoint = async context =>
                        {
                            await Task.FromResult(0);
                            _logger.LogInformation($"WeixinOAuth.OnRedirectToAuthorizationEndpoint to {context.RedirectUri}");
                            //如果这不是Weixin客户端，则显示一个二维码，让用户打开手机微信扫码登录。
                            //如果这是Weixin客户端，则直接访问微信身份验证服务端。
                            context.Response.Redirect(context.RedirectUri);
                        }
                    };
                });

            //var appId = Configuration["weixin:appid"];
            //var appSecret = Configuration["weixin:appsecret"];
            //bool useAdvancedScope = false;
            //try { useAdvancedScope = Convert.ToBoolean(Configuration["weixin:useadvancedscope"]); } catch { }
            //bool useQrcode = false;
            //try { useQrcode = Convert.ToBoolean(Configuration["weixin:useqrcode"]); } catch { }
            //app.UseWeixinOAuth(options =>
            //{
            //    options.AppId = appId;
            //    options.AppSecret = appSecret;
            //    options.Scope.Add(WeixinOAuthScopes.snsapi_userinfo);
            //    options.SaveTokens = true;
            //    //AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpointQrcode,
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseExceptionHandler("/Home/Error");

            app.UseStaticFiles();

            app.UseAuthentication();

            // Choose an authentication type
            //app.Map("/login", signoutApp =>
            //{
            //    signoutApp.Run(async context =>
            //    {
            //        var authType = context.Request.Query["authscheme"];
            //        if (!string.IsNullOrEmpty(authType))
            //        {
            //            // By default the client will be redirect back to the URL that issued the challenge (/login?authtype=foo),
            //            // send them to the home page instead (/).
            //            await context.ChallengeAsync(authType, new AuthenticationProperties() { RedirectUri = "/" });
            //            return;
            //        }

            //        context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
            //        await context.Response.WriteAsync("<html><body>");
            //        await context.Response.WriteAsync("Choose an authentication scheme: <br>");
            //        var schemeProvider = context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            //        foreach (var type in await schemeProvider.GetAllSchemesAsync())
            //        {
            //            await context.Response.WriteAsync("<a href=\"?authscheme=" + type.Name + "\">" + (type.DisplayName ?? "(suppressed)") + "</a><br>");
            //        }
            //        await context.Response.WriteAsync("</body></html>");
            //    });
            //});

            // Sign-out to remove the user cookie.
            //app.Map("/logout", signoutApp =>
            //{
            //    signoutApp.Run(async context =>
            //    {
            //        context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
            //        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            //        await context.Response.WriteAsync("<html><body>");
            //        await context.Response.WriteAsync("You have been logged out. Goodbye " + context.User.Identity.Name + "<br>");
            //        await context.Response.WriteAsync("<a href=\"/\">Home</a>");
            //        await context.Response.WriteAsync("</body></html>");
            //    });
            //});

            // Display the remote error
            //app.Map("/error", errorApp =>
            //{
            //    errorApp.Run(async context =>
            //    {
            //        context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
            //        await context.Response.WriteAsync("<html><body>");
            //        await context.Response.WriteAsync("An remote failure has occurred: " + context.Request.Query["FailureMessage"] + "<br>");
            //        await context.Response.WriteAsync("<a href=\"/\">Home</a>");
            //        await context.Response.WriteAsync("</body></html>");
            //    });
            //});

            //app.Run(async context =>
            //     {
            //         // CookieAuthenticationOptions.AutomaticAuthenticate = true (default) causes User to be set
            //         var user = context.User;

            //         // This is what [Authorize] calls
            //         // var user = await context.Authentication.AuthenticateAsync(AuthenticationManager.AutomaticScheme);

            //         // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
            //         // var user = await context.Authentication.AuthenticateAsync(MicrosoftAccountDefaults.AuthenticationScheme);

            //         // Deny anonymous request beyond this point.
            //         if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
            //         {
            //             // This is what [Authorize] calls
            //             // The cookie middleware will intercept this 401 and redirect to /login
            //             await context.ChallengeAsync();

            //             // This is what [Authorize(ActiveAuthenticationSchemes = MicrosoftAccountDefaults.AuthenticationScheme)] calls
            //             // await context.Authentication.ChallengeAsync(MicrosoftAccountDefaults.AuthenticationScheme);

            //             return;
            //         }

            //         // Display user informationforeach (var claim in context.User.Claims)
            //         {
            //             await context.Response.WriteAsync(claim.Type + ": " + claim.Value + "<br>");
            //         }
            //         context.Response.ContentType = $"text/html; charset={Encoding.UTF8.WebName}";
            //         await context.Response.WriteAsync("<html><body>");
            //         await context.Response.WriteAsync("Hello " + (context.User.Identity.Name ?? "anonymous") + "<br>");


            //         await context.Response.WriteAsync("Tokens:<br>");

            //         await context.Response.WriteAsync("Access Token: " + await context.GetTokenAsync("access_token") + "<br>");
            //         await context.Response.WriteAsync("Refresh Token: " + await context.GetTokenAsync("refresh_token") + "<br>");
            //         await context.Response.WriteAsync("Token Type: " + await context.GetTokenAsync("token_type") + "<br>");
            //         await context.Response.WriteAsync("expires_at: " + await context.GetTokenAsync("expires_at") + "<br>");
            //         await context.Response.WriteAsync("<a href=\"/api/anonymousvisitor\">Anonymous Visitor</a><br>");
            //         await context.Response.WriteAsync("<a href=\"/api/authorizedvisitor\">Authorized Visitor</a><br>");
            //         await context.Response.WriteAsync("<a href=\"/logout\">Logout</a><br>");
            //         await context.Response.WriteAsync("</body></html>");
            //     });

            app.UseMvcWithDefaultRoute();
        }
    }
}