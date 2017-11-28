using AspNetCore.QcloudSms;
using AspNetCore.ViewDivertMiddleware;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using System.Web;

namespace AspNetCore.WeixinOAuth.Demo
{
    public class Startup
    {
        private readonly ILogger _logger;
        private IHostingEnvironment HostingEnvironment { get; }
        private IConfiguration Configuration { get; }

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
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<AppDbContext>(options =>
                options.UseInMemoryDatabase("WeixinOAuthInMemory"));

            services.AddIdentity<AppUser, IdentityRole>(config =>
                {
                    config.SignIn.RequireConfirmedPhoneNumber = true;
                })
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();
            services.TryAddScoped<AppUserStore, AppUserStore>();
            services.TryAddScoped<AppUserManager, AppUserManager>();

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
                    //options.DefaultAuthenticateScheme = WeixinOAuthDefaults.AuthenticationScheme;
                    //options.DefaultChallengeScheme = WeixinOAuthDefaults.AuthenticationScheme;
                    //options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
                })
                .AddWeixinOAuth(WeixinOAuthDefaults.AuthenticationScheme, options =>
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
                             //如果这不是Weixin客户端，则显示一个二维码，让用户打开手机微信扫码登录。
                             if (!AgentResolver.IsMicroMessenger(context.HttpContext))
                             {
                                 //context.RedirectUrl: https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx02056e2b2b9cc4ef&redirect_uri=http%3A%2F%2Fweixinoauth.myvas.com%2Fsignin-weixin-oauth&response_type=code&scope=snsapi_base,snsapi_userinfo&state=hlaz9Ax5dLqCgM1RIzeemjcK08SIgMeeEUYGBU4E5bk&uin=MzcyMzAzOTM3&key=acf9e0498e32d7d7fa3ffe92fa608a68dd67388b3bf82257d1041999a8846282b9c6338acbde623ef3dc37ea23982a89&pass_ticket=ySQZsimUMA6UQWWQROGDk0bQT6Kxn23KQ/o+ZLYDVdl+Lid/fZcqe9TNfBe9Q2x0im9I7M/Okr6BHeCk4Phqrg==
                                 var authorizeUri = new Uri(context.RedirectUri);
                                 var appid = HttpUtility.ParseQueryString(authorizeUri.Query).Get("appid");
                                 var authorizeCallbackUrl = HttpUtility.ParseQueryString(authorizeUri.Query).Get("redirect_uri");
                                 var state = HttpUtility.ParseQueryString(authorizeUri.Query).Get("state");

                                 var q = new QueryBuilder();
                                 q.Add("appid", appid);
                                 q.Add("redirect_uri", authorizeCallbackUrl);
                                 q.Add("response_type", "code");
                                 q.Add("scope", "snsapi_login");
                                 q.Add("state", state);
                                 var waitForCallback = string.Concat(
                                     "https://open.weixin.qq.com/connect/qrconnect",
                                     q.ToQueryString().ToUriComponent(),
                                     "#wechat_redirect");

                                 //var qrid = ShortGuid.NewGuid().ToString();
                                 //q.Add("returnUrl", string.Concat(
                                 //    context.Request.Scheme,
                                 //    "://",
                                 //    context.Request.Host.ToUriComponent(),
                                 //    context.Request.PathBase.ToUriComponent()));

                                 //var waitForCallback = string.Concat(
                                 //    context.Request.Scheme,
                                 //    "://",
                                 //    context.Request.Host.ToUriComponent(),
                                 //    context.Request.PathBase.ToUriComponent(),
                                 //     "/Account/WaitForExternalLoginWithQr",
                                 //      q.ToQueryString().ToUriComponent());
                                 //_logger.LogInformation($"WeixinOAuth.OnRedirectToAuthorizationEndpoint to {waitForCallback}");
                                 context.Response.Redirect(waitForCallback);
                             }
                             else
                             {
                                 //如果这是Weixin客户端，则直接访问微信身份验证服务端。
                                 _logger.LogInformation($"WeixinOAuth.OnRedirectToAuthorizationEndpoint to {context.RedirectUri}");
                                 context.Response.Redirect(context.RedirectUri);
                             }
                         }
                     };
                 });

            // Add application services.
            services.AddDebugQcloudSms();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }

        #region Helpers
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
        #endregion
    }
}
