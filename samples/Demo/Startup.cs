using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using AspNetCore.WeixinOAuth.Demo.Data;
using AspNetCore.WeixinOAuth.Demo.Models;
using AspNetCore.WeixinOAuth.Demo.Services;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Extensions;
using AspNetCore.ViewDivertMiddleware;

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
                            if (!AgentResolver.IsMicroMessenger(context.HttpContext))
                            {
                                var q = new QueryBuilder();
                                q.Add("redirectUrl", context.RedirectUri);
                                var qrlogin = string.Concat(
                                    context.Request.Scheme,
                                    "://",
                                    context.Request.Host.ToUriComponent(),
                                    context.Request.PathBase.ToUriComponent(),
                                     "/Account/LoginQr",
                                      q.ToQueryString().ToUriComponent());
                                context.Response.Redirect(qrlogin);
                            }
                            else
                            {
                                //如果这是Weixin客户端，则直接访问微信身份验证服务端。
                                context.Response.Redirect(context.RedirectUri);
                            }
                        }
                    };
                });

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();

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
