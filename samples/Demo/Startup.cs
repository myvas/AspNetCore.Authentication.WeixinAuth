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
            _logger.LogDebug($"WeixinOpen:AppId: {Configuration["WeixinOpen:AppId"]}");
            _logger.LogDebug($"QcloudSms:SdkAppId: {Configuration["QcloudSms:SdkAppId"]}");
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<AppDbContext>(options =>
                options.UseInMemoryDatabase("WeixinOAuthInMemory"));

            services.AddIdentity<AppUser, IdentityRole>()
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

                options.SignIn.RequireConfirmedPhoneNumber = true;
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
            .AddWeixinOAuth(options =>
                {
                    options.AppId = Configuration["WeixinOAuth:AppId"];
                    options.AppSecret = Configuration["WeixinOAuth:AppSecret"];
                })
            .AddWeixinOpen(options =>
            {
                options.AppId = Configuration["WeixinOpen:AppId"];
                options.AppSecret = Configuration["WeixinOpen:AppSecret"];
            });

            // Add application services.
            services.AddQcloudSms(options =>
            {
                options.SdkAppId = Configuration["QcloudSms:SdkAppId"];
                options.AppKey = Configuration["QcloudSms:AppKey"];
            });

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
