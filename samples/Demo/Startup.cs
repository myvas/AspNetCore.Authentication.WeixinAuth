using AspNetCore.Authentication.QQConnect;
using AspNetCore.TencentSms;
using Demo;
using Demo.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Demo
{
    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddDbContext<AppDbContext>(options => options.UseInMemoryDatabase("WeixinAuthDemo"));
            services.AddDbContext<AppDbContext>(options => options.UseSqlite(_configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<AppUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddUserManager<AppUserManager>()
                .AddSignInManager<SignInManager<AppUser>>()
                .AddDefaultTokenProviders();
            services.Configure<IdentityOptions>(options =>
            {
                options.Password = new PasswordOptions
                {
                    RequireLowercase = false,
                    RequireUppercase = false,
                    RequireNonAlphanumeric = false,
                    RequireDigit = false
                };
                options.User.RequireUniqueEmail = false;
                options.SignIn.RequireConfirmedEmail = false;

                options.SignIn.RequireConfirmedPhoneNumber = true;
            });
            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/Account/LogOff";
                options.AccessDeniedPath = "/Account/AccessDenied";
            });

            services.AddAuthentication()
                .AddWeixinOpen(options =>
                {
                    options.AppId = _configuration["WeixinOpen:AppId"];
                    options.AppSecret = _configuration["WeixinOpen:AppSecret"];
                    options.SaveTokens = true;
                })
                .AddWeixinAuth(options =>
                {
                    options.AppId = _configuration["WeixinAuth:AppId"];
                    options.AppSecret = _configuration["WeixinAuth:AppSecret"];
                    //options.SaveTokens = true;
                })
                .AddQQConnect(options =>
                {
                    options.AppId = _configuration["QQConnect:AppId"];
                    options.AppKey = _configuration["QQConnect:AppKey"];
                    //options.SaveTokens = true;

                    QQConnectScopes.TryAdd(options.Scope,
                        QQConnectScopes.Items.get_user_info,
                        QQConnectScopes.Items.list_album,
                        QQConnectScopes.Items.upload_pic,
                        QQConnectScopes.Items.do_like);
                });

            services.AddTencentSms(options =>
            {
                options.SdkAppId = _configuration["TencentSms:SdkAppId"];
                options.AppKey = _configuration["TencentSms:AppKey"];
            });

            services.AddViewDivert();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
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
    }
}
