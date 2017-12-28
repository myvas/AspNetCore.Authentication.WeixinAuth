using AspNetCore.QcloudSms;
using AspNetCore.ViewDivertMiddleware;
using Demo;
using Demo.Models;
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
                .AddWeixinOpen(options => {
                    options.AppId = _configuration["WeixinOpen:AppId"];
                    options.AppSecret = _configuration["WeixinOpen:AppSecret"];
                })
                .AddWeixinOAuth(options =>
                {
                    options.AppId = _configuration["WeixinAuth:AppId"];
                    options.AppSecret = _configuration["WeixinAuth:AppSecret"];
                });
            services.AddQcloudSms(options =>
            {
                options.SdkAppId = _configuration["QcloudSms:SdkAppId"];
                options.AppKey = _configuration["QcloudSms:AppKey"];
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
