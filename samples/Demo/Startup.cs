using Demo.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Myvas.AspNetCore.Authentication;

namespace Demo
{
	public class Startup
	{
		public IConfiguration Configuration { get; }

		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//services.AddDbContext<AppDbContext>(options => options.UseInMemoryDatabase("WeixinAuthDemo"));
			services.AddDbContext<AppDbContext>(options => options.UseSqlite(Configuration.GetConnectionString("DefaultConnection")));

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
					options.AppId = Configuration["WeixinOpen:AppId"];
					options.AppSecret = Configuration["WeixinOpen:AppSecret"];
					options.SaveTokens = true;
				})
				.AddWeixinAuth(options =>
				{
					options.AppId = Configuration["WeixinAuth:AppId"];
					options.AppSecret = Configuration["WeixinAuth:AppSecret"];
					options.SilentMode = false; //不采用静默模式
												//options.SaveTokens = true;
				})
				.AddQQConnect(options =>
				{
					options.AppId = Configuration["QQConnect:AppId"];
					options.AppKey = Configuration["QQConnect:AppKey"];
					//options.SaveTokens = true;

					QQConnectScopes.TryAdd(options.Scope,
						QQConnectScopes.get_user_info,
						QQConnectScopes.list_album,
						QQConnectScopes.upload_pic,
						QQConnectScopes.do_like);
				});

			services.AddTencentSms(options =>
			{
				options.SdkAppId = Configuration["TencentSms:SdkAppId"];
				options.AppKey = Configuration["TencentSms:AppKey"];
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
