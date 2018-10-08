using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Demo.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Demo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args)
                .Build()
                .MigrateDatabase()
                .SeedDatabase()
                .Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args)
            => new WebHostBuilder()
                .UseKestrel()
                .UseContentRoot(Directory.GetCurrentDirectory())

                .ConfigureAppConfiguration(ConfigureAppConfiguration)
                .ConfigureLogging(ConfigureLogging)

                .UseIISIntegration()
                .UseDefaultServiceProvider(DefaultServiceProvider)
                //.CaptureStartupErrors(true)
                .UseStartup<Startup>();

        private static void ConfigureAppConfiguration(WebHostBuilderContext hostingContext, IConfigurationBuilder config)
        {
            var env = hostingContext.HostingEnvironment;
            var environmentName = env.EnvironmentName;

            //1。使用默认配置文件。源码可见。通常直接在字段中填写配置说明。
            //2。使用secret.json。通常，不论是在开发者个人机，测试服务器，还是正式部署的服务器上，应当使用此配置文件。
            //3。在数据库开发者的个人机上，通常需要在Development和Production两种模式中频繁切换，此时我们可以创建x.Development.json来替换secret.json中的配置。
            //4。除了Development具有替换secret.json的能力，其他Environment也可能需要这种替换能力。
            config.SetBasePath(Directory.GetCurrentDirectory())
                //.SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
                .AddUserSecrets<Startup>()
                .AddJsonFile($"appsettings.{environmentName}.json", optional: true, reloadOnChange: true);
        }

        private static void ConfigureLogging(WebHostBuilderContext hostingContext, ILoggingBuilder logging)
        {
            logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
            logging.AddConsole();
            logging.AddDebug();
        }

        private static void DefaultServiceProvider(WebHostBuilderContext hostingContext, Microsoft.Extensions.DependencyInjection.ServiceProviderOptions options)
        {
            // To detect: InvalidOperationException: Cannot consume scoped service 'Ruhu.AppDbContext' from singleton 'Microsoft.AspNetCore.Authorization.IAuthorizationHandler'.
            options.ValidateScopes = hostingContext.HostingEnvironment.IsDevelopment();
        }
    }
}
