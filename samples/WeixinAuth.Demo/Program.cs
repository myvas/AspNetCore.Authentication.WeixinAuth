using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using WeixinAuth.Demo.Data;

namespace WeixinAuth.Demo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args)
                .MigrateDatabase()
                .SeedDatabase()
                .Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            var hostingConfiguration = BuildHostingConfiguration();

            var webhostBuilder = new WebHostBuilder()
                .UseKestrel()
                .UseContentRoot(Directory.GetCurrentDirectory())

                .ConfigureAppConfiguration(ConfigureAppConfiguration)
                .ConfigureLogging(ConfigureLogging)

                .UseIISIntegration()
                .UseDefaultServiceProvider(DefaultServiceProvider)

                .UseConfiguration(hostingConfiguration);

            var webHost = webhostBuilder
                //.CaptureStartupErrors(true)
                .UseStartup<Startup>()
                .Build();

            return webHost;
        }


        private static IConfiguration BuildHostingConfiguration()
        {
            var envConfiguration = new ConfigurationBuilder()
                .AddEnvironmentVariables(prefix: "ASPNETCORE_")
                .Build();
            var environmentName = envConfiguration[WebHostDefaults.EnvironmentKey];
            if (string.IsNullOrEmpty(environmentName))
            {
                environmentName = "Production";
            }

            var hostingConfigurationBuilder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory()) //AppContext.BaseDirectory is assembly's location
                                                              //默认为Production环境配置
                .AddJsonFile("hosting.json", optional: true)
                //若Development环境须不同配置，请修改hosting.Development.json
                .AddJsonFile($"hosting.{environmentName}.json", optional: true); // urls

            return hostingConfigurationBuilder.Build();
        }

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
                //默认所有配置均填充注释说明，不作实际用途。
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
                //默认为Development环境配置
                .AddJsonFile("logging.json", optional: false, reloadOnChange: false)
                //通常在开发者个人计算机中创建secrets.json，用于存储开发者个人或小组的相关配置
                .AddUserSecrets<Startup>()
                //特别地，开发者可能使用本地数据库，此时可创建appsettings.Development.json以覆盖secrets.json中的数据库连接串。
                //生产环境计算机，则通常会直接使用secrets.json作为正式部署的配置。
                //建议不要使用appsettings.Production.json！
                .AddJsonFile($"appsettings.{environmentName}.json", optional: true, reloadOnChange: true)
                //若Production环境须不同配置，请创建logging.Production.json
                .AddJsonFile($"logging.{environmentName}.json", optional: true, reloadOnChange: true);
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
