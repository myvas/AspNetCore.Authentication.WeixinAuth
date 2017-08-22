using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Reflection;

namespace Myvas.AspNetCore.Authentication.WeixinOAuth.Sample
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var host = BuildWebHost(args);

            host.Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            return CreateWebHostBuilder(args)
                .Build();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            var hostingConfiguration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("hosting.json", optional: true, reloadOnChange: true)
                // These two are just additional ways to load configuration settings.
                .AddEnvironmentVariables(prefix: "ASPNETCORE_") // ASPNETCORE_URLS http://localhost:5001
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("hosting.json", optional: true) // "urls":"http://localhost:5002;...."
                .AddCommandLine(args) // --urls="http://localhost:5003;..."
                .AddUserSecrets<Startup>()
                .Build();

            var builder = new WebHostBuilder()
                .UseConfiguration(hostingConfiguration)
                .UseKestrel()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    var env = hostingContext.HostingEnvironment;

                    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                        .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true);

                    if (env.IsDevelopment())
                    {
                        var appAssembly = Assembly.Load(new AssemblyName(env.ApplicationName));
                        if (appAssembly != null)
                        {
                            config.AddUserSecrets(appAssembly, optional: true);
                        }
                    }

                    config.AddEnvironmentVariables();

                    if (args != null)
                    {
                        config.AddCommandLine(args);
                    }
                })
                .ConfigureLogging((hostingContext, logging) =>
                {
                    logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                    logging.AddConsole();
                    logging.AddDebug();
                })
                .UseIISIntegration()
                .UseDefaultServiceProvider((context, options) =>
                {
                    options.ValidateScopes = context.HostingEnvironment.IsDevelopment();
                })
                .UseStartup<Startup>();

            return builder;
        }
    }
}
