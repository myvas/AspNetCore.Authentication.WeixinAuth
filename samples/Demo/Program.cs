using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Reflection;
using Microsoft.AspNetCore;

namespace AspNetCore.WeixinOAuth.Demo
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
            var builder = CreateWebHostBuilder(args);

            return builder.Build();
        }

        private static IConfiguration BuildConfigurationForHostingUrls()
        {
            var hostingConfigurationBuilder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory()) //AppContext.BaseDirectory is assembly's location
                .AddJsonFile("hosting.json", optional: true); // urls

            return hostingConfigurationBuilder.Build();
        }

        private static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            var hostingConfiguration = BuildConfigurationForHostingUrls();

            var builder = WebHost.CreateDefaultBuilder()
                .UseConfiguration(hostingConfiguration)
                .UseStartup<Startup>();

            return builder;
        }
    }
}
