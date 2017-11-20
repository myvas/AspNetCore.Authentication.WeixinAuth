using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AspNetCore.WeixinOAuth.Demo
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            var hostingConfiguration = BuildConfigurationForHostingUrls();

            return WebHost.CreateDefaultBuilder(args)
                .UseConfiguration(hostingConfiguration)
                .UseStartup<Startup>()
                .Build();
        }


        private static IConfiguration BuildConfigurationForHostingUrls()
        {
            var hostingConfigurationBuilder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory()) //AppContext.BaseDirectory is assembly's location
                .AddJsonFile("hosting.json", optional: true); // urls

            return hostingConfigurationBuilder.Build();
        }
    }
}
