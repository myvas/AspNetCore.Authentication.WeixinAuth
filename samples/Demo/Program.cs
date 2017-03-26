using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Myvas.AspNetCore.Authentication.WeixinOAuth.Sample
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var config = new ConfigurationBuilder()
                // These two are just additional ways to load configuration settings.
                .AddEnvironmentVariables(prefix: "ASPNETCORE_") // ASPNETCORE_URLS http://localhost:5001
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("hosting.json", optional: true) // "urls":"http://localhost:5002;...."
                .AddCommandLine(args) // --urls="http://localhost:5003;..."
                .Build();

            var host = new WebHostBuilder()
                .UseConfiguration(config)
                .UseKestrel()
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseIISIntegration()
                .UseStartup<Startup>()
                .Build();

            host.Run();
        }
    }
}
