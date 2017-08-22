using System;
using System.Threading.Tasks;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json;
using Xunit;
using Microsoft.AspNetCore.Authentication.Facebook;

namespace test
{
    public class WeixinOAuthTests
    {
        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddFacebook();
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = await schemeProvider.GetSchemeAsync(FacebookDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("FacebookHandler", scheme.HandlerType.Name);
            Assert.Equal(FacebookDefaults.AuthenticationScheme, scheme.DisplayName);
        }

        [Fact]
        public void MathRound_Pass()
        {
            Assert.Equal(9, Math.Round(8.96));
        }
    }
}
