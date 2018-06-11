using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;
using Xunit;

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
