using AspNetCore.WeixinOAuth;
using AspNetCore.WeixinOAuth.Messages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Net.Http;

namespace Microsoft.Extensions.DependencyInjection
{
    public class WeixinOAuthPostConfigureOptions : IPostConfigureOptions<WeixinOAuthOptions>
    {
        private readonly IDataProtectionProvider _dp;

        public WeixinOAuthPostConfigureOptions(IDataProtectionProvider dataProtection)
        {
            _dp = dataProtection;
        }

        public void PostConfigure(string name, WeixinOAuthOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;
            if (options.Backchannel == null)
            {
                options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
                options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("AspNetCoreWeixinOAuth/2.0.0");
                options.Backchannel.Timeout = options.BackchannelTimeout;
                options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
                //options.Backchannel.DefaultRequestHeaders.Accept.ParseAdd("*/*");
                //options.Backchannel.DefaultRequestHeaders.ExpectContinue = false;
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(
                    typeof(WeixinOAuthHandler).FullName, name, "v1");
                //options.StateDataFormat = new PropertiesDataFormat(dataProtector);
                options.StateDataFormat = new SecureDataFormat<AuthenticationProperties>(
                    new AuthenticationPropertiesSerializer(),
                    dataProtector);
            }
        }
    }
}
