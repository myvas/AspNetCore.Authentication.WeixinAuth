using AspNetCore.Authentication.WeixinAuth;
using AspNetCore.Authentication.WeixinAuth.Messages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;

namespace Microsoft.Extensions.DependencyInjection
{
    public class WeixinAuthPostConfigureOptions<TOptions> : IPostConfigureOptions<TOptions>
        where TOptions : WeixinAuthOptions, new()
    {
        private readonly IDataProtectionProvider _dp;
        private readonly AuthenticationOptions _authOptions;

        public WeixinAuthPostConfigureOptions(IDataProtectionProvider dataProtection,
            IOptions<AuthenticationOptions> authOptions)
        {
            _dp = dataProtection;
            _authOptions = authOptions.Value;
        }

        public virtual void PostConfigure(string name, TOptions options)
        {
            if (options.GetClaimsFromUserInfoEndpoint)
            {
                if (!WeixinAuthScopes.Contains(options.Scope, WeixinAuthScopes.Items.snsapi_userinfo))
                {
                    WeixinAuthScopes.TryAdd(options.Scope, WeixinAuthScopes.Items.snsapi_userinfo);
                }
            }
            else
            {
                if (!WeixinAuthScopes.Contains(options.Scope, WeixinAuthScopes.Items.snsapi_base))
                {
                    WeixinAuthScopes.TryAdd(options.Scope, WeixinAuthScopes.Items.snsapi_base);
                }
            }

            options.SignInScheme = options.SignInScheme ?? _authOptions.DefaultSignInScheme ?? _authOptions.DefaultScheme;
            if (string.Equals(options.SignInScheme, name, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The SignInScheme for a remote authentication handler cannot be set to itself.  If it was not explicitly set, the AuthenticationOptions.DefaultSignInScheme or DefaultScheme is used.");
            }

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
                    typeof(WeixinAuthHandler<TOptions>).FullName, name, "v1");
                //options.StateDataFormat = new PropertiesDataFormat(dataProtector);
                options.StateDataFormat = new SecureDataFormat<AuthenticationProperties>(
                    new AuthenticationPropertiesSerializer(),
                    dataProtector);
            }
        }
    }
}
