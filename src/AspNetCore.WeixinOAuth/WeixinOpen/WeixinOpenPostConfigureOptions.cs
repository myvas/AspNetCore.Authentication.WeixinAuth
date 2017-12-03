using AspNetCore.WeixinOAuth;
using AspNetCore.WeixinOAuth.Messages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;

namespace Microsoft.Extensions.DependencyInjection
{
    public class WeixinOpenPostConfigureOptions<TOptions> : WeixinOAuthPostConfigureOptions<TOptions>
        where TOptions : WeixinOAuthOptions, new()
    {
        public WeixinOpenPostConfigureOptions(IDataProtectionProvider dataProtection,
            IOptions<AuthenticationOptions> authOptions) : base(dataProtection, authOptions)
        {
        }

        public override void PostConfigure(string name, TOptions options)
        {
            base.PostConfigure(name, options);

            if (!options.Scope.Contains(WeixinOAuthScopes.snsapi_login))
            {
                options.Scope.Add(WeixinOAuthScopes.snsapi_login);
            }
        }
    }
}
