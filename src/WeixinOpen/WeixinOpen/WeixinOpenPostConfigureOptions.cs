using AspNetCore.Authentication.WeixinOpen;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    public class WeixinOpenPostConfigureOptions<TOptions> : WeixinOAuthPostConfigureOptions<TOptions>
        where TOptions : WeixinOpenOptions, new()
    {
        public WeixinOpenPostConfigureOptions(
            IDataProtectionProvider dataProtection,
            IOptions<AuthenticationOptions> authOptions) 
            : base(dataProtection, authOptions)
        {
        }

        public override void PostConfigure(string name, TOptions options)
        {
            base.PostConfigure(name, options);

            if (!options.Scope.Contains(WeixinOpenScopes.snsapi_login))
            {
                options.Scope.Add(WeixinOpenScopes.snsapi_login);
            }
        }
    }
}
