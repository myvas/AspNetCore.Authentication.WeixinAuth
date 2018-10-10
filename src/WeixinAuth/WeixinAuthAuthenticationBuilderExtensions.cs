using AspNetCore.Authentication.WeixinAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 微信公众平台@微信网页授权机制
    /// https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140842
    /// </summary>
    public static class WeixinAuthAuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddWeixinAuth(this AuthenticationBuilder builder)
            => builder.AddWeixinAuth(WeixinAuthDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddWeixinAuth(this AuthenticationBuilder builder, Action<WeixinAuthOptions> setupAction)
            => builder.AddWeixinAuth(WeixinAuthDefaults.AuthenticationScheme, setupAction);

        public static AuthenticationBuilder AddWeixinAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<WeixinAuthOptions> setupAction)
            => builder.AddWeixinAuth(authenticationScheme, WeixinAuthDefaults.DisplayName, setupAction);

        public static AuthenticationBuilder AddWeixinAuth(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<WeixinAuthOptions> setupAction)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.TryAddTransient<IWeixinAuthApi, WeixinAuthApi>();

            return builder.AddOAuth<WeixinAuthOptions, WeixinAuthHandler>(authenticationScheme, displayName, setupAction);
        }
    }
}
