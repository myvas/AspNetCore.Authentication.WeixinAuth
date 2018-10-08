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
    public static class WeixinAuthExtensions
    {
        public static AuthenticationBuilder AddWeixinAuth(this AuthenticationBuilder builder, Action<WeixinAuthOptions> configureOptions)
            => builder.AddWeixinAuth(WeixinAuthDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddWeixinAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<WeixinAuthOptions> configureOptions)
            => builder.AddWeixinAuth(authenticationScheme, WeixinAuthDefaults.DisplayName, configureOptions);

        /// <summary>
        /// Authenticate users using Weixin OAuth
        /// </summary>
        /// <param name="builder">The <see cref="IApplicationBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IApplicationBuilder"/></returns>
        public static AuthenticationBuilder AddWeixinAuth(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<WeixinAuthOptions> configureOptions)
        {
            Action<WeixinAuthOptions> newSetupAction = options => {
                options.ClaimsIssuer = WeixinAuthDefaults.ClaimsIssuer;
                options.CallbackPath = WeixinAuthDefaults.CallbackPath;
                options.AuthorizationEndpoint = WeixinAuthDefaults.AuthorizationEndpoint;
                options.TokenEndpoint = WeixinAuthDefaults.TokenEndpoint;
                options.UserInformationEndpoint = WeixinAuthDefaults.UserInformationEndpoint;
            };
            newSetupAction += configureOptions;

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<WeixinAuthOptions>, WeixinAuthPostConfigureOptions<WeixinAuthOptions>>());

            return builder.AddRemoteScheme<WeixinAuthOptions, WeixinAuthHandler<WeixinAuthOptions>>(authenticationScheme, displayName, newSetupAction);
        }
    }
}
