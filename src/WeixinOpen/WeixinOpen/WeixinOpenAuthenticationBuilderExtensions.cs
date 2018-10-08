using AspNetCore.Authentication.WeixinOpen;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 微信开放平台@网站应用微信登录
    /// https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419316505&token=&lang=zh_CN
    /// </summary>
    public static class WeixinOpenExtensions
    {
        public static AuthenticationBuilder AddWeixinOpen(this AuthenticationBuilder builder)
            => builder.AddWeixinOpen(WeixinOpenDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddWeixinOpen(this AuthenticationBuilder builder, Action<WeixinOpenOptions> setupAction)
            => builder.AddWeixinOpen(WeixinOpenDefaults.AuthenticationScheme, setupAction);

        public static AuthenticationBuilder AddWeixinOpen(this AuthenticationBuilder builder, string authenticationScheme, Action<WeixinOpenOptions> setupAction)
            => builder.AddWeixinOpen(authenticationScheme, WeixinOpenDefaults.DisplayName, setupAction);

        /// <summary>
        /// Authenticate users using Weixin OAuth for Open
        /// </summary>
        /// <param name="builder">The <see cref="IApplicationBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IApplicationBuilder"/></returns>
        public static AuthenticationBuilder AddWeixinOpen(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<WeixinOpenOptions> setupAction)
        {
            Action<WeixinOpenOptions> runningSetupAction = options =>
            {
                options.ClaimsIssuer = WeixinOpenDefaults.ClaimsIssuer;
                options.CallbackPath = WeixinOpenDefaults.CallbackPath;
                options.AuthorizationEndpoint = WeixinOpenDefaults.AuthorizationEndpoint;
                options.TokenEndpoint = WeixinOpenDefaults.TokenEndpoint;
                options.UserInformationEndpoint = WeixinOpenDefaults.UserInformationEndpoint;
            };

            if (setupAction != null)
            {
                runningSetupAction += setupAction;
            }

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<WeixinOpenOptions>, WeixinOpenPostConfigureOptions<WeixinOpenOptions>>());

            return builder.AddRemoteScheme<WeixinOpenOptions, WeixinOpenHandler<WeixinOpenOptions>>(authenticationScheme, displayName, runningSetupAction);
        }
    }
}
