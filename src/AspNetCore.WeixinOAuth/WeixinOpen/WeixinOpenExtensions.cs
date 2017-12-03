using AspNetCore.WeixinOAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WeixinOpenExtensions
    {
        public static AuthenticationBuilder AddWeixinOpen(this AuthenticationBuilder builder)
            => builder.AddWeixinOpen(WeixinOpenDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddWeixinOpen(this AuthenticationBuilder builder, Action<WeixinOAuthOptions> setupAction)
            => builder.AddWeixinOpen(WeixinOpenDefaults.AuthenticationScheme, setupAction);

        public static AuthenticationBuilder AddWeixinOpen(this AuthenticationBuilder builder, string authenticationScheme, Action<WeixinOAuthOptions> setupAction)
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
            Action<WeixinOAuthOptions> setupAction)
        {
            Action<WeixinOAuthOptions> runningSetupAction = options => { 
                options.ClaimsIssuer = WeixinOpenDefaults.ClaimsIssuer;
                options.CallbackPath = WeixinOpenDefaults.CallbackPath;
                options.AuthorizationEndpoint = WeixinOpenDefaults.AuthorizationEndpoint;
                options.TokenEndpoint = WeixinOpenDefaults.TokenEndpoint;
                options.UserInformationEndpoint = WeixinOpenDefaults.UserInformationEndpoint;
            };
            runningSetupAction += setupAction;

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<WeixinOAuthOptions>, WeixinOpenPostConfigureOptions<WeixinOAuthOptions>>());

            return builder.AddRemoteScheme<WeixinOAuthOptions, WeixinOAuthHandler<WeixinOAuthOptions>>(authenticationScheme, displayName, runningSetupAction);
        }
    }
}
