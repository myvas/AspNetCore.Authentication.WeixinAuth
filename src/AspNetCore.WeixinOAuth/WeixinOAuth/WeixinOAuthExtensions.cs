using AspNetCore.WeixinOAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WeixinOAuthExtensions
    {
        public static AuthenticationBuilder AddWeixinOAuth(this AuthenticationBuilder builder, Action<WeixinOAuthOptions> configureOptions)
            => builder.AddWeixinOAuth(WeixinOAuthDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddWeixinOAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<WeixinOAuthOptions> configureOptions)
            => builder.AddWeixinOAuth(authenticationScheme, WeixinOAuthDefaults.DisplayName, configureOptions);

        /// <summary>
        /// Authenticate users using Weixin OAuth
        /// </summary>
        /// <param name="builder">The <see cref="IApplicationBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IApplicationBuilder"/></returns>
        public static AuthenticationBuilder AddWeixinOAuth(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<WeixinOAuthOptions> configureOptions)
        {
            Action<WeixinOAuthOptions> newSetupAction = options => {
                options.ClaimsIssuer = WeixinOAuthDefaults.ClaimsIssuer;
                options.CallbackPath = WeixinOAuthDefaults.CallbackPath;
                options.AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpoint;
                options.TokenEndpoint = WeixinOAuthDefaults.TokenEndpoint;
                options.UserInformationEndpoint = WeixinOAuthDefaults.UserInformationEndpoint;
            };
            newSetupAction += configureOptions;

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<WeixinOAuthOptions>, WeixinOAuthPostConfigureOptions<WeixinOAuthOptions>>());

            return builder.AddRemoteScheme<WeixinOAuthOptions, WeixinOAuthHandler<WeixinOAuthOptions>>(authenticationScheme, displayName, newSetupAction);
        }
    }
}
