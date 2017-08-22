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
        public static AuthenticationBuilder AddWeixinOAuth(this AuthenticationBuilder builder)
            => builder.AddWeixinOAuth(WeixinOAuthDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddWeixinOAuth(this AuthenticationBuilder builder, Action<WeixinOAuthOptions> setupAction)
            => builder.AddWeixinOAuth(WeixinOAuthDefaults.AuthenticationScheme, setupAction);

        public static AuthenticationBuilder AddWeixinOAuth(this AuthenticationBuilder builder, string authenticationScheme, Action<WeixinOAuthOptions> setupAction)
            => builder.AddWeixinOAuth(authenticationScheme, WeixinOAuthDefaults.DisplayName, setupAction);

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
            Action<WeixinOAuthOptions> setupAction)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<WeixinOAuthOptions>, WeixinOAuthPostConfigureOptions>());

            return builder.AddRemoteScheme<WeixinOAuthOptions, WeixinOAuthHandler>(authenticationScheme, displayName, setupAction);

            //// Must be AuthorizationEndpoint and snsapi_base/userinfo
            //if (options.AuthorizationEndpoint != WeixinOAuthDefaults.AuthorizationEndpoint)
            //{
            //    options.AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpoint;
            //}
            //options.Scope.Remove(WeixinOAuthScopes.snsapi_login);

            //return app.UseMiddleware<WeixinOAuthMiddleware>(Options.Create(options));
        }
    }
}
