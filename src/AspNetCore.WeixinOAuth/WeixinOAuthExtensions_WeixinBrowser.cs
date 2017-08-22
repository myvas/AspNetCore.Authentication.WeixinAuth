using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using System;

namespace AspNetCore.WeixinOAuth
{
    public static class WeixinOAuthExtensions_WeixinBrowser
    {
        /// <summary>
        /// Authenticate users using Weixin OAuth
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IApplicationBuilder"/></returns>
        public static IApplicationBuilder UseWeixinOAuth(
            this IApplicationBuilder app,
            Action<WeixinOAuthOptions> setupAction)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (setupAction == null)
            {
                throw new ArgumentNullException(nameof(setupAction));
            }

            var options = new WeixinOAuthOptions();
            setupAction(options);

            return app.UseWeixinOAuth(options);
        }

        /// <summary>
        /// Authenticate users using Weixin OAuth
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IApplicationBuilder"/></returns>
        public static IApplicationBuilder UseWeixinOAuth(
            this IApplicationBuilder app,
            WeixinOAuthOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Must be AuthorizationEndpoint and snsapi_base/userinfo
            if (options.AuthorizationEndpoint != WeixinOAuthDefaults.AuthorizationEndpoint)
            {
                options.AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpoint;
            }
            options.Scope.Remove(WeixinOAuthScopes.snsapi_login);

            return null;// app.UseMiddleware<WeixinOAuthMiddleware>(Options.Create(options));
        }
    }
}
