using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using System;

namespace AspNetCore.WeixinOAuth
{
    public static class WeixinOAuthExtensions_WebBrowser
    {
        /// <summary>
        /// Authenticate users using Weixin OAuth
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IApplicationBuilder"/></returns>
        public static IApplicationBuilder UseWeixinOAuthQr(
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

            return app.UseWeixinOAuthQr(options);
        }

        /// <summary>
        /// Authenticate users using Weixin OAuth
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IApplicationBuilder"/></returns>
        public static IApplicationBuilder UseWeixinOAuthQr(
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
            
            // Must be AuthorizationEndpointQrcode and snsapi_login!
            if (options.AuthorizationEndpoint != WeixinOAuthDefaults.AuthorizationEndpointQr)
            {
                options.AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpointQr;
            }
            {
                options.Scope.Clear();
                options.Scope.Add(WeixinOAuthScopes.snsapi_login);
            }
            if (options.CallbackPath == WeixinOAuthDefaults.CallbackPath)
            {
                options.CallbackPath = WeixinOAuthDefaults.CallbackPathQr;
            }

            return app.UseMiddleware<WeixinOAuthMiddleware>(Options.Create(options));
        }
    }
}
