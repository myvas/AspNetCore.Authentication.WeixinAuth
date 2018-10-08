using AspNetCore.Authentication.QQ;
using Microsoft.AspNetCore.Authentication;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class QQOAuthApplicationBuilderExtensions
    {
        public static AuthenticationBuilder AddQQ(            this AuthenticationBuilder builder) 
            => builder.AddQQ(QQOAuthDefaults.AuthenticationScheme, _ => { });
        
        public static AuthenticationBuilder AddQQOAuth(this AuthenticationBuilder builder, Action<QQOAuthOptions> setupAction)
            => builder.AddQQ(QQOAuthDefaults.AuthenticationScheme, setupAction);

        public static AuthenticationBuilder AddQQ(this AuthenticationBuilder builder, string authenticationScheme, Action<QQOAuthOptions> setupAction)
            => builder.AddQQ(authenticationScheme, QQOAuthDefaults.DisplayName, setupAction);

        public static AuthenticationBuilder AddQQ(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<QQOAuthOptions> setupAction)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddOAuth<QQOAuthOptions, QQOAuthHandler>(authenticationScheme, displayName, setupAction);
        }
    }
}
