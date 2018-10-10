using AspNetCore.Authentication.QQConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class QQConnectApplicationBuilderExtensions
    {
        public static AuthenticationBuilder AddQQConnect(this AuthenticationBuilder builder)
            => builder.AddQQConnect(QQConnectDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddQQConnect(this AuthenticationBuilder builder, Action<QQConnectOptions> setupAction)
            => builder.AddQQConnect(QQConnectDefaults.AuthenticationScheme, setupAction);

        public static AuthenticationBuilder AddQQConnect(this AuthenticationBuilder builder, string authenticationScheme, Action<QQConnectOptions> setupAction)
            => builder.AddQQConnect(authenticationScheme, QQConnectDefaults.DisplayName, setupAction);

        public static AuthenticationBuilder AddQQConnect(
            this AuthenticationBuilder builder,
            string authenticationScheme,
            string displayName,
            Action<QQConnectOptions> setupAction)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.TryAddTransient<IQQConnectApi, QQConnectApi>();

            return builder.AddOAuth<QQConnectOptions, QQConnectHandler>(authenticationScheme, displayName, setupAction);
        }
    }
}
