using Microsoft.Extensions.Logging;
using System;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal static class LoggingExtensions
    {
        private static Action<ILogger, string, string, Exception> _handleChallenge;

        static LoggingExtensions()
        {
            _handleChallenge = LoggerMessage.Define<string, string>(
                eventId: new EventId(1, "HandleChallenge"),
                logLevel: LogLevel.Debug,
                formatString: "HandleChallenge with Location: {Location}; and Set-Cookie: {Cookie}.");
        }

        public static void HandleChallenge(this ILogger logger, string location, string cookie)
            => _handleChallenge(logger, location, cookie, null);
    }
}
