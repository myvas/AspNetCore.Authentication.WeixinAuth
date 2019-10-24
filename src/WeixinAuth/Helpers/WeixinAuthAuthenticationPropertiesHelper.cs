using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Myvas.AspNetCore.Authentication
{
    public static class WeixinAuthAuthenticationPropertiesHelper
    {
        public const string CorrelationProperty = ".xsrf";
        public const string CorrelationMarker = "N";

        public static string GetCorrelationId(AuthenticationProperties properties)
        {
            return properties.Items[CorrelationProperty];
        }

        public static AuthenticationProperties GetByCorrelationId(PropertiesDataFormat stateFormat, IList<string> cookies, string correlationId, string schemeName, string correlationCookieName = ".AspNetCore.Correlation")
        {
            var state = correlationId;
            var fullCookieValue = cookies.FirstOrDefault(x => x.StartsWith($"{correlationCookieName}.{schemeName}.{CorrelationMarker}.{state}"));
            var cookieValue = GetCookieValue(fullCookieValue, state);
            var stateProperties = stateFormat.Unprotect(cookieValue);
            return stateProperties;
        }

        public static string GetCookieValue(string fullCookieString, string key)
        {
            if (!fullCookieString.StartsWith(key))
            {
                var trimedFullCookieString = fullCookieString.Substring(key.Length);

                var regexPattern = "=(?<Value>.+);";
                var regex = new Regex(regexPattern, RegexOptions.Compiled | RegexOptions.Multiline, TimeSpan.FromSeconds(10));
                var match = regex.Match(trimedFullCookieString);
                if (match.Success && match.Groups["Value"].Success)
                {
                    return match.Groups["Value"].Value;
                }
            }
            return "";
        }
    }
}
