using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Myvas.AspNetCore.Authentication.WeixinAuth
{
    public static class WeixinAuthAuthenticationPropertiesExtensions
    {
        private const string CorrelationProperty = ".xsrf";

        public static string GetCorrelationId(this AuthenticationProperties properties)
        {
            return properties.Items[CorrelationProperty];
        }

        public static AuthenticationProperties GetByCorrelationId(PropertiesDataFormat stateFormat, IList<string> cookies, string correlationId, string schemeName, string correlationCookieName = ".AspNetCore.Correlation")
        {
            var state = correlationId;
            var fullCookieValue = cookies.FirstOrDefault(x => x.StartsWith($"{correlationCookieName}.{schemeName}.{state}.N"));
            var cookieValue = WeixinAuthAuthenticationPropertiesExtensions.GetCookieValue(fullCookieValue, state);
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
