using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinOpen.Messages
{
    public static class AuthenticationPropertiesExtensions
    {
        private const string CorrelationProperty = ".xsrf";

        public static string GetCorrelationId(this AuthenticationProperties properties)
        {
            return properties.Items[CorrelationProperty];
        }

        private const string RedirectProperty = ".redirect";

        public static string GetRedirectUri(this AuthenticationProperties properties)
        {
            return properties.Items[RedirectProperty];
        }

        private const string XsrfIdProperty = "XsrfId";

        public static string GetXsrfId(this AuthenticationProperties properties)
        {
            return properties.Items[XsrfIdProperty];
        }
        
        private const string LoginProviderProperty = "LoginProvider";

        public static string GetLoginProvider(this AuthenticationProperties properties)
        {
            return properties.Items[LoginProviderProperty];
        }
    }
}
