using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Messages
{
    public static class AuthenticationPropertiesExtensions
    {
        private const string CorrelationProperty = ".xsrf";

        public static string GetCorrelationId(this AuthenticationProperties properties)
        {
            return properties.Items[CorrelationProperty];
        }
    }
}
