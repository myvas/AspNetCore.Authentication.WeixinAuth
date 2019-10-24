using Microsoft.AspNetCore.Authentication;
using System.Threading.Tasks;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal static class AuthenticationPropertiesExtensions
    {
        public static string GetCorrelationId(this AuthenticationProperties properties)
        {
            return WeixinAuthAuthenticationPropertiesHelper.GetCorrelationId(properties);
        }
    }
}
