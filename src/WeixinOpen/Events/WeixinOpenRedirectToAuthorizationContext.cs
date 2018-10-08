using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinOpen.Events
{
    /// <summary>
    /// Context passed when a Challenge causes a redirect to authorize endpoint in the middleware.
    /// </summary>
    public class WeixinOpenRedirectToAuthorizationContext<TOptions> : BaseWeixinOpenContext<TOptions>
        where TOptions : WeixinOpenOptions, new()
    {
        /// <summary>
        /// The Context passed when a Challenge causes a redirect to authorize endpoint in the WeixinOAuth middleware.
        /// </summary>
        /// <param name="context">The HTTP request context.</param>
        /// <param name="options">The <see cref="WeixinOpenOptions"/>.</param>
        /// <param name="properties">The authentication properties of the challenge.</param>
        /// <param name="redirectUri">The initial redirect URI.</param>
        public WeixinOpenRedirectToAuthorizationContext(
            HttpContext context, 
            AuthenticationScheme scheme,
            TOptions options,
            AuthenticationProperties properties, 
            string redirectUri)
            : base(context,scheme, options)
        {
            Properties = properties;
            RedirectUri = redirectUri;
        }
        
        /// <summary>
        /// Gets the URI used for the redirect operation.
        /// </summary>
        public string RedirectUri { get; private set; }

        /// <summary>
        /// Gets the authentication properties of the challenge.
        /// </summary>
        public AuthenticationProperties Properties { get; private set; }
    }
}
