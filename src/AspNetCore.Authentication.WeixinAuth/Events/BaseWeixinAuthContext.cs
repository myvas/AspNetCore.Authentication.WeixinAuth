using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinAuth.Events
{
    /// <summary>
    /// Base class for other Twitter contexts.
    /// </summary>
    public class BaseWeixinAuthContext<TOptions> : BaseContext<TOptions>
        where TOptions : WeixinAuthOptions, new()
    {
        /// <summary>
        /// Initializes a <see cref="BaseWeixinOAuthContext"/>
        /// </summary>
        /// <param name="context">The HTTP environment</param>
        /// <param name="options">The options for WeixinOAuth</param>
        public BaseWeixinAuthContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
            : base(context, scheme, options)
        {
        }
    }
}
