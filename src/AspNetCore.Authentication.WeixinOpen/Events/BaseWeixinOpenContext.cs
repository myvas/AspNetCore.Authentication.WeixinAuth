using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinOpen.Events
{
    /// <summary>
    /// Base class for other Twitter contexts.
    /// </summary>
    public class BaseWeixinOpenContext<TOptions> : BaseContext<TOptions>
        where TOptions : WeixinOpenOptions, new()
    {
        /// <summary>
        /// Initializes a <see cref="BaseWeixinOAuthContext"/>
        /// </summary>
        /// <param name="context">The HTTP environment</param>
        /// <param name="options">The options for WeixinOAuth</param>
        public BaseWeixinOpenContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
            : base(context, scheme, options)
        {
        }
    }
}
