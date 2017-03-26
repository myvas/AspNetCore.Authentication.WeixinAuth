using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Events
{
    /// <summary>
    /// Base class for other Twitter contexts.
    /// </summary>
    public class BaseWeixinOAuthContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="BaseWeixinOAuthContext"/>
        /// </summary>
        /// <param name="context">The HTTP environment</param>
        /// <param name="options">The options for WeixinOAuth</param>
        public BaseWeixinOAuthContext(HttpContext context, WeixinOAuthOptions options)
            : base(context)
        {
            Options = options;
        }

        public WeixinOAuthOptions Options { get; }
    }
}
