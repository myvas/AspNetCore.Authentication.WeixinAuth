using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinOpen
{
    //
    // Summary:
    //     Defines constants for the well-known claim types that can be assigned to a subject.
    //     This class cannot be inherited.
    public static class WeixinAuthenticationTokenNames
    {
        /// <summary>
        /// weixin_openid
        /// </summary>
        public const string weixin_openid = "weixin_openid";

        /// <summary>
        /// weixin_scope
        /// </summary>
        public const string weixin_scope = "weixin_scope";

        /// <summary>
        /// access_token
        /// </summary>
        public const string access_token = "access_token";

        /// <summary>
        /// refresh_token
        /// </summary>
        public const string refresh_token = "refresh_token";

        /// <summary>
        /// token_type
        /// </summary>
        public const string token_type = "token_type";

        /// <summary>
        /// expires_at
        /// </summary>
        public const string expires_at = "expires_at";
    }
}
