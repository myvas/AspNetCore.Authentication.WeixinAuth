using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Myvas.AspNetCore.Authentication.WeixinAuth
{
    //
    // Summary:
    //     Defines constants for the well-known claim types that can be assigned to a subject.
    //     This class cannot be inherited.
    public static class WeixinAuthenticationTokenNames
    {
        /// <summary>
        /// openid
        /// </summary>
        public const string openid = "weixin_openid";

        /// <summary>
        /// unionid
        /// </summary>
        public const string unionid = "unionid";

        /// <summary>
        /// scope
        /// </summary>
        public const string scope = "scope";

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
