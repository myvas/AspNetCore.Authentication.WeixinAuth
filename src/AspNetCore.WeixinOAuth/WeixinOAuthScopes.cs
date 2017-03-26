using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth
{
    public static class WeixinOAuthScopes
    {
        /// <summary>
        /// 此授权用于网页扫码登录。
        /// </summary>
        public const string snsapi_login = "snsapi_login";

        /// <summary>
        /// 此授权用于获取进入页面的用户openid，静默授权并自动跳转到回调页。
        /// </summary>
        public const string snsapi_base = "snsapi_base";

        /// <summary>
        /// 此授权用于获取微信用户资料，须用户手动同意，但无须用户关注公众号。
        /// </summary>
        public const string snsapi_userinfo = "snsapi_userinfo";
    }
}
