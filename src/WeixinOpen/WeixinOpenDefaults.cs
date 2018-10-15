using System.ComponentModel.DataAnnotations;

namespace Myvas.AspNetCore.Authentication
{
    public static class WeixinOpenDefaults
    {
        /// <summary>
        /// WeixinOpen
        /// </summary>
        public const string AuthenticationScheme = "WeixinOpen";

        /// <summary>
        /// WeixinOpen
        /// </summary>
        public const string DisplayName = "WeixinOpen";

        /// <summary>
        /// WeixinOpen
        /// </summary>
        public const string ClaimsIssuer = "WeixinOpen";

        /// <summary>
        /// /signin-weixinopen
        /// </summary>
        public const string CallbackPath = "/signin-weixinopen";

        /// <summary>
        /// https://open.weixin.qq.com/connect/qrconnect, different from WeixinAuth
        /// </summary>
        public const string AuthorizationEndpoint = "https://open.weixin.qq.com/connect/qrconnect";

        /// <summary>
        /// https://api.weixin.qq.com/sns/oauth2/access_token
        /// </summary>
        public const string TokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token";

        /// <summary>
        /// https://api.weixin.qq.com/sns/userinfo
        /// </summary>
        public const string UserInformationEndpoint = "https://api.weixin.qq.com/sns/userinfo";

        /// <summary>
        /// https://api.weixin.qq.com/sns/oauth2/refresh_token
        /// </summary>
        public const string RefreshTokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/refresh_token";

        /// <summary>
        /// https://api.weixin.qq.com/sns/auth
        /// </summary>
        public const string ValidateTokenEndpoint = "https://api.weixin.qq.com/sns/auth";
    }
}
