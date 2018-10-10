using System.ComponentModel.DataAnnotations;

namespace AspNetCore.Authentication.WeixinOpen
{
    public enum LanguageCodes
    {
        [Display(ShortName = "zh_CN", Name = "简体")]
        zh_CN,
        [Display(ShortName = "zh_TW", Name = "繁体")]
        zh_TW,
        [Display(ShortName = "en", Name = "英语")]
        en
    }

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
        /// https://open.weixin.qq.com/connect/qrconnect
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
