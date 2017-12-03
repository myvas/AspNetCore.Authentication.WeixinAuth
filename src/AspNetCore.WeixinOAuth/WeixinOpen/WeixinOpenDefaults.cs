namespace AspNetCore.WeixinOAuth
{
    public static class WeixinOpenDefaults
    {
        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string AuthenticationScheme = "Weixin-Open";
        
        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string DisplayName = "Weixin Open";

        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string ClaimsIssuer = "Weixin-Open";
        
        /// <summary>
        /// /signin-weixin-oauth-qr
        /// </summary>
        public const string CallbackPath = "/signin-weixin-open";

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
    }
}
