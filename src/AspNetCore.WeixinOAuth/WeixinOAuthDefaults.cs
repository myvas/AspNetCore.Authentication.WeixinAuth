namespace AspNetCore.WeixinOAuth
{
    public static class WeixinOAuthDefaults
    {
        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string AuthenticationScheme = "Weixin-OAuth";

        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string AuthenticationSchemeQr = "Weixin-OAuth-Qr";

        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string DisplayName = "Weixin OAuth";

        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string Issuer = "Weixin-OAuth";

        /// <summary>
        /// /signin-weixin-oauth
        /// </summary>
        public const string CallbackPath = "/signin-weixin-oauth";

        /// <summary>
        /// /signin-weixin-oauth-qr
        /// </summary>
        public const string CallbackPathQr = "/signin-weixin-oauth-qr";

        /// <summary>
        /// https://open.weixin.qq.com/connect/qrconnect
        /// </summary>
        public const string AuthorizationEndpointQr = "https://open.weixin.qq.com/connect/qrconnect";

        /// <summary>
        /// https://open.weixin.qq.com/connect/oauth2/authorize
        /// </summary>
        public const string AuthorizationEndpoint = "https://open.weixin.qq.com/connect/oauth2/authorize";

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
