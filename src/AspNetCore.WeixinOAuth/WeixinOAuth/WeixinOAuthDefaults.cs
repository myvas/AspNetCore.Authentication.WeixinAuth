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
        public const string DisplayName = "Weixin OAuth";

        /// <summary>
        /// Weixin-OAuth
        /// </summary>
        public const string ClaimsIssuer = "Weixin-OAuth";

        /// <summary>
        /// /signin-weixin-oauth
        /// </summary>
        public const string CallbackPath = "/signin-weixin-oauth";
        
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
