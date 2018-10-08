namespace AspNetCore.Authentication.QQ
{
    public static class QQOAuthDefaults
    {
        /// <summary>
        /// QQ
        /// </summary>
        public const string AuthenticationScheme = "QQ";

        /// <summary>
        /// QQ
        /// </summary>
        public const string DisplayName = "QQ";

        /// <summary>
        /// QQ
        /// </summary>
        public const string ClaimsIssuer = "QQ";

        /// <summary>
        /// /signin-qq
        /// </summary>
        public const string CallbackPath = "/signin-qq";

        public static readonly string AuthorizationEndpoint = "https://graph.qq.com/oauth2.0/authorize";

        public static readonly string TokenEndpoint = "https://graph.qq.com/oauth2.0/token";

        public static readonly string OpenIdEndpoint = "https://graph.qq.com/oauth2.0/me";

        public static readonly string UserInformationEndpoint = "https://graph.qq.com/user/get_user_info";
    }
}