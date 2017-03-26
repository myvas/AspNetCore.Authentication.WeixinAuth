using AspNetCore.WeixinOAuth.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using System.Collections.Generic;

namespace AspNetCore.WeixinOAuth
{
    /// <summary>
    /// Configuration options for <see cref="WeixinOAuthMiddleware"/>.
    /// </summary>
    public class WeixinOAuthOptions : RemoteAuthenticationOptions
    {
        /// <summary>
        /// Gets or sets the provider-assigned client id.
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        /// Gets or sets the provider-assigned client secret.
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// Gets or sets the URI where the client will be redirected to authenticate.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the URI the middleware will access to exchange the OAuth token.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the URI the middleware will access to obtain the user information.
        /// This value is not used in the default implementation, it is for use in custom implementations of
        /// IOAuthAuthenticationEvents.Authenticated or OAuthAuthenticationHandler.CreateTicketAsync.
        /// </summary>
        public string UserInformationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IOAuthEvents"/> used to handle authentication events.
        /// </summary>
        public new IWeixinOAuthEvents Events
        {
            get { return (IWeixinOAuthEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Gets the list of permissions to request.
        /// </summary>
        public ICollection<string> Scope { get; } = new HashSet<string>();

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// 国家地区语言版本，支持zh_CN 简体（默认），zh_TW 繁体，en 英语等三种。
        /// </summary>
        /// <remarks>在拉取用户信息时用到</remarks>
        public string LanguageCode { get; set; } = "zh_CN";

        public WeixinOAuthOptions()
        {
            Events = new WeixinOAuthEvents();

            AuthenticationScheme = WeixinOAuthDefaults.AuthenticationScheme;
            DisplayName = WeixinOAuthDefaults.DisplayName;
            ClaimsIssuer = WeixinOAuthDefaults.Issuer;

            //Scope.Add(WeixinOAuthScopes.snsapi_login);
            //if (Scope.Count < 1) Scope.Add(WeixinOAuthScopes.snsapi_userinfo);

            CallbackPath = WeixinOAuthDefaults.CallbackPath;

            AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpoint;
            TokenEndpoint = WeixinOAuthDefaults.TokenEndpoint;
            UserInformationEndpoint = WeixinOAuthDefaults.UserInformationEndpoint;
        }
    }
}
