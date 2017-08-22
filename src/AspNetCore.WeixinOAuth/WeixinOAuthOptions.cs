using AspNetCore.WeixinOAuth.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Globalization;

namespace AspNetCore.WeixinOAuth
{
    /// <summary>
    /// Configuration options for <see cref="WeixinOAuthMiddleware"/>.
    /// </summary>
    public class WeixinOAuthOptions : RemoteAuthenticationOptions
    {
        public string AppId { get { return ClientId; } set { ClientId = value; } }
        public string AppSecret { get { return ClientSecret; } set { ClientSecret = value; } }

        /// <summary>
        /// Gets or sets the provider-assigned client id.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the provider-assigned client secret.
        /// </summary>
        public string ClientSecret { get; set; }

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
        public new WeixinOAuthEvents Events
        {
            get { return (WeixinOAuthEvents)base.Events; }
            set { base.Events = value; }
        }
        
        /// <summary>
        /// A collection of claim actions used to select values from the json user data and create Claims.
        /// </summary>
        public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

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
            
            CallbackPath = WeixinOAuthDefaults.CallbackPath;

            AuthorizationEndpoint = WeixinOAuthDefaults.AuthorizationEndpoint;
            TokenEndpoint = WeixinOAuthDefaults.TokenEndpoint;
            UserInformationEndpoint = WeixinOAuthDefaults.UserInformationEndpoint;

            //Scope.Add(WeixinOAuthScopes.snsapi_login);
            //if (Scope.Count < 1) Scope.Add(WeixinOAuthScopes.snsapi_userinfo);

            ClaimsIssuer = WeixinOAuthDefaults.Issuer;
        }

        public override void Validate()
        {
            base.Validate();
            
            if (string.IsNullOrEmpty(ClientId))
            {
                throw new ArgumentException($"{nameof(ClientId)} must be provided", nameof(ClientId));
            }

            if (string.IsNullOrEmpty(ClientSecret))
            {
                throw new ArgumentException($"{nameof(ClientSecret)} must be provided", nameof(ClientSecret));
            }

            if (string.IsNullOrEmpty(AuthorizationEndpoint))
            {
                throw new ArgumentException($"{nameof(AuthorizationEndpoint)} must be provided", nameof(AuthorizationEndpoint));
            }

            if (string.IsNullOrEmpty(TokenEndpoint))
            {
                throw new ArgumentException($"{nameof(TokenEndpoint)} must be provided", nameof(TokenEndpoint));
            }

            if (!CallbackPath.HasValue)
            {
                throw new ArgumentException($"{nameof(CallbackPath)} must be provided", nameof(CallbackPath));
            }
        }
    }
}
