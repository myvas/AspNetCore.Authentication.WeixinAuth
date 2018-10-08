using AspNetCore.Authentication.WeixinOpen.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using System;
using System.Collections.Generic;

namespace AspNetCore.Authentication.WeixinOpen
{
    /// <summary>
    /// Configuration options for <see cref="WeixinOAuthMiddleware"/>.
    /// </summary>
    public class WeixinOpenOptions : RemoteAuthenticationOptions
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
        public new WeixinOpenEvents<WeixinOpenOptions> Events
        {
            get => (WeixinOpenEvents<WeixinOpenOptions>)base.Events;
            set => base.Events = value;
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
        
        public WeixinOpenOptions()
        {
            Events = new WeixinOpenEvents<WeixinOpenOptions>();

            ClaimsIssuer = WeixinOpenDefaults.ClaimsIssuer;
            CallbackPath = WeixinOpenDefaults.CallbackPath;
            AuthorizationEndpoint = WeixinOpenDefaults.AuthorizationEndpoint;
            TokenEndpoint = WeixinOpenDefaults.TokenEndpoint;
            UserInformationEndpoint = WeixinOpenDefaults.UserInformationEndpoint;
            Scope.Add(WeixinOpenScopes.snsapi_login);

            SaveTokens = true;
        }

        public override void Validate()
        {
            base.Validate();

            if (string.IsNullOrEmpty(AppId))
            {
                throw new ArgumentException($"{nameof(AppId)} must be provided", nameof(AppId));
            }

            if (string.IsNullOrEmpty(AppSecret))
            {
                throw new ArgumentException($"{nameof(AppSecret)} must be provided", nameof(AppSecret));
            }

            if (string.IsNullOrEmpty(AuthorizationEndpoint))
            {
                throw new ArgumentException($"{nameof(AuthorizationEndpoint)} must be provided", nameof(AuthorizationEndpoint));
            }

            if (string.IsNullOrEmpty(TokenEndpoint))
            {
                throw new ArgumentException($"{nameof(TokenEndpoint)} must be provided", nameof(TokenEndpoint));
            }

            if (CallbackPath == null || !CallbackPath.HasValue)
            {
                throw new ArgumentException($"{nameof(CallbackPath)} must be provided", nameof(CallbackPath));
            }
        }
    }
}
