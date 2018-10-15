using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Myvas.AspNetCore.Authentication.WeixinOpen;
using System;
using System.Security.Claims;

namespace Myvas.AspNetCore.Authentication
{
    /// <summary>
    /// Configuration options for <see cref="WeixinOpenHandler"/>.
    /// </summary>
    public class WeixinOpenOptions : OAuthOptions
    {
        /// <summary>
        /// Gets or sets the provider-assigned client id.
        /// </summary>
        public string AppId { get => ClientId; set => ClientId = value; }

        /// <summary>
        /// Gets or sets the provider-assigned client secret.
        /// </summary>
        public string AppSecret { get => ClientSecret; set => ClientSecret = value; }

        /// <summary>
        /// 国家地区语言版本，支持zh_CN 简体（默认），zh_TW 繁体，en 英语等三种。
        /// </summary>
        /// <remarks>在拉取用户信息时用到</remarks>
        public string LanguageCode { get; set; }

        public string RefreshTokenEndpoint { get; set; }
        public string ValidateTokenEndpoint { get; set; }

        public WeixinOpenOptions()
        {
            CallbackPath = WeixinOpenDefaults.CallbackPath;
            AuthorizationEndpoint = WeixinOpenDefaults.AuthorizationEndpoint;
            TokenEndpoint = WeixinOpenDefaults.TokenEndpoint;
            RefreshTokenEndpoint = WeixinOpenDefaults.RefreshTokenEndpoint;
            ValidateTokenEndpoint = WeixinOpenDefaults.ValidateTokenEndpoint;
            UserInformationEndpoint = WeixinOpenDefaults.UserInformationEndpoint;
            LanguageCode = "zh_CN";
            Scope.Add(WeixinOpenScopes.snsapi_login);
            SaveTokens = true;

            ClaimsIssuer = WeixinOpenDefaults.ClaimsIssuer;

            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.UnionId, "unionid");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.OpenId, "openid");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.NickName, "nickname");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.Sex, "sex");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.Province, "province");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.Country, "country");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.HeadImageUrl, "headimgurl");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.Privilege, "privilege");
            ClaimActions.MapJsonKey(WeixinOpenClaimTypes.Scope, "scope");

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "unionid");
            ClaimActions.MapJsonKey(ClaimTypes.Name, "nickname");
            ClaimActions.MapJsonKey(ClaimTypes.Gender, "sex");
            ClaimActions.MapJsonKey(ClaimTypes.Country, "country");
            ClaimActions.MapJsonKey(ClaimTypes.StateOrProvince, "province");
        }
        
        public override void Validate()
        {
            if (string.IsNullOrEmpty(LanguageCode))
            {
                throw new ArgumentException($"{nameof(LanguageCode)} must be provided", nameof(LanguageCode));
            }

            if (string.IsNullOrEmpty(TokenEndpoint))
            {
                throw new ArgumentException($"{nameof(RefreshTokenEndpoint)} must be provided", nameof(RefreshTokenEndpoint));
            }

            base.Validate();
        }
    }
}
