using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Myvas.AspNetCore.Authentication.WeixinAuth;
using System;
using System.Security.Claims;

namespace Myvas.AspNetCore.Authentication
{
    /// <summary>
    /// Configuration options for <see cref="WeixinAuthHandler"/>.
    /// </summary>
    public class WeixinAuthOptions : OAuthOptions
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

        /// <summary>
        /// 是否采用静默模式。默认为是。使用静默模式时，将仅获取用户的OpenId信息，不会获取微信用户昵称、头像等其他信息。
        /// </summary>
        public bool SilentMode
        {
            get
            {
                return WeixinAuthScopes.Contains(Scope, WeixinAuthScopes.snsapi_userinfo);
            }
            set
            {
                if (value)
                {
                    Scope.Remove(WeixinAuthScopes.snsapi_userinfo);
                    if (Scope.Count < 1)
                    {
                        Scope.Add(WeixinAuthScopes.snsapi_base);
                    }
                }
                else
                {
                    WeixinAuthScopes.TryAdd(Scope, WeixinAuthScopes.snsapi_userinfo);
                }
            }
        }

        public WeixinAuthOptions()
        {
            CallbackPath = WeixinAuthDefaults.CallbackPath;
            AuthorizationEndpoint = WeixinAuthDefaults.AuthorizationEndpoint;
            TokenEndpoint = WeixinAuthDefaults.TokenEndpoint;
            RefreshTokenEndpoint = WeixinAuthDefaults.RefreshTokenEndpoint;
            ValidateTokenEndpoint = WeixinAuthDefaults.ValidateTokenEndpoint;
            UserInformationEndpoint = WeixinAuthDefaults.UserInformationEndpoint;
            LanguageCode = "zh_CN";
            WeixinAuthScopes.TryAdd(Scope, WeixinAuthScopes.snsapi_base);
            SilentMode = true;
            SaveTokens = true;

            ClaimsIssuer = WeixinAuthDefaults.ClaimsIssuer;

            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.UnionId, "unionid");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.OpenId, "openid");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.NickName, "nickname");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.Sex, "sex");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.Province, "province");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.City, "city");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.Country, "country");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.HeadImageUrl, "headimgurl");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.Privilege, "privilege");
            ClaimActions.MapJsonKey(WeixinAuthClaimTypes.Scope, "scope");

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
