using AspNetCore.Authentication.WeixinAuth.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace AspNetCore.Authentication.WeixinAuth
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
        /// 是否需要获取除微信OpenId外的其他用户信息（名称，头像等）
        /// </summary>
        public bool GetClaimsFromUserInfoEndpoint
        {
            get
            {
                return WeixinAuthScopes.Contains(Scope, WeixinAuthScopes.Items.snsapi_userinfo);
            }
            set
            {
                if (value)
                {
                    WeixinAuthScopes.TryAdd(Scope, WeixinAuthScopes.Items.snsapi_userinfo);
                }
                else
                {
                    Scope.Remove(WeixinAuthScopes.Items.snsapi_userinfo.ToString());
                    if (Scope.Count < 1)
                    {
                        Scope.Add(WeixinAuthScopes.Items.snsapi_base.ToString());
                    }
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
            LanguageCode =  "zh_CN";
            WeixinAuthScopes.TryAdd(Scope, WeixinAuthScopes.Items.snsapi_base);
            GetClaimsFromUserInfoEndpoint = true;
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
