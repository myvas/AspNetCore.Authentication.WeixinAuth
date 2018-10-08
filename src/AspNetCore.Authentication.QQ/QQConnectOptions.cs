using AspNetCore.Authentication.QQConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;

namespace AspNetCore.Authentication.QQConnect
{
    public class QQConnectOptions : OAuthOptions
    {
        public string OpenIdEndpoint { get; set; }

        /// <summary>
        /// 用于决定展示的样式，网站接入时使用。
        /// （1）不传则默认展示为PC下的样式。
        /// （2）如果传入“mobile”，则展示为mobile端下的样式。
        /// </summary>
        public string DisplayStyle { get; set; }

        public string AppId { get => ClientId; set => ClientId = value; }
        public string AppKey { get => ClientSecret; set => ClientSecret = value; }

        public QQConnectOptions()
        {
            OpenIdEndpoint = QQConnectDefaults.OpenIdEndpoint;

            CallbackPath = new PathString(QQConnectDefaults.CallbackPath);
            AuthorizationEndpoint = QQConnectDefaults.AuthorizationEndpoint;
            TokenEndpoint = QQConnectDefaults.TokenEndpoint;
            UserInformationEndpoint = QQConnectDefaults.UserInformationEndpoint;

            Scope.Add(QQConnectScopes.Items.get_user_info.ToString());
            //QQOAuthScopes.TryAdd(Scope,
            //    QQOAuthScopes.Items.get_user_info,
            //    QQOAuthScopes.Items.list_album,
            //    QQOAuthScopes.Items.upload_pic,
            //    QQOAuthScopes.Items.do_like);

            DisplayStyle = "";//mobile, default for Desktop Web Style.

            ClaimsIssuer = QQConnectDefaults.ClaimsIssuer;

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "openid");
            ClaimActions.MapJsonKey(ClaimTypes.Name, "nickname");
            ClaimActions.MapJsonKey(ClaimTypes.Gender, "gender");

            ClaimActions.MapJsonKey("urn:qq:client_id", "client_id");
            ClaimActions.MapJsonKey("urn:qq:openid", "openid");
            ClaimActions.MapJsonKey("urn:qq:nickname", "nickname");
            ClaimActions.MapJsonKey("urn:qq:figureurl", "figureurl");
            ClaimActions.MapJsonKey("urn:qq:figureurl_1", "figureurl_1");
            ClaimActions.MapJsonKey("urn:qq:figureurl_2", "figureurl_2");
            ClaimActions.MapJsonKey("urn:qq:figureurl_qq_1", "figureurl_qq_1");
            ClaimActions.MapJsonKey("urn:qq:figureurl_qq_2", "figureurl_qq_2");
            ClaimActions.MapJsonKey("urn:qq:gender", "gender");
            ClaimActions.MapJsonKey("urn:qq:is_yellow_vip", "is_yellow_vip");
            ClaimActions.MapJsonKey("urn:qq:vip", "vip");
            ClaimActions.MapJsonKey("urn:qq:yellow_vip_level", "yellow_vip_level");
            ClaimActions.MapJsonKey("urn:qq:level", "level");
            ClaimActions.MapJsonKey("urn:qq:is_yellow_year_vip", "is_yellow_year_vip");
        }

        public override void Validate()
        {
            if (string.IsNullOrEmpty(OpenIdEndpoint))
            {
                throw new ArgumentNullException(nameof(OpenIdEndpoint));
            }

            base.Validate();
        }
    }
}
