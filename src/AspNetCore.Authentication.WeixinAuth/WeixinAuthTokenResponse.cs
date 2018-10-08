using Microsoft.AspNetCore.Authentication.OAuth;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinAuth
{
    public class WeixinAuthTokenResponse //: OAuthTokenResponse
    {
        /// <summary>
        /// weixin-oauth
        /// </summary>
        public const string FixedTokenType = "weixin-auth";

        /// <summary>
        /// 微信openid
        /// </summary>
        public string OpenId { get; set; }
        public string Scope { get; set; }

        #region Properties from OAuthTokenResponse
        public JObject Response { get; set; }
        public string AccessToken { get; set; }
        public string TokenType { get { return FixedTokenType; } }
        public string RefreshToken { get; set; }
        public string ExpiresIn { get; set; }
        public Exception Error { get; set; }
        #endregion

        public WeixinAuthTokenResponse() { }

        private WeixinAuthTokenResponse(JObject response)
        {
            Response = response;

            var errorCode = response.Value<string>("errcode");
            if (string.IsNullOrEmpty(errorCode))
            {
                AccessToken = response.Value<string>("access_token");
                ExpiresIn = response.Value<string>("expires_in");
                RefreshToken = response.Value<string>("refresh_token");
                OpenId = response.Value<string>("openid");
                Scope = response.Value<string>("scope");
            }
            else
            {
                var errorMsg = response.Value<string>("errmsg");
                Error = new Exception($"{errorCode} {errorMsg}");
            }
        }
        private WeixinAuthTokenResponse(Exception error)
        {
            Error = error;
        }

        public static WeixinAuthTokenResponse Success(JObject response)
        {
            return new WeixinAuthTokenResponse(response);
        }

        public static WeixinAuthTokenResponse Failed(Exception error)
        {
            return new WeixinAuthTokenResponse(error);
        }
    }
}
