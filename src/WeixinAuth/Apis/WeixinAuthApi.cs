using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinAuth
{
    public class WeixinAuthApi : IWeixinAuthApi
    {
        public ILogger Logger { get; }

        public WeixinAuthApi(IOptionsMonitor<WeixinAuthApi> optionsAccessor, ILoggerFactory loggerFactory)
        {
            Logger = loggerFactory?.CreateLogger<WeixinAuthApi>() ?? throw new ArgumentNullException(nameof(loggerFactory));
        }

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers.ToString() + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

        /// <summary>
        /// 通过code换取网页授权access_token。通过code换取的是一个特殊的网页授权access_token,与基础支持中的access_token（该access_token用于调用其他接口）不同。
        /// </summary>
        /// <param name="refreshToken">refresh_token拥有较长的有效期（30天），当refresh_token失效的后，需要用户重新授权，所以，请开发者在refresh_token即将过期时（如第29天时），进行定时的自动刷新并保存好它。</param>
        /// <remarks>尤其注意：由于公众号的secret和获取到的access_token安全级别都非常高，必须只保存在服务器，不允许传给客户端。后续刷新access_token、通过access_token获取用户信息等步骤，也必须从服务器发起。</remarks>
        /// <returns></returns>
        public async Task<OAuthTokenResponse> GetToken(HttpClient backchannel, string tokenEndpoint, string appId, string appSecret, string code, CancellationToken cancellationToken)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                ["appid"] = appId,
                ["secret"] = appSecret,
                ["code"] = code,
                ["grant_type"] = "authorization_code"
            };

            var requestUrl = QueryHelpers.AddQueryString(tokenEndpoint, tokenRequestParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = "OAuth token endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return OAuthTokenResponse.Failed(new Exception(error));
            }

            var content = await response.Content.ReadAsStringAsync();
            // { 
            //    "access_token":"ACCESS_TOKEN", 
            //    "expires_in":7200, 
            //    "refresh_token":"REFRESH_TOKEN",
            //    "openid":"OPENID", 
            //    "scope":"SCOPE",
            //    "unionid": "o6_bmasdasdsad6_2sgVt7hMZOPfL"
            //}
            var payload = JObject.Parse(content);
            int errorCode = WeixinAuthHandlerHelper.GetErrorCode(payload);
            if (errorCode != 0)
            {
                var error = "OAuth token endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return OAuthTokenResponse.Failed(new Exception(error));
            }

            //payload.Add("token_type", "");
            return OAuthTokenResponse.Success(payload);
        }


        /// <summary>
        /// 刷新或续期access_token使用。由于access_token有效期（目前为2个小时）较短，当access_token超时后，可以使用refresh_token进行刷新。
        /// </summary>
        /// <param name="refreshToken">refresh_token拥有较长的有效期（30天），当refresh_token失效的后，需要用户重新授权，所以，请开发者在refresh_token即将过期时（如第29天时），进行定时的自动刷新并保存好它。</param>
        /// <returns></returns>
        public async Task<OAuthTokenResponse> RefreshToken(HttpClient backchannel, string refreshTokenEndpoint, string appId, string refreshToken, CancellationToken cancellationToken)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                ["appid"] = appId,
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            };

            var requestUrl = QueryHelpers.AddQueryString(refreshTokenEndpoint, tokenRequestParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = "OAuth refresh token endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return OAuthTokenResponse.Failed(new Exception(error));
            }

            var content = await response.Content.ReadAsStringAsync();
            //{
            //    "access_token":"ACCESS_TOKEN",
            //    "expires_in":7200,
            //    "refresh_token":"REFRESH_TOKEN",
            //    "openid":"OPENID",
            //    "scope":"SCOPE"
            //}
            var payload = JObject.Parse(content);
            int errorCode = WeixinAuthHandlerHelper.GetErrorCode(payload);
            if (errorCode != 0)
            {
                var error = "OAuth refresh token endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return OAuthTokenResponse.Failed(new Exception(error));
            }

            return OAuthTokenResponse.Success(payload);
        }

        /// <summary>
        /// 检验授权凭证（access_token）是否有效。
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task<bool> ValidateToken(HttpClient backchannel, string validateTokenEndpoint, string appId, string accessToken, CancellationToken cancellationToken)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                ["appid"] = appId,
                ["access_token"] = accessToken
            };

            var requestUrl = QueryHelpers.AddQueryString(validateTokenEndpoint, tokenRequestParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = "OAuth validate token endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return false;
            }

            var content = await response.Content.ReadAsStringAsync();
            var payload = JObject.Parse(content);
            try
            {
                var errcode = payload.Value<int>("errcode");
                return (errcode == 0);
            }
            catch { }
            return false;
        }

        /// <summary>
        /// 获取用户个人信息（UnionID机制）
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        public async Task<JObject> GetUserInfo(HttpClient backchannel, string userInformationEndpoint, string accessToken, string openid, CancellationToken cancellationToken, LanguageCodes languageCode = LanguageCodes.zh_CN)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                ["access_token"] = accessToken,
                ["openid"] = openid,
                ["lang"] = languageCode.ToString()
            };

            var requestUrl = QueryHelpers.AddQueryString(userInformationEndpoint, tokenRequestParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = "OAuth userinformation endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return null;
            }

            var content = await response.Content.ReadAsStringAsync();
            //{
            //    "openid":"OPENID",
            //    "nickname":"NICKNAME",
            //    "sex":1,
            //    "province":"PROVINCE",
            //    "city":"CITY",
            //    "country":"COUNTRY",
            //    "headimgurl": "http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0",
            //    "privilege":[
            //        "PRIVILEGE1",
            //        "PRIVILEGE2"
            //    ],
            //    "unionid": " o6_bmasdasdsad6_2sgVt7hMZOPfL"
            //}
            var payload = JObject.Parse(content);

            int errorCode = WeixinAuthHandlerHelper.GetErrorCode(payload);
            if (errorCode != 0)
            {
                var error = "OAuth user information endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return null;
            }

            return payload;
        }
    }
}