using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.WebUtilities;
using System.Net.Http;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using System;
using System.Text;

namespace AspNetCore.Authentication.QQConnect
{
    public class QQConnectHandler : OAuthHandler<QQConnectOptions>
    {
        ILogger<QQConnectHandler> _logger;

        public QQConnectHandler(
            IOptionsMonitor<QQConnectOptions> options,
            ILoggerFactory loggerFactory, UrlEncoder encoder, ISystemClock clock)
            : base(options, loggerFactory, encoder, clock)
        {
            _logger = loggerFactory.CreateLogger<QQConnectHandler>();
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity,
            AuthenticationProperties properties,
            OAuthTokenResponse tokens)
        {
            // Get the openId and clientId
            var openIdParameters = new Dictionary<string, string>()
            {
                { "access_token", tokens.AccessToken}
            };
            var requestUrl = QueryHelpers.AddQueryString(Options.OpenIdEndpoint, openIdParameters);
            var response = await Backchannel.GetAsync(requestUrl, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"An error occurred when retrieving user openid ({response.StatusCode}).");
            }
            var content = await response.Content.ReadAsStringAsync();
            var contentRegex = new Regex(@"callback\((.*)\);", RegexOptions.Compiled);
            var match = contentRegex.Match(content);
            if (!match.Success)
            {
                var msg = $"获取openid错误,content:{content}";
                _logger.LogError(msg);
                throw new HttpRequestException($"An error occurred when parsing response message for user openid. Please contact us if the spec changed.");
            }
            var payload = JObject.Parse(match.Groups[1].Value);
            //{“client_id”:”YOUR_APPID”,”openid”:”YOUR_OPENID”}
            var clientId = payload.Value<string>("client_id");
            var openid = payload.Value<string>("openid");

            // Get the UserInfo
            var getUserInfoParameters = new Dictionary<string, string>()
            {
                {"access_token", tokens.AccessToken},
                {"oauth_consumer_key", clientId},
                {"openid", openid }
            };
            var userInfoRequestUrl = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, getUserInfoParameters);
            var userInfoRsp = await Backchannel.GetAsync(userInfoRequestUrl, Context.RequestAborted);
            var userInfoPayload = JObject.Parse(await userInfoRsp.Content.ReadAsStringAsync());
            userInfoPayload.Add("openid", openid);
            userInfoPayload.Add("client_id", clientId);

            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, userInfoPayload);//, ticket, Context, Options, Backchannel, tokens, userInfoPayload);
            context.RunClaimActions();

            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            queryStrings.Add("response_type", "code");
            queryStrings.Add("client_id", Options.ClientId);
            queryStrings.Add("redirect_uri", redirectUri);

            AddQueryString(queryStrings, properties, QQConnectChallengeProperties.ScopeKey, FormatScope, Options.Scope);
            //if (string.Compare(Options.DisplayStyle, "mobile", true) == 0)
            {
                AddQueryString(queryStrings, properties, QQConnectChallengeProperties.DisplayStyleKey, Options.DisplayStyle);
            }
            AddQueryString(queryStrings, properties, QQConnectChallengeProperties.LoginHintKey);

            var state = Options.StateDataFormat.Protect(properties);
            queryStrings.Add("state", state);

            var authorizationEndpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
            return authorizationEndpoint;
        }

        #region AddQueryString
        // Copy from Microsoft.AspNetCore.Authentication.Google/GoogleHandler.cs
        private void AddQueryString<T>(
            IDictionary<string, string> queryStrings,
            AuthenticationProperties properties,
            string name,
            Func<T, string> formatter,
            T defaultValue)
        {
            string value = null;
            var parameterValue = properties.GetParameter<T>(name);
            if (parameterValue != null)
            {
                value = formatter(parameterValue);
            }
            else if (!properties.Items.TryGetValue(name, out value))
            {
                value = formatter(defaultValue);
            }

            // Remove the parameter from AuthenticationProperties so it won't be serialized into the state
            properties.Items.Remove(name);

            if (value != null)
            {
                queryStrings[name] = value;
            }
        }

        private void AddQueryString(
            IDictionary<string, string> queryStrings,
            AuthenticationProperties properties,
            string name,
            string defaultValue = null)
            => AddQueryString(queryStrings, properties, name, x => x, defaultValue);
        #endregion

        /// <summary>
        /// 腾讯定义的接口方法与标准方法不一致，故须覆写此函数。
        /// </summary>
        /// <param name="code"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                { "client_id", Options.ClientId },
                { "redirect_uri", redirectUri },
                { "client_secret", Options.ClientSecret },
                { "code", code },
                { "grant_type", "authorization_code" },
            };

            var requestUrl = QueryHelpers.AddQueryString(Options.TokenEndpoint, tokenRequestParameters);

            var response = await Backchannel.GetAsync(requestUrl, Context.RequestAborted);
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                //access_token=FE04************************CCE2&expires_in=7776000&refresh_token=88E4************************BE14
                var payload = ParseQuery(content);
                payload.Add("token_type", ""); //Unkown type!
                return OAuthTokenResponse.Success(payload);
            }
            else
            {
                var error = "OAuth token endpoint failure: " + await Display(response);
                //_logger.LogError(error);
                return OAuthTokenResponse.Failed(new Exception(error));
            }
        }

        private JObject ParseQuery(string query)
        {
            var jObject = new JObject();

            foreach (var kv in query.Split('&'))
            {
                var keyValue = kv.Split('=');

                jObject.Add(keyValue[0], new JValue(keyValue[1]));
            }

            return jObject;
        }

        // Copy from Microsoft.AspNetCore.Authentication.OAuth/OAuthHandler.cs
        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers.ToString() + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }
    }
}