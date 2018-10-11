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
        private readonly IQQConnectApi _api;

        public QQConnectHandler(
            IQQConnectApi api,
            IOptionsMonitor<QQConnectOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, loggerFactory, encoder, clock)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity,
            AuthenticationProperties properties,
            OAuthTokenResponse tokens)
        {
            // Get the openId and clientId
            var payload = await _api.GetOpenId(Options.Backchannel, Options.OpenIdEndpoint, tokens.AccessToken, Context.RequestAborted);
            //{“client_id”:”YOUR_APPID”,”openid”:”YOUR_OPENID”}
            var clientId = payload.Value<string>("client_id");
            var openid = payload.Value<string>("openid");

            // Get the UserInfo
            var userInfoPayload = await _api.GetUserInfo(Options.Backchannel, Options.UserInformationEndpoint, tokens.AccessToken, openid, clientId, Context.RequestAborted);
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

            var scope = PickAuthenticationProperty(properties, QQConnectChallengeProperties.ScopeKey, FormatScope, Options.Scope);
            var display = PickAuthenticationProperty(properties, QQConnectChallengeProperties.DisplayStyleKey, Options.DisplayStyle);

            var state = Options.StateDataFormat.Protect(properties);

            queryStrings.Add("state", state);
            queryStrings.Add(QQConnectChallengeProperties.ScopeKey, scope);
            queryStrings.Add(QQConnectChallengeProperties.DisplayStyleKey, display);

            var authorizationEndpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
            return authorizationEndpoint;
        }

        protected override string FormatScope(IEnumerable<string> scopes)
            => string.Join(",", scopes); // WeixinOpen comma separated

        #region Pick value from AuthenticationProperties
        private static string PickAuthenticationProperty<T>(
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

            return value;
        }

        private static string PickAuthenticationProperty(
            AuthenticationProperties properties,
            string name,
            string defaultValue = null)
            => PickAuthenticationProperty(properties, name, x => x, defaultValue);
        #endregion

        /// <summary>
        /// 腾讯定义的接口方法与标准方法不一致，故须覆写此函数。
        /// </summary>
        /// <param name="code"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            return await _api.GetToken(Options.Backchannel, Options.TokenEndpoint, Options.AppId, Options.AppKey, code, redirectUri, Context.RequestAborted);
        }
    }
}