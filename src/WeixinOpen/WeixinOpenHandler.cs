using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Myvas.AspNetCore.Authentication.WeixinOpen
{
    internal class WeixinOpenHandler : OAuthHandler<WeixinOpenOptions>
    {
        private readonly IWeixinOpenApi _api;

        public WeixinOpenHandler(
            IWeixinOpenApi api,
            IOptionsMonitor<WeixinOpenOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, loggerFactory, encoder, clock)
        {
            _api = api ?? throw new ArgumentNullException(nameof(api));
        }

        protected const string CorrelationPrefix = ".AspNetCore.Correlation.";
        protected const string CorrelationProperty = ".xsrf";
        //protected const string CorrelationMarker = "N";
        protected const string AuthSchemeKey = ".AuthScheme";

        protected static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

        protected virtual List<string> SplitScope(string scope)
        {
            var result = new List<string>();
            if (string.IsNullOrWhiteSpace(scope)) return result;
            return scope.Split(',').ToList();
        }

        /// <summary>
        /// 生成网页授权调用URL，用于获取code。（然后可以用此code换取网页授权access_token）
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="redirectUri">跳转回调redirect_uri，应当使用https链接来确保授权code的安全性。请在传入前使用UrlEncode对链接进行处理。</param>
        /// <returns></returns>
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            //注意：参数只有五个，顺序不能改变！微信对该链接做了正则强匹配校验，如果链接的参数顺序不对，授权页面将无法正常访问!!!
            var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            queryStrings.Add("appid", Options.AppId);
            queryStrings.Add("redirect_uri", redirectUri);
            queryStrings.Add("response_type", "code");

            var scope = PickAuthenticationProperty(properties, OAuthChallengeProperties.ScopeKey, FormatScope, Options.Scope);
            queryStrings.Add(OAuthChallengeProperties.ScopeKey, scope);

            var state = Options.StateDataFormat.Protect(properties);
            queryStrings.Add("state", state);

            var authorizationUrl = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
            return authorizationUrl + "#wechat_redirect";
        }

        protected override string FormatScope(IEnumerable<string> scopes)
            => string.Join(",", scopes); // // OAuth2 3.3 space separated, but weixin not

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
        /// Step 2：通过code获取access_token
        /// </summary> 
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            return await _api.GetToken(Options.Backchannel, Options.TokenEndpoint, Options.AppId, Options.AppSecret, code, Context.RequestAborted);
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
        /// Call the OAuthServer and get a user's information.
        /// The context object will have the Identity, AccessToken, and UserInformationEndpoint available.
        /// Using this information, we can query the auth server for claims to attach to the identity.
        /// A particular OAuthServer's endpoint returns a json object with a roles member and a name member.
        /// We call this endpoint with HttpClient, parse the result, and attach the claims to the Identity.
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="properties"></param>
        /// <param name="tokens"></param>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            ClaimsIdentity identity,
            AuthenticationProperties properties,
            OAuthTokenResponse tokens)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }
            if (tokens == null)
            {
                throw new ArgumentNullException(nameof(tokens));
            }

            var openid = tokens.Response.Value<string>("openid");
            var unionid = tokens.Response.Value<string>("unionid");
            var scope = tokens.Response.Value<string>("scope");

            var userInfoPayload = await _api.GetUserInfo(Options.Backchannel, Options.UserInformationEndpoint, tokens.AccessToken, openid, Context.RequestAborted, WeixinOpenLanguageCodes.zh_CN);
            userInfoPayload.Add("scope", scope);

            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, userInfoPayload);
            context.RunClaimActions();

            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }
    }
}