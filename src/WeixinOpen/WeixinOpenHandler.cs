using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
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

            //未找到官方说明，但实验证明properties添加returnUrl和scheme后，state为1264字符，此时报错：state参数过长。所以properties只能存放在Cookie中，state作为Cookie值的索引键。
            //var state = Options.StateDataFormat.Protect(properties);
            //queryStrings.Add("state", state);
            var correlationId = properties.Items[CorrelationProperty];
            Context.Response.Cookies.Append(BuildStateCookieName(correlationId), Options.StateDataFormat.Protect(properties));
            queryStrings.Add("state", correlationId);

            var authorizationUrl = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
            return authorizationUrl + "#wechat_redirect";
        }

        #region Handle big properties protected output, by store it to cookie 'xxxx.state'
        private const string CorrelationMarker = "N";
        protected virtual string BuildCorelationCookieName(string correlationId)
        {
            return Options.CorrelationCookie.Name + Scheme.Name + "." + correlationId;
        }
        protected virtual string BuildStateCookieName(string correlationId)
        {
            return Options.CorrelationCookie.Name + Scheme.Name + "." + correlationId + "." + CorrelationMarker;
        }
        #endregion

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

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var query = Request.Query;

            var error = query["error"];
            if (!StringValues.IsNullOrEmpty(error))
            {
                var failureMessage = new StringBuilder();
                failureMessage.Append(error);
                var errorDescription = query["error_description"];
                if (!StringValues.IsNullOrEmpty(errorDescription))
                {
                    failureMessage.Append(";Description=").Append(errorDescription);
                }
                var errorUri = query["error_uri"];
                if (!StringValues.IsNullOrEmpty(errorUri))
                {
                    failureMessage.Append(";Uri=").Append(errorUri);
                }

                return HandleRequestResult.Fail(failureMessage.ToString());
            }

            var state = query["state"]; // ie. correlationId
            if (StringValues.IsNullOrEmpty(state))
            {
                return HandleRequestResult.Fail("The oauth state was missing.");
            }

            var stateCookieName = BuildStateCookieName(state);
            var protectedProperties = Request.Cookies[stateCookieName];
            if (string.IsNullOrEmpty(protectedProperties))
            {
                return HandleRequestResult.Fail($"The oauth state cookie was missing: Cookie: {stateCookieName}");
            }

            var cookieOptions = Options.CorrelationCookie.Build(Context, Clock.UtcNow);
            Response.Cookies.Delete(stateCookieName, cookieOptions);

            var properties = Options.StateDataFormat.Unprotect(protectedProperties);
            if (properties == null)
            {
                return HandleRequestResult.Fail($"The oauth state cookie was invalid: Cookie: {stateCookieName}");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }


            var code = query["code"];

            if (StringValues.IsNullOrEmpty(code))
            {
                Logger.LogWarning("Code was not found.", properties);
                return HandleRequestResult.Fail("Code was not found.", properties);
            }

            var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));

            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error, properties);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.", properties);
            }

            var identity = new ClaimsIdentity(ClaimsIssuer);

            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();

                authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.access_token, Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.refresh_token, Value = tokens.RefreshToken });
                }
                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.token_type, Value = tokens.TokenType });
                }
                if (!string.IsNullOrEmpty(tokens.GetOpenId()))
                {
                    authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.openid, Value = tokens.GetOpenId() });
                }
                if (!string.IsNullOrEmpty(tokens.GetUnionId()))
                {
                    authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.unionid, Value = tokens.GetUnionId() });
                }
                if (!string.IsNullOrEmpty(tokens.GetScope()))
                {
                    authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.scope, Value = tokens.GetScope() });
                }
                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = WeixinAuthenticationTokenNames.expires_at,
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }

                properties.StoreTokens(authTokens); //ExternalLoginInfo.AuthenticationTokens
            }


            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.", properties);
            }
        }

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