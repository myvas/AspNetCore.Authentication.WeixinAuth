using AspNetCore.Authentication.WeixinAuth.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
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
using Base64UrlTextEncoder = Microsoft.AspNetCore.Authentication.Base64UrlTextEncoder;

namespace AspNetCore.Authentication.WeixinAuth
{
    internal class WeixinAuthHandler : OAuthHandler<WeixinAuthOptions>
    {
        private readonly IWeixinAuthApi _api;

        protected const string CorrelationPrefix = ".AspNetCore.Correlation.";
        protected const string CorrelationProperty = ".xsrf";

        protected static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

        public WeixinAuthHandler(
            IOptionsMonitor<WeixinAuthOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override string FormatScope(IEnumerable<string> scopes)
            => string.Join(",", scopes); // // OAuth2 3.3 space separated, but weixin not

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
            //state：腾讯非QR方式最长只能128字节，所以只能设计一个correlationId指向到特定的Cookie键值，实现各参数的存取。
            //see: https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140842&token=&lang=zh_CN
            var correlationId = properties.Items[CorrelationProperty];
            state = correlationId;
            queryStrings.Add("state", state);

            var authorizationUrl = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, queryStrings);
            return authorizationUrl + "#wechat_redirect";
        }

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

            var state = query["state"]; // ie. correlationId
            if (StringValues.IsNullOrEmpty(state))
            {
                return HandleRequestResult.Fail("The oauth state was missing.");
            }

            var stateCookieName = ConcateCookieName(state);
            var protectedProperties = Request.Cookies[stateCookieName];
            if (string.IsNullOrEmpty(protectedProperties))
            {
                return HandleRequestResult.Fail($"The oauth state cookie was missing: Cookie: {stateCookieName}");
            }

            var properties = Options.StateDataFormat.Unprotect(protectedProperties);
            if (properties == null)
            {
                return HandleRequestResult.Fail($"The oauth state cookie was invalid: Cookie: {stateCookieName}");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties, state))
            {
                return HandleRequestResult.Fail("Correlation failed.", properties);
            }

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

            var code = query["code"];

            if (StringValues.IsNullOrEmpty(code))
            {
                Logger.LogWarning("Code was not found.");
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
        /// code -> oauth.access_token + openid
        /// </summary>
        /// <param name="code">用于换取网页授权access_token。此code只能使用一次，5分钟未被使用自动过期。</param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
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

            var unionid = tokens.GetUnionId();
            var openid = tokens.GetOpenId();
            var scope = tokens.GetScope();

            JObject payload = new JObject();
            if (WeixinAuthScopes.Contains(scope, WeixinAuthScopes.Items.snsapi_userinfo))
            {
                payload = await _api.GetUserInfo(Options.Backchannel, Options.UserInformationEndpoint, tokens.AccessToken, openid, Context.RequestAborted, LanguageCodes.zh_CN);
            }
            if (!payload.ContainsKey("unionid") && string.IsNullOrWhiteSpace(unionid))
            {
                payload.Add("unionid", unionid);
            }
            if (!payload.ContainsKey("openid") && string.IsNullOrWhiteSpace(openid))
            {
                payload.Add("openid", openid);
            }
            payload.Add("scope", scope);

            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload);
            context.RunClaimActions();

            await Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="properties">properties only .Items[CorrelationProperty] used.</param>
        protected override void GenerateCorrelationId(AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            var bytes = new byte[32];
            CryptoRandom.GetBytes(bytes);
            var correlationId = Base64UrlTextEncoder.Encode(bytes);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                Expires = Clock.UtcNow.Add(Options.RemoteAuthenticationTimeout),
            };

            properties.Items[CorrelationProperty] = correlationId; //need to build challenge url

            var cookieName = ConcateCookieName(correlationId);
            Response.Cookies.Append(cookieName, Options.StateDataFormat.Protect(properties), cookieOptions);
        }

        protected virtual string ConcateCookieName(string correlationId)
        {
            return CorrelationPrefix + Scheme.Name + "." + correlationId;
        }

        protected override bool ValidateCorrelationId(AuthenticationProperties properties)
        {
            Logger.LogCritical($"The program try to invoke a not implementted method of ValidateCorrelationId() in WeixinOAuthHandler!");
            throw new NotImplementedException();
        }

        /// <summary>
        /// cut smaller of <see cref="AuthenticationProperties"/> to suit for WeixinOAuth State's limitation of 128 bytes.
        /// </summary>
        /// <remarks>The cookie of AspNetCore.Correlation.Weixin-OAuth.{correlationId} will be deleted in this method. </remarks>
        /// <param name="properties">from cookie. properties = Request.Cookies[ConcateCookieName(correlationId)];</param>
        /// <param name="state">from url</param>
        /// <returns></returns>
        protected virtual bool ValidateCorrelationId(AuthenticationProperties properties, string state)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            string correlationId;
            if (!properties.Items.TryGetValue(CorrelationProperty, out correlationId))
            {
                Logger.LogWarning($"{CorrelationProperty} state property not found.");
                return false;
            }
            properties.Items.Remove(CorrelationProperty);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps
            };
            var cookieName = ConcateCookieName(correlationId);
            Response.Cookies.Delete(cookieName, cookieOptions);

            if (!string.Equals(correlationId, state, StringComparison.Ordinal))
            {
                Logger.LogWarning($"The correlation value in cookie '{cookieName}' did not match the expected value '{state}'.");
                return false;
            }

            return true;
        }
    }
}