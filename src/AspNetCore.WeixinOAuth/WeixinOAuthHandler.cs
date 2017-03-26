using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Security.Claims;
using System;
using System.Security.Cryptography;
using Microsoft.Extensions.Primitives;
using Microsoft.AspNetCore.Http.Features.Authentication;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Linq;
using Microsoft.AspNetCore.Http;
using AspNetCore.WeixinOAuth.Events;
using AspNetCore.WeixinOAuth.Messages;
using AspNetCore.WeixinOAuth.Extensions;

namespace AspNetCore.WeixinOAuth
{
    internal class WeixinOAuthHandler : RemoteAuthenticationHandler<WeixinOAuthOptions>
    {
        protected const string CorrelationPrefix = ".AspNetCore.Correlation.";
        protected const string CorrelationProperty = ".xsrf";
        //protected const string CorrelationMarker = "N";
        protected const string AuthSchemeKey = ".AuthScheme";

        protected static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

        protected HttpClient Backchannel { get; private set; }

        public WeixinOAuthHandler(HttpClient backchannel)
        {
            Backchannel = backchannel;
        }

        protected virtual string FormatScope()
        {
            // OAuth2 3.3 space separated, but weixin not
            return string.Join(",", Options.Scope);
        }

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
        protected virtual string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var scope = FormatScope();
            //TODO: state腾讯非QR方式最长只能128字节
            //see: https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140842&token=&lang=zh_CN
            var correlationId = properties.Items[CorrelationProperty];
            var state = correlationId;//Options.StateDataFormat.Protect(propertiesMinified);

            //注意：参数顺序也不能乱！微信说对该链接做了正则强匹配校验，如果链接的参数顺序不对，授权页面将无法正常访问
            var queryBuilder = new QueryBuilder()
            {
                { "appid", Options.AppId },
                { "redirect_uri", redirectUri },
                { "response_type", "code" },
                { "scope", scope },
                { "state", state }
            };
            return Options.AuthorizationEndpoint + queryBuilder + "#wechat_redirect";
        }

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = new AuthenticationProperties(context.Properties);

            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
            var redirectContext = new WeixinOAuthRedirectToAuthorizationContext(
                Context, Options,
                properties, authorizationEndpoint);
            await Options.Events.RedirectToAuthorizationEndpoint(redirectContext);
            Logger.LogInformation($"Redirecting to {authorizationEndpoint}...");
            return true;
        }


        protected override async Task<AuthenticateResult> HandleRemoteAuthenticateAsync()
        {
            Logger.LogInformation($"Handling callback from remote at {Options.CallbackPath}...");
            AuthenticationProperties properties = null;
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

                return AuthenticateResult.Fail(failureMessage.ToString());
            }

            var code = query["code"];
            var state = query["state"]; // correlationId

            var stateCookieName = ConcateCookieName(state);
            var protectedProperties = Request.Cookies[stateCookieName];
            if (string.IsNullOrEmpty(protectedProperties))
            {
                var errMsg = $"'{stateCookieName}' cookie not found.";
                Logger.LogWarning(errMsg);
                return AuthenticateResult.Fail("Correlation failed." + errMsg);
            }

            properties = Options.StateDataFormat.Unprotect(protectedProperties);
            if (properties == null)
            {
                var errMsg = "The oauth state was missing or invalid.";
                Logger.LogWarning(errMsg);
                return AuthenticateResult.Fail(errMsg);
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties, state))
            {
                var errMsg = "Correlation failed.";
                Logger.LogWarning(errMsg);
                return AuthenticateResult.Fail(errMsg);
            }

            if (StringValues.IsNullOrEmpty(code))
            {
                Logger.LogWarning("Code was not found.");
                return AuthenticateResult.Fail("Code was not found.");
            }

            var tokens = await CustomExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));
            if (tokens.Error != null)
            {
                Logger.LogWarning(tokens.Error.StackTrace);
                return AuthenticateResult.Fail(tokens.Error);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                Logger.LogWarning("Failed to retrieve access token.");
                return AuthenticateResult.Fail("Failed to retrieve access token.");
            }

            var identity = new ClaimsIdentity(Options.ClaimsIssuer);
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
                if (!string.IsNullOrEmpty(tokens.OpenId))
                {
                    authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.weixin_openid, Value = tokens.OpenId });
                }
                if (!string.IsNullOrEmpty(tokens.Scope))
                {
                    authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.weixin_scope, Value = tokens.Scope });
                }
                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Options.SystemClock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken { Name = WeixinAuthenticationTokenNames.expires_at, Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) });
                    }
                }

                properties.StoreTokens(authTokens); //ExternalLoginInfo.AuthenticationTokens
            }

            var ticket = await CustomCreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return AuthenticateResult.Success(ticket);
            }
            else
            {
                Logger.LogWarning("Failed to retrieve user information from remote server.");
                return AuthenticateResult.Fail("Failed to retrieve user information from remote server.");
            }
        }

        /// <summary>
        /// code -> oauth.access_token + openid
        /// </summary>
        /// <param name="code">用于换取网页授权access_token。此code只能使用一次，5分钟未被使用自动过期。</param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected virtual async Task<WeixinOAuthTokenResponse> CustomExchangeCodeAsync(string code, string redirectUri)
        {
            var query = new QueryBuilder()
            {
                { "appid", Options.AppId },
                { "secret", Options.AppSecret },
                { "code", code },
                { "grant_type", "authorization_code" },
                { "redirect_uri", redirectUri }
            };
            var url = Options.TokenEndpoint + query;
            Logger.LogInformation($"Exchanging code via {url}...");
            var response = await Backchannel.GetAsync(url, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                var error = "An error occured while exchanging the code.";
                Logger.LogError($"{error} The remote server returned a {response.StatusCode} response with the following payload: {response.Headers.ToString()} {await response.Content.ReadAsStringAsync()}");
                //throw new HttpRequestException($"{error}");
                return WeixinOAuthTokenResponse.Failed(new Exception(error));
            }
            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            var result = WeixinOAuthTokenResponse.Success(payload);
            //错误时微信会返回错误JSON数据包，示例如下: { "errcode":40029,"errmsg":"invalid code"}
            if (string.IsNullOrWhiteSpace(result.AccessToken))
            {
                int errorCode = WeixinOAuthHandlerHelper.GetErrorCode(payload);
                var errorMessage = WeixinOAuthHandlerHelper.GetErrorMessage(payload);
                return WeixinOAuthTokenResponse.Failed(new Exception($"The remote server returned an error while exchanging the code. {errorCode} {errorMessage}"));
            }
            return result;
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
        protected virtual async Task<AuthenticationTicket> CustomCreateTicketAsync(
            ClaimsIdentity identity, AuthenticationProperties properties, WeixinOAuthTokenResponse tokens)
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

            var openId = tokens.OpenId;
            var scope = tokens.Scope;
            // std:NameIdentifier
            identity.AddOptionalClaim(ClaimTypes.NameIdentifier, openId, Options.ClaimsIssuer);
            identity.AddOptionalClaim(WeixinOAuthClaimTypes.OpenId, openId, Options.ClaimsIssuer);
            // scope
            identity.AddOptionalClaim(WeixinOAuthClaimTypes.Scope, scope, Options.ClaimsIssuer);

            if (SplitScope(scope).Contains(WeixinOAuthScopes.snsapi_userinfo))
            {
                identity = await RetrieveUserInfoAsync(tokens.AccessToken, openId, identity);
            }

            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            var context = new WeixinOAuthCreatingTicketContext(Context, Options, Backchannel, ticket, tokens);
            await Options.Events.CreatingTicket(context);

            return context.Ticket;
        }

        private async Task<ClaimsIdentity> RetrieveUserInfoAsync(string accessToken, string openId, ClaimsIdentity identity)
        {
            //call userinfo
            var query = new QueryBuilder();
            query.Add("access_token", accessToken);
            query.Add("openid", openId);
            query.Add("lang", Options.LanguageCode);
            var url = Options.UserInformationEndpoint + query;
            Logger.LogInformation($"Retrieving user info via {url}...");
            var response = await Backchannel.GetAsync(url, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError($"An error occurred while retrieving the user profile: the remote server returned a {response.StatusCode} response with the following payload: {response.Headers.ToString()} {await response.Content.ReadAsStringAsync()}");
                throw new HttpRequestException("An error occured while retrieving the user profile.");
            }
            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            int errorCode = WeixinOAuthHandlerHelper.GetErrorCode(payload);
            if (errorCode != 0)
            {
                var errorMessage = WeixinOAuthHandlerHelper.GetErrorMessage(payload);
                Logger.LogError($"The remote server returned an error while retrieving the user profile. {errorCode} {errorMessage}");
                throw new Exception($"The remote server returned an error while retrieving the user profile. {errorCode} {errorMessage}");
            }
            else
            {
                //提取userinfo
                // std:Name
                var nickname = WeixinOAuthHandlerHelper.GetNickName(payload);
                identity.AddOptionalClaim(ClaimTypes.Name, nickname, this.Options.ClaimsIssuer);
                identity.AddOptionalClaim(WeixinOAuthClaimTypes.NickName, nickname, Options.ClaimsIssuer);

                var sex = WeixinOAuthHandlerHelper.GetGender(payload);
                identity.AddOptionalClaim(WeixinOAuthClaimTypes.Gender, sex, Options.ClaimsIssuer);

                var province = WeixinOAuthHandlerHelper.GetProvince(payload);
                identity.AddOptionalClaim(WeixinOAuthClaimTypes.Province, province, Options.ClaimsIssuer);

                var city = WeixinOAuthHandlerHelper.GetCity(payload);
                identity.AddOptionalClaim(WeixinOAuthClaimTypes.City, city, Options.ClaimsIssuer);

                var country = WeixinOAuthHandlerHelper.GetCountry(payload);
                identity.AddOptionalClaim(WeixinOAuthClaimTypes.Country, country, Options.ClaimsIssuer);

                var headImageUrl = WeixinOAuthHandlerHelper.GetHeadImageUrl(payload);
                identity.AddOptionalClaim(WeixinOAuthClaimTypes.HeadImageUrl, headImageUrl, Options.ClaimsIssuer);

                var privileges = WeixinOAuthHandlerHelper.GetPrivileges(payload);
                foreach (string privilege in privileges)
                {
                    identity.AddOptionalClaim(WeixinOAuthClaimTypes.Privilege, privilege, Options.ClaimsIssuer);
                }

                var unionId = WeixinOAuthHandlerHelper.GetUnionId(payload);
                identity.AddOptionalClaim(WeixinOAuthClaimTypes.UnionId, unionId, Options.ClaimsIssuer);
            }

            return identity;
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
                Expires = Options.SystemClock.UtcNow.Add(Options.RemoteAuthenticationTimeout),
            };

            properties.Items[CorrelationProperty] = correlationId; //need to build challenge url

            var cookieName = ConcateCookieName(correlationId);
            Response.Cookies.Append(cookieName, Options.StateDataFormat.Protect(properties), cookieOptions);
        }

        protected virtual string ConcateCookieName(string correlationId)
        {
            return CorrelationPrefix + Options.AuthenticationScheme + "." + correlationId;
        }

        protected override bool ValidateCorrelationId(AuthenticationProperties properties)
        {
            Logger.LogCritical($"The program try to invoke a not implementted method of ValidateCorrelationId() in WeixinOAuthHandler!");
            throw new NotImplementedException();
        }

        /// <summary>
        /// cut smaller of <see cref="AuthenticationProperties"/> to suit for WeixinOAuth State's limitation of 128 bytes.
        /// </summary>
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