using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
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
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace AspNetCore.WeixinOAuth
{
    internal class WeixinOAuthHandler : RemoteAuthenticationHandler<WeixinOAuthOptions>
    {
        protected const string CorrelationPrefix = ".AspNetCore.Correlation.";
        protected const string CorrelationProperty = ".xsrf";
        //protected const string CorrelationMarker = "N";
        protected const string AuthSchemeKey = ".AuthScheme";

        protected static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

        protected HttpClient Backchannel => Options.Backchannel;

        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring. 
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new WeixinOAuthEvents Events
        {
            get { return (WeixinOAuthEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Creates a new instance of the events instance.
        /// </summary>
        /// <returns>A new instance of the events instance.</returns>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new WeixinOAuthEvents());

        public WeixinOAuthHandler(IOptionsMonitor<WeixinOAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

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
            //state：腾讯非QR方式最长只能128字节，所以只能设计一个correlationId指向到特定的Cookie键值，实现各参数的存取。
            //see: https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140842&token=&lang=zh_CN
            var correlationId = properties.Items[CorrelationProperty];
            var state = correlationId;

            //注意：参数顺序也不能乱！微信对该链接做了正则强匹配校验，如果链接的参数顺序不对，授权页面将无法正常访问
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

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
            var redirectContext = new WeixinOAuthRedirectToAuthorizationContext(
                Context, Scheme, Options,
                properties, authorizationEndpoint);
            await Events.RedirectToAuthorizationEndpoint(redirectContext);
            Logger.LogInformation($"Redirecting to {authorizationEndpoint}...");
        }

        public override Task<bool> ShouldHandleRequestAsync() => Task.FromResult(Options.CallbackPath == Request.Path);

        public override async Task<bool> HandleRequestAsync()
        {
            if (!await ShouldHandleRequestAsync()) //signin-weixin-oauth
            {
                return false;
            }

            AuthenticationTicket ticket = null;
            Exception exception = null;
            try
            {
                var authResult = await HandleRemoteAuthenticateAsync();
                if (authResult == null)
                {
                    exception = new InvalidOperationException("Invalid return state, unable to redirect.");
                }
                else if (authResult.Handled)
                {
                    return true;
                }
                else if (authResult.Skipped || authResult.None)
                {
                    return false;
                }
                else if (!authResult.Succeeded)
                {
                    exception = authResult.Failure ??
                                new InvalidOperationException("Invalid return state, unable to redirect.");
                }

                ticket = authResult.Ticket;
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            if (exception != null)
            {
                Logger.LogWarning($"Error on remote authentication: {exception.Message}");

                var errorContext = new RemoteFailureContext(Context, Scheme, Options, exception);
                await Events.RemoteFailure(errorContext);

                if (errorContext.Result != null)
                {
                    if (errorContext.Result.Handled)
                    {
                        return true;
                    }
                    else if (errorContext.Result.Skipped)
                    {
                        return false;
                    }
                }

                throw exception;
            }

            // We have a ticket if we get here
            var ticketContext = new TicketReceivedContext(Context, Scheme, Options, ticket)
            {
                ReturnUri = ticket.Properties.RedirectUri
            };
            // REVIEW: is this safe or good?
            ticket.Properties.RedirectUri = null;

            // Mark which provider produced this identity so we can cross-check later in HandleAuthenticateAsync
            ticketContext.Properties.Items[AuthSchemeKey] = Scheme.Name;

            await Events.TicketReceived(ticketContext);

            if (ticketContext.Result != null)
            {
                if (ticketContext.Result.Handled)
                {
                    Logger.LogInformation($"Signin handled.");
                    return true;
                }
                else if (ticketContext.Result.Skipped)
                {
                    Logger.LogInformation($"Signin skipped.");
                    return false;
                }
            }

            await Context.SignInAsync(SignInScheme, ticketContext.Principal, ticketContext.Properties);

            // Default redirect path is the base path
            if (string.IsNullOrEmpty(ticketContext.ReturnUri))
            {
                ticketContext.ReturnUri = "/";
            }

            Response.Redirect(ticketContext.ReturnUri);
            return true;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var result = await Context.AuthenticateAsync(SignInScheme);
            if (result != null)
            {
                if (result.Failure != null)
                {
                    return result;
                }

                // The SignInScheme may be shared with multiple providers, make sure this provider issued the identity.
                string authenticatedScheme;
                var ticket = result.Ticket;
                if (ticket != null && ticket.Principal != null && ticket.Properties != null
                    && ticket.Properties.Items.TryGetValue(AuthSchemeKey, out authenticatedScheme)
                    && string.Equals(Scheme.Name, authenticatedScheme, StringComparison.Ordinal))
                {
                    return AuthenticateResult.Success(new AuthenticationTicket(ticket.Principal,
                        ticket.Properties, Scheme.Name));
                }

                return AuthenticateResult.Fail("Not authenticated");
            }

            return AuthenticateResult.Fail("Remote authentication does not directly support AuthenticateAsync");
        }
        
        protected override Task HandleForbiddenAsync(AuthenticationProperties properties) => Context.ForbidAsync(SignInScheme);

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
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

                return HandleRequestResult.Fail(failureMessage.ToString());
            }

            var code = query["code"];
            var state = query["state"]; // correlationId

            if (StringValues.IsNullOrEmpty(code))
            {
                Logger.LogWarning("Code was not found.");
                return HandleRequestResult.Fail("Code was not found.");
            }

            if (StringValues.IsNullOrEmpty(state))
            {
                Logger.LogWarning("State was not found.");
                return HandleRequestResult.Fail("State was not found.");
            }

            var stateCookieName = ConcateCookieName(state);
            var protectedProperties = Request.Cookies[stateCookieName];
            if (string.IsNullOrEmpty(protectedProperties))
            {
                var errMsg = $"'{stateCookieName}' cookie not found.";
                Logger.LogWarning(errMsg);
                return HandleRequestResult.Fail("Correlation failed." + errMsg);
            }

            properties = Options.StateDataFormat.Unprotect(protectedProperties);
            if (properties == null)
            {
                var errMsg = "The oauth state was missing or invalid.";
                Logger.LogWarning(errMsg);
                return HandleRequestResult.Fail(errMsg);
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties, state))
            {
                var errMsg = "Correlation failed. Correlation id not valid.";
                Logger.LogWarning(errMsg);
                return HandleRequestResult.Fail(errMsg);
            }

            //通过code换取网页授权access_token
            var tokens = await CustomExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));
            if (tokens.Error != null)
            {
                Logger.LogWarning(tokens.Error.StackTrace);
                return HandleRequestResult.Fail(tokens.Error);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                Logger.LogWarning("Failed to retrieve access token.");
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            }

            var identity = new ClaimsIdentity(Options.SignInScheme);
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

            var ticket = await CustomCreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                Logger.LogWarning("Failed to retrieve user information from remote server.");
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.");
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
            else
            {
                identity.AddOptionalClaim(ClaimTypes.Name, $"[{openId}]", this.Options.ClaimsIssuer);
            }

            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
            var context = new WeixinOAuthCreatingTicketContext(Context, Scheme, Options, Backchannel, ticket, tokens);
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