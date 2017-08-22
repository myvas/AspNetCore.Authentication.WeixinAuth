using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Events
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="ClaimsIdentity"/>.
    /// </summary>
    public class WeixinOAuthCreatingTicketContext : BaseWeixinOAuthContext
    {
        /// <summary>
        /// Initializes a new <see cref="WeixinOAuthCreatingTicketContext"/>.
        /// </summary>
        /// <param name="context">The HTTP environment.</param>
        /// <param name="options">The options used by the authentication middleware.</param>
        /// <param name="backchannel">The HTTP client used by the authentication middleware</param>
        /// <param name="ticket">The <see cref="AuthenticationTicket"/>.</param>
        /// <param name="tokens">The tokens returned from the token endpoint.</param>
        public WeixinOAuthCreatingTicketContext(
            HttpContext context,
            AuthenticationScheme scheme,
            WeixinOAuthOptions options,
            HttpClient backchannel,
            AuthenticationTicket ticket,
            WeixinOAuthTokenResponse tokens)
            : this(context, scheme, options, backchannel, ticket, tokens, user: new JObject())
        {
        }

        /// <summary>
        /// Initializes a new <see cref="OAuthCreatingTicketContext"/>.
        /// </summary>
        /// <param name="context">The HTTP environment.</param>
        /// <param name="options">The options used by the authentication middleware.</param>
        /// <param name="backchannel">The HTTP client used by the authentication middleware</param>
        /// <param name="ticket">The <see cref="AuthenticationTicket"/>.</param>
        /// <param name="tokens">The tokens returned from the token endpoint.</param>
        /// <param name="user">The JSON-serialized user.</param>
        public WeixinOAuthCreatingTicketContext(
            HttpContext context,
            AuthenticationScheme scheme,
            WeixinOAuthOptions options,
            HttpClient backchannel,
            AuthenticationTicket ticket,
            WeixinOAuthTokenResponse tokens,
            JObject user)
            : base(context, scheme, options)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (backchannel == null)
            {
                throw new ArgumentNullException(nameof(backchannel));
            }
            if (tokens == null)
            {
                throw new ArgumentNullException(nameof(tokens));
            }

            TokenResponse = tokens;
            Backchannel = backchannel;
            Ticket = ticket;
            User = user ?? new JObject();
        }

        /// <summary>
        /// Gets the JSON-serialized user or an empty
        /// <see cref="JObject"/> if it is not available.
        /// </summary>
        public JObject User { get; }

        /// <summary>
        /// Gets the token response returned by the authentication service.
        /// </summary>
        public WeixinOAuthTokenResponse TokenResponse { get; }

        /// <summary>
        /// Gets the access token provided by the authentication service.
        /// </summary>
        public string AccessToken => TokenResponse.AccessToken;

        /// <summary>
        /// Gets the access token type provided by the authentication service.
        /// </summary>
        public string TokenType => TokenResponse.TokenType;

        /// <summary>
        /// Gets the refresh token provided by the authentication service.
        /// </summary>
        public string RefreshToken => TokenResponse.RefreshToken;

        /// <summary>
        /// Gets the access token expiration time.
        /// </summary>
        public TimeSpan? ExpiresIn
        {
            get
            {
                int value;
                if (int.TryParse(TokenResponse.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                {
                    return TimeSpan.FromSeconds(value);
                }

                return null;
            }
        }

        /// <summary>
        /// Gets the backchannel used to communicate with the provider.
        /// </summary>
        public HttpClient Backchannel { get; }

        /// <summary>
        /// The <see cref="AuthenticationTicket"/> that will be created.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }

        /// <summary>
        /// Gets the main identity exposed by <see cref="Ticket"/>.
        /// This property returns <c>null</c> when <see cref="Ticket"/> is <c>null</c>.
        /// </summary>
        public ClaimsIdentity Identity => Ticket?.Principal.Identity as ClaimsIdentity;

    }
}
