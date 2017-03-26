using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Authentication;

namespace AspNetCore.WeixinOAuth.Events
{
    /// <summary>
    /// Specifies callback methods which the <see cref="OAuthMiddleware{T}"/> invokes to enable developer control over the authentication process.
    /// </summary>
    public interface IWeixinOAuthEvents : IRemoteAuthenticationEvents
    {
        /// <summary>
        /// Invoked after the provider successfully authenticates a user. This can be used to retrieve user information.
        /// This event may not be invoked by sub-classes of OAuthAuthenticationHandler if they override CreateTicketAsync.
        /// </summary>
        /// <param name="context">Contains information about the login session.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task CreatingTicket(WeixinOAuthCreatingTicketContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to the authorize endpoint.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge.</param>
        Task RedirectToAuthorizationEndpoint(WeixinOAuthRedirectToAuthorizationContext context);
    }
}
