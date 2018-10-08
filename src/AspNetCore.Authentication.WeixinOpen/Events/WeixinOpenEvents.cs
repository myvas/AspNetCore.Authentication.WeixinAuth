using AspNetCore.Authentication.WeixinOpen.Internal;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinOpen.Events
{
    /// <summary>
    /// Default <see cref="IWeixinOAuthEvents"/> implementation.
    /// </summary>
    public class WeixinOpenEvents<TOptions> : RemoteAuthenticationEvents
        where TOptions : WeixinOpenOptions, new()
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
        /// </summary>
        public Func<WeixinOpenCreatingTicketContext<TOptions>, Task> OnCreatingTicket { get; set; } = context => TaskCache.CompletedTask;

        /// <summary>
        /// Gets or sets the delegate that is invoked when the RedirectToAuthorizationEndpoint method is invoked.
        /// </summary>
        public Func<WeixinOpenRedirectToAuthorizationContext<TOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return TaskCache.CompletedTask;
        };

        /// <summary>
        /// Invoked after the provider successfully authenticates a user.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task CreatingTicket(WeixinOpenCreatingTicketContext<TOptions> context) => OnCreatingTicket(context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the OAuth middleware.
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="Http.Authentication.AuthenticationProperties"/> of the challenge.</param>
        public virtual Task RedirectToAuthorizationEndpoint(WeixinOpenRedirectToAuthorizationContext<TOptions> context) => OnRedirectToAuthorizationEndpoint(context);
    }
}