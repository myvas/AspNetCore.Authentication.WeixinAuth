using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using AspNetCore.WeixinOAuth.Demo.Data;
using Microsoft.EntityFrameworkCore;

namespace Microsoft.AspNetCore.Identity.EntityFrameworkCore
{
    /// <summary>
    /// User store with custimized AppUser implementation
    /// </summary>
    public class AppUserStore : UserStore<AppUser>
    {
        public AppUserStore(AppDbContext context, IdentityErrorDescriber describer = null)
            : base(context, describer)
        {
        }

        /// <summary>
        /// Gets the user, if any, associated with the specified, chinese mobile phone number.
        /// </summary>
        /// <param name="phoneNumber"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task<AppUser> FindByPhoneNumberAsync(string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return Users.FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber, cancellationToken);
        }

        /// <summary>
        /// Gets the user, if any, associated with the specified, chinese mobile phone number.
        /// </summary>
        /// <param name="phoneNumber"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task<AppUser> FindByConfirmedPhoneNumberAsync(string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return Users.FirstOrDefaultAsync(u => u.PhoneNumberConfirmed && (u.PhoneNumber == phoneNumber), cancellationToken);
        }

        private DbSet<IdentityUserExternalLogin> UserExternalLogins { get { return Context.Set<IdentityUserExternalLogin>(); } }
        public virtual Task<int> AddAuthenticatedWithQrAsync(string correlationId, UserLoginInfo login, CancellationToken cancellationToken=default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var data = CreateUserExternalLogin(correlationId, login);
            Context.Add(data);
            return Context.SaveChangesAsync(cancellationToken);
            //UserExternalLogins.Add();
            //return Task.CompletedTask;
        }

        /// <summary>
        /// Called to create a new instance of a <see cref="IdentityUserLogin{TKey}"/>.
        /// </summary>
        /// <param name="user">The associated user.</param>
        /// <param name="login">The sasociated login.</param>
        /// <returns></returns>
        protected virtual IdentityUserExternalLogin CreateUserExternalLogin(string correlationId, UserLoginInfo login)
        {
            return new IdentityUserExternalLogin
            {
                CorrelationId = correlationId,
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName
            };
        }

        /// <summary>
        /// Return a user external login with the matching correlationId, provider if it exists.
        /// </summary>
        /// <param name="correlationId">The correlation's id.</param>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user external login if it exists.</returns>
        public virtual Task<IdentityUserExternalLogin> FindAuthenticatedWithQrAsync(string correlationId, string loginProvider, CancellationToken cancellationToken)
        {
            return UserExternalLogins.SingleOrDefaultAsync(userLogin => userLogin.CorrelationId.Equals(correlationId) && userLogin.LoginProvider == loginProvider, cancellationToken);
        }
    }
}
