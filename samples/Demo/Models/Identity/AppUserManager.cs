using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Identity
{
    public class AppUserManager : UserManager<AppUser>, IDisposable
    {
        private readonly CancellationToken _cancel;

        protected override CancellationToken CancellationToken => _cancel;

        public AppUserManager(
            AppUserStore store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<AppUser> passwordHasher,
            IEnumerable<IUserValidator<AppUser>> userValidators,
            IEnumerable<IPasswordValidator<AppUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<AppUserManager> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators,
                  keyNormalizer, errors, services, logger)
        {
            _cancel = services?.GetService<IHttpContextAccessor>()?.HttpContext?.RequestAborted ?? CancellationToken.None;
            Store = store;
        }

        public virtual Task<AppUser> FindByPhoneNumberAsync(string phoneNumber)
        {
            ThrowIfDisposed();
            var store = Store as AppUserStore;
            if (store == null)
            {
                throw new NotSupportedException("Store does not implement AppUserStore.");
            }
            return store.FindByPhoneNumberAsync(phoneNumber, CancellationToken);
        }

        public virtual async Task<IdentityResult> ConfirmPhoneNumberAsync(AppUser user, string code)
        {
            ThrowIfDisposed();
            var store = Store as AppUserStore;
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (!await VerifyUserTokenAsync(user, Options.Tokens.EmailConfirmationTokenProvider, ConfirmEmailTokenPurpose, code))
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            await store.SetPhoneNumberConfirmedAsync(user, true, CancellationToken);
            return await UpdateAsync(user);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="loginProvider"></param>
        /// <param name="qrid">An uuid associated with qrcode scan</param>
        /// <returns></returns>
        public virtual async Task AddAuthenticatedWithQrAsync(string qrid, UserLoginInfo login)
        {
            ThrowIfDisposed();
            var store = Store as AppUserStore;
            if (qrid == null)
            {
                throw new ArgumentNullException(nameof(qrid));
            }

            await store.AddAuthenticatedWithQrAsync(qrid, login, CancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="loginProvider"></param>
        /// <param name="qrid">An uuid associated with qrcode scan</param>
        /// <returns></returns>
        public virtual async Task<IdentityUserExternalLogin> FindAuthenticatedWithQrAsync(string qrid, string loginProvider)
        {
            ThrowIfDisposed();
            var store = Store as AppUserStore;
            if (qrid == null)
            {
                throw new ArgumentNullException(nameof(qrid));
            }

            return await store.FindAuthenticatedWithQrAsync(qrid, loginProvider, CancellationToken);
        }
    }
}
