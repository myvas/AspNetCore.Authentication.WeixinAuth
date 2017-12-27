using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Demo.Models
{
    public class AppUserManager : UserManager<AppUser>
    {
        public AppUserManager(IUserStore<AppUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<AppUser> passwordHasher,
            IEnumerable<IUserValidator<AppUser>> userValidators,
            IEnumerable<IPasswordValidator<AppUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<AppUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public virtual async Task<AppUser> FindByPhoneNumberAsync(string phoneNumber)
        {
            return await Users.FirstOrDefaultAsync(x => x.PhoneNumber == phoneNumber);
        }

        public virtual async Task<IdentityResult> VerifyAndConfirmPhoneNumberAsync(AppUser user, string code)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (!await VerifyUserTokenAsync(user, Options.Tokens.ChangePhoneNumberTokenProvider, ChangePhoneNumberTokenPurpose + ":" + user.PhoneNumber, code))
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }

            user.PhoneNumberConfirmed = true;
            return await UpdateAsync(user);
        }

        public virtual async Task<(AppUser user, string code)> GenerateChangePhoneNumberTokenAsync(string phoneNumber)
        {
            var user = await FindByPhoneNumberAsync(phoneNumber);
            if (user == null)
            {
                user = new AppUser { UserName = phoneNumber, PhoneNumber = phoneNumber };
                var identityResult = await CreateAsync(user);
                if (!identityResult.Succeeded)
                {
                    var errMsg = "";
                    foreach (var err in identityResult.Errors)
                    {
                        errMsg += $"[{err.Code}]{err.Description}";
                    }
                    throw new ApplicationException($"Failed on creating a user.{errMsg}");
                }
            }

            var code = await GenerateChangePhoneNumberTokenAsync(user, phoneNumber);
            return (user, code);
        }


        public virtual async Task<(AppUser user, IdentityResult result)> VerifyChangePhoneNumberTokenAsync(string phoneNumber, string token)
        {
            if (string.IsNullOrEmpty(phoneNumber))
            {
                throw new ArgumentNullException(nameof(phoneNumber));
            }
            if (string.IsNullOrEmpty(token))
            {
                throw new ArgumentNullException(nameof(token));
            }
            var user = await FindByPhoneNumberAsync(phoneNumber);
            if (user == null)
            {
                throw new ArgumentNullException($"User associated with phone number {phoneNumber} not exists!");
            }

            // Make sure the token is valid and the stamp matches
            //var result = VerifyUserTokenAsync(user, Options.Tokens.ChangePhoneNumberTokenProvider, ChangePhoneNumberTokenPurpose + ":" + phoneNumber, token).Result;
            var result = await VerifyAndConfirmPhoneNumberAsync(user, token);
            return (user, result);
        }
    }
}
