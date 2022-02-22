﻿using System;
using System.Security.Claims;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal static class WeixinAuthClaimsExtensions
    {
        public static ClaimsIdentity AddOptionalClaim(this ClaimsIdentity identity,
            string type, string value, string issuer)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            // Don't update the identity if the claim cannot be safely added.
            if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(value))
            {
                return identity;
            }

            identity.AddClaim(new Claim(type, value, ClaimValueTypes.String, issuer ?? ClaimsIdentity.DefaultIssuer));
            return identity;
        }
    }
}
