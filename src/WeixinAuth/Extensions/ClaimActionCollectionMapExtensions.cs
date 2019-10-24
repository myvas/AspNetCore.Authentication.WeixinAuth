using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using System;
using System.Collections.Generic;
using System.Text;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Extensions
{
    internal static class ClaimActionCollectionMapExtensions
    {
        public static void MapJsonKeyArray(this ClaimActionCollection collection, string claimType, string jsonKey)
        {
            collection.Add(new JsonKeyArrayClaimAction(claimType, null, jsonKey));
        }

        public static void MapJsonKeyArray(this ClaimActionCollection collection, string claimType, string jsonKey, string valueType)
        {
            collection.Add(new JsonKeyArrayClaimAction(claimType, valueType, jsonKey));
        }
    }
}