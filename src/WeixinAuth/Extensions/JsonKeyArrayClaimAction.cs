using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using System.Security.Claims;
using System.Text.Json;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal class JsonKeyArrayClaimAction : ClaimAction
    {
        public JsonKeyArrayClaimAction(string claimType, string valueType)
            : base(claimType, valueType)
        {
            JsonKey = claimType.ToLower();
        }

        /// <summary>
        /// Creates a new JsonKeyArrayClaimAction.
        /// </summary>
        /// <param name="claimType">The value to use for Claim.Type when creating a Claim.</param>
        /// <param name="valueType">The value to use for Claim.ValueType when creating a Claim.</param>
        /// <param name="jsonKey">The top level key to look for in the json user data.</param>
        public JsonKeyArrayClaimAction(string claimType, string valueType, string jsonKey) : base(claimType, valueType)
        {
            JsonKey = jsonKey;
        }

        /// <summary>
        /// The top level key to look for in the json user data.
        /// </summary>
        public string JsonKey { get; }

        #region removed from 3.0, JObject replaced by JsonElement
        //public override void Run(JObject userData, ClaimsIdentity identity, string issuer)
        //{
        //    var values = userData?[JsonKey];
        //    if (!(values is JArray)) return;

        //    foreach (var value in values)
        //    {
        //        identity.AddClaim(new Claim(ClaimType, value.ToString(), ValueType, issuer));
        //    }
        //}
        #endregion

        public override void Run(JsonElement userData, ClaimsIdentity identity, string issuer)
        {
            var isArray = userData.GetArrayLength() > 0;
            if (isArray)
            {
                var arr = userData.GetStringArray(JsonKey);
                foreach (var value in arr)
                    identity.AddClaim(new Claim(ClaimType, value.ToString(), ValueType, issuer));
            }
            else
            {
                var s = userData.GetString(JsonKey);
                identity.AddClaim(new Claim(ClaimType, s, ValueType, issuer));
            }
        }
    }
}