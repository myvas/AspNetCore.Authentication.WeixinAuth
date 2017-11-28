using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Microsoft.AspNetCore.Identity
{
    /// <summary>
    /// Represents a login via qrcode and its associated pc for a mobile device.
    /// </summary>
    public class IdentityUserExternalLogin : IdentityUserExternalLogin<string>
    {
    }

    /// <summary>
    /// Represents a login via qrcode and its associated pc for a mobile device.
    /// </summary>
    /// <typeparam name="TKey">The type of the primary key of the user associated with this login.</typeparam>
    public class IdentityUserExternalLogin<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Gets or sets the login provider for the login (e.g. weixin-oauth on a mobile device)
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        /// Gets or sets the unique provider identifier for this login.
        /// </summary>
        public virtual string ProviderKey { get; set; }

        /// <summary>
        /// Gets or sets the friendly name used in a UI for this login.
        /// </summary>
        public virtual string ProviderDisplayName { get; set; }

        /// <summary>
        /// Gets or sets the of the correlation id associated with this login.
        /// </summary>
        public virtual TKey CorrelationId { get; set; }
    }
}
