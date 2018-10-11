using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace AspNetCore.Authentication.WeixinAuth
{
    /// <summary>
    /// Serializes and deserializes WeixinOAuth request and access tokens so that they can be used by other application components.
    /// </summary>
    public class WeixinAuthPropertiesDataFormat : SecureDataFormat<AuthenticationProperties>
    {

        public WeixinAuthPropertiesDataFormat(IDataProtector protector)
            : base(new WeixinAuthenticationPropertiesSerializer(), protector)
        {
        }
    }
}