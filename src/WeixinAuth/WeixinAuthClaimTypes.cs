using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinAuth
{
    /// <summary>
    /// Defines constants for the well-known claim types that can be assigned to a subject.
    /// This class cannot be inherited.
    /// </summary>
    public static class WeixinAuthClaimTypes
    {
        #region snsapi_base
        /// <summary>
        /// urn:weixin:openid, should be always equal to ClaimTypes.NameIdentifier
        /// </summary>
        public const string OpenId = "urn:weixin:openid";

        /// <summary>
        /// urn:weixin:scope
        /// </summary>
        public const string Scope = "urn:weixin:scope";
        #endregion
        #region snsapi_userinfo
        /// <summary>
        /// urn:weixin:nickname, should be always equal to ClaimTypes.Name
        /// </summary>
        public const string NickName = "urn:weixin:nickname";

        /// <summary>
        /// urn:weixin:headimgurl
        /// </summary>
        public const string HeadImageUrl = "urn:weixin:headimgurl";

        /// <summary>
        /// urn:weixin:sex
        /// </summary>
        public const string Sex = "urn:weixin:sex";

        /// <summary>
        /// urn:weixin:country
        /// </summary>
        public const string Country = "urn:weixin:country";

        /// <summary>
        /// urn:weixin:province
        /// </summary>
        public const string Province = "urn:weixin:province";

        /// <summary>
        /// urn:weixin:city
        /// </summary>
        public const string City = "urn:weixin:city";

        /// <summary>
        /// urn:weixin:unionid
        /// </summary>
        public const string UnionId = "urn:weixin:unionid";

        /// <summary>
        /// urn:weixin:privilege，可能有多个Claims。
        /// </summary>
        public const string Privilege = "urn:weixin:privilege";
        #endregion
    }
}
