using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinOpen
{
    /// <summary>
    /// Defines constants for the well-known claim types that can be assigned to a subject.
    /// This class cannot be inherited.
    /// </summary>
    public static class WeixinOpenClaimTypes
    {
        #region snsapi_base
        /// <summary>
        /// urn:weixinoauth:openid, should be always equal to ClaimTypes.NameIdentifier
        /// </summary>
        public const string OpenId = "urn:weixin:openid";

        /// <summary>
        /// urn:weixinoauth:scope
        /// </summary>
        public const string Scope = "urn:weixin:scope";
        #endregion
        #region snsapi_userinfo
        /// <summary>
        /// urn:weixinoauth:nickname, should be always equal to ClaimTypes.Name
        /// </summary>
        public const string NickName = "urn:weixin:nickname";

        /// <summary>
        /// urn:weixinoauth:headimgurl
        /// </summary>
        public const string HeadImageUrl = "urn:weixin:headimgurl";

        /// <summary>
        /// urn:weixinoauth:sex
        /// </summary>
        public const string Gender = "urn:weixin:sex";

        /// <summary>
        /// urn:weixinoauth:country
        /// </summary>
        public const string Country = "urn:weixin:country";

        /// <summary>
        /// urn:weixinoauth:province
        /// </summary>
        public const string Province = "urn:weixin:province";

        /// <summary>
        /// urn:weixinoauth:city
        /// </summary>
        public const string City = "urn:weixin:city";

        /// <summary>
        /// urn:weixinoauth:unionid
        /// </summary>
        public const string UnionId = "urn:weixin:unionid";

        /// <summary>
        /// urn:weixinoauth:privilege，可能有多个Claims。
        /// </summary>
        public const string Privilege = "urn:weixin:privilege";
        #endregion
    }
}
