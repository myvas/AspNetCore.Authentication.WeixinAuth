using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Myvas.AspNetCore.Authentication.WeixinOpen
{
    /// <summary>
    /// Defines constants for the well-known claim types that can be assigned to a subject.
    /// This class cannot be inherited.
    /// </summary>
    public static class WeixinOpenClaimTypes
    {
        /// <summary>
        /// urn:weixinoauth:unionid, should be <see cref="ClaimTypes.NameIdentifier"/>
        /// </summary>
        public const string UnionId = "urn:weixin:unionid";

        #region snsapi_base
        /// <summary>
        /// urn:weixinoauth:openid, should NOT be <see cref="ClaimTypes.NameIdentifier"/>
        /// </summary>
        public const string OpenId = "urn:weixin:openid";

        /// <summary>
        /// urn:weixinoauth:scope
        /// </summary>
        public const string Scope = "urn:weixin:scope";
        #endregion
        #region snsapi_userinfo
        /// <summary>
        /// urn:weixinoauth:nickname, should be <see cref="ClaimTypes.Name"/>
        /// </summary>
        public const string NickName = "urn:weixin:nickname";

        /// <summary>
        /// urn:weixinoauth:headimgurl
        /// </summary>
        public const string HeadImageUrl = "urn:weixin:headimgurl";

        /// <summary>
        /// urn:weixinoauth:sex, should be <see cref="ClaimTypes.Gender"/>
        /// </summary>
        public const string Sex = "urn:weixin:sex";

        /// <summary>
        /// urn:weixinoauth:country, should be <see cref="ClaimTypes.Country"/>
        /// </summary>
        public const string Country = "urn:weixin:country";

        /// <summary>
        /// urn:weixinoauth:province, should be <see cref="ClaimTypes.StateOrProvince"/>
        /// </summary>
        public const string Province = "urn:weixin:province";

        /// <summary>
        /// urn:weixinoauth:city
        /// </summary>
        public const string City = "urn:weixin:city";
        
        /// <summary>
        /// urn:weixinoauth:privilege，JArray, 可能有多个Claims。
        /// </summary>
        public const string Privilege = "urn:weixin:privilege";
        #endregion
    }
}
