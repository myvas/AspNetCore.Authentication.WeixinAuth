using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCore.Authentication.QQ.Models
{
    /// <summary>
    /// PC网站接入时，获取到用户OpenID，返回包如下：
    /// <code>callback( {"client_id":"YOUR_APPID","openid":"YOUR_OPENID"} );</code>
    /// </summary>
    public class OpenIdJson
    {
        public string client_id { get; set; }
        public string openid { get; set; }
    }
}
