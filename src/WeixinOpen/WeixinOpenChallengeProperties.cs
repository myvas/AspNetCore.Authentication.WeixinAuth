using Microsoft.AspNetCore.Authentication.OAuth;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCore.Authentication.WeixinOpen
{
    public class WeixinOpenChallengeProperties : OAuthChallengeProperties
    {
        //TODO: WeixinOpenChallengeProperties
        //Assert.Equal("force", query["approval_prompt"]);
        //Assert.Equal("consent", query["prompt"]);
        //Assert.Equal("false", query["include_granted_scopes"]);

        /// <summary>
        /// The parameter key for the "access_type" argument being used for a challenge request.
        /// </summary>
        public static readonly string AccessTypeKey = "access_type";

        /// <summary>
        /// The "access_type" parameter value being used for a challenge request.
        /// </summary>
        public string AccessType
        {
            get => GetParameter<string>(AccessTypeKey);
            set => SetParameter(AccessTypeKey, value);
        }

        /// <summary>
        /// The parameter key for the "login_hint" argument being used for a challenge request.
        /// </summary>
        public static readonly string LoginHintKey = "login_hint";
        /// <summary>
        /// The "login_hint" parameter value being used for a challenge request.
        /// </summary>
        public string LoginHint
        {
            get => GetParameter<string>(LoginHintKey);
            set => SetParameter(LoginHintKey, value);
        }

        /// <summary>
        /// The parameter key for the "unionid" argument being used for a challenge request.
        /// </summary>
        public static readonly string UnionIdKey = "u";
        /// <summary>
        /// The "unionid" parameter value being used for a challenge request.
        /// </summary>
        public string UnionId
        {
            get => GetParameter<string>(UnionIdKey);
            set => SetParameter(UnionIdKey, value);
        }

        /// <summary>
        /// The parameter key for the "openid" argument being used for a challenge request.
        /// </summary>
        public static readonly string OpenIdKey = "o";
        /// <summary>
        /// The "openid" parameter value being used for a challenge request.
        /// </summary>
        public string OpenId
        {
            get => GetParameter<string>(OpenIdKey);
            set => SetParameter(OpenIdKey, value);
        }

        /// <summary>
        /// The parameter key for the "local_userid" argument being used for a challenge request.
        /// </summary>
        public static readonly string LocalUserIdKey = "lu";
        /// <summary>
        /// The "local_userid" parameter value being used for a challenge request.
        /// </summary>
        public string LocalUserId
        {
            get => GetParameter<string>(LocalUserIdKey);
            set => SetParameter(LocalUserIdKey, value);
        }

        public WeixinOpenChallengeProperties()
        { }

        public WeixinOpenChallengeProperties(IDictionary<string, string> items)
            : base(items)
        { }

        public WeixinOpenChallengeProperties(IDictionary<string, string> items, IDictionary<string, object> parameters)
            : base(items, parameters)
        { }
    }
}
