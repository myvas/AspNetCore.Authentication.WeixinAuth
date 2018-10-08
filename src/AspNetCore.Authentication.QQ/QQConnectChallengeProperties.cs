using Microsoft.AspNetCore.Authentication.OAuth;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCore.Authentication.QQConnect
{
    public class QQConnectChallengeProperties : OAuthChallengeProperties
    {
        /// <summary>
        /// The parameter key for the "display" argument being used for a challenge request.
        /// </summary>
        /// <remarks>用于展示的样式。(1)不传则默认展示为PC下的样式。(2)如果传入“mobile”，则展示为mobile端下的样式。</remarks>
        public static readonly string DisplayStyleKey = "display";
        
        public string DisplayStyle
        {
            get => GetParameter<string>(DisplayStyleKey);
            set => SetParameter(DisplayStyleKey, value);
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

        public QQConnectChallengeProperties()
        { }

        public QQConnectChallengeProperties(IDictionary<string, string> items)
            : base(items)
        { }

        public QQConnectChallengeProperties(IDictionary<string, string> items, IDictionary<string, object> parameters)
            : base(items, parameters)
        { }
    }
}
