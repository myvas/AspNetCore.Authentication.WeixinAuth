using Microsoft.AspNetCore.Authentication.OAuth;
using System;
using System.Collections.Generic;
using System.Text;

namespace Myvas.AspNetCore.Authentication.QQConnect
{
    public class QQConnectChallengeProperties : OAuthChallengeProperties
    {
        public class Displays
        {
            public const string pc = "pc";
            public const string mobile = "mobile";
        }

        /// <summary>
        /// The parameter key for the "display" argument being used for a challenge request.
        /// </summary>
        /// <remarks>用于展示的样式。(1)不传则默认展示为"pc"样式。(2)另一个样式是“mobile”。</remarks>
        public static readonly string DisplayStyleKey = "display";

        public string Display
        {
            get => GetParameter<string>(DisplayStyleKey);
            set => SetParameter(DisplayStyleKey, value);
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
