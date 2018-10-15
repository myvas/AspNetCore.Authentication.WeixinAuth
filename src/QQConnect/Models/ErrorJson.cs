using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace Myvas.AspNetCore.Authentication.QQConnect
{
    public class QQConnectErrorJson
    {
        public int? ret { get; set; }
        public string msg { get; set; }

        [JsonIgnore]
        public bool Success { get { return ret.GetValueOrDefault(0) == 0; } }
    }
}
