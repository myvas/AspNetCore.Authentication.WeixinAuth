using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCore.Authentication.QQConnect.Models
{
    public class ErrorJson
    {
        public int? ret { get; set; }
        public string msg { get; set; }

        [JsonIgnore]
        public bool Success { get { return ret.GetValueOrDefault(0) == 0; } }
    }
}
