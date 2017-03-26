using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WeixinOAuth.Messages
{
    /// <summary>
    /// The WeixinOAuth request 'state' obtained from the request endpoint.
    /// </summary>
    public class WeixinState
    {
        public WeixinState() { }
        public WeixinState(string correlationId)
        {
            CorrelationId = correlationId;
        }

        public string CorrelationId { get; set; }
    }
}
