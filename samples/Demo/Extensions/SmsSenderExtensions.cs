using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AspNetCore.WeixinOAuth.Demo.Services;
using AspNetCore.QcloudSms;

namespace AspNetCore.WeixinOAuth.Demo.Services
{
    public static class SmsSenderExtensions
    {
        public static Task SendSmsConfirmationAsync(this ISmsSender smsSender, string mobile, string code)
        {
            var content = $"your verification code is {code}";
            return smsSender.SendSmsAsync(mobile, content);
        }
    }
}
