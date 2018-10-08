using AspNetCore.QcloudSms;
using AspNetCore.TencentSms;
using System.Threading.Tasks;

namespace AspNetCore.QcloudSms
{
    internal static class QcloudSmsSenderExtensions
    {
        /// <summary>
        /// 发送验证码短信
        /// </summary>
        /// <param name="_smsSender"></param>
        /// <param name="vcode"></param>
        public static async Task<bool> SendVcodeAsync(this ISmsSender _smsSender, string mobile, string vcode)
        {
            var codeText = $"【新广州入户】{vcode}为您的验证码。如非本人操作，请忽略本短信。";
            return await _smsSender.SendSmsAsync(mobile, codeText);
        }
    }
}
