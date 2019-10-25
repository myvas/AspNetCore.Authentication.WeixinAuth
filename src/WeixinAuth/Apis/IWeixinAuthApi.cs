using Microsoft.AspNetCore.Authentication.OAuth;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal interface IWeixinAuthApi
    {
        Task<OAuthTokenResponse> GetToken(HttpClient backchannel, string tokenEndpoint, string appId, string appSecret, string code, CancellationToken cancellationToken);
        Task<JsonDocument> GetUserInfo(HttpClient backchannel, string userInformationEndpoint, string accessToken, string openid, CancellationToken cancellationToken, WeixinAuthLanguageCodes languageCode = WeixinAuthLanguageCodes.zh_CN);
    }
}