using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace AspNetCore.Authentication.WeixinOpen
{
    public interface IWeixinOpenApi
    {
        Task<bool> ValidateToken(HttpClient backchannel, string validateTokenEndpoint, string appId, string accessToken, CancellationToken cancellationToken);
        Task<JObject> GetUserInfo(HttpClient backchannel, string userInformationEndpoint, string accessToken, string openid, CancellationToken cancellationToken, LanguageCodes languageCode = LanguageCodes.zh_CN);
        Task<OAuthTokenResponse> RefreshToken(HttpClient backchannel, string refreshTokenEndpoint, string appId, string refreshToken, CancellationToken cancellationToken);
        Task<OAuthTokenResponse> GetToken(HttpClient backchannel, string tokenEndpoint, string appId, string appSecret, string code, CancellationToken cancellationToken);
    }
}