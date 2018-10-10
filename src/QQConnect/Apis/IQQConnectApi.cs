using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace AspNetCore.Authentication.QQConnect
{
    public interface IQQConnectApi
    {
        Task<bool> ValidateToken(HttpClient backchannel, string validateTokenEndpoint, string appId, string accessToken, CancellationToken cancellationToken);
        Task<OAuthTokenResponse> RefreshToken(HttpClient backchannel, string refreshTokenEndpoint, string appId, string refreshToken, CancellationToken cancellationToken);
        Task<OAuthTokenResponse> GetToken(HttpClient backchannel, string tokenEndpoint, string clientId, string clientSecret, string code, string redirectUri, CancellationToken cancellationToken);
        Task<JObject> GetUserInfo(HttpClient backchannel, string userInformationEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<JObject> GetOpenId(HttpClient backchannel, string endpoint, string accessToken, CancellationToken cancellationToken);
    }
}