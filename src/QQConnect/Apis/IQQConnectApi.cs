using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace Myvas.AspNetCore.Authentication.QQConnect
{
    public interface IQQConnectApi
    {
        Task<JObject> AddAlbum(HttpClient backchannel, string addAlbumEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<JObject> GetOpenId(HttpClient backchannel, string openIdEndpoint, string accessToken, CancellationToken cancellationToken);
        Task<OAuthTokenResponse> GetToken(HttpClient backchannel, string tokenEndpoint, string clientId, string clientSecret, string code, string redirectUri, CancellationToken cancellationToken);
        Task<JObject> GetUserInfo(HttpClient backchannel, string userInformationEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<JObject> GetUserVipInfo(HttpClient backchannel, string userVipInfoEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<JObject> GetUserVipRichInfo(HttpClient backchannel, string userVipRichInfoEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<JObject> ListAlbum(HttpClient backchannel, string listAlbumEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<JObject> ListPhoto(HttpClient backchannel, string listPhotoEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<OAuthTokenResponse> RefreshToken(HttpClient backchannel, string refreshTokenEndpoint, string appId, string refreshToken, CancellationToken cancellationToken);
        Task<JObject> UploadPicture(HttpClient backchannel, string uploadPictureEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken);
        Task<bool> ValidateToken(HttpClient backchannel, string validateTokenEndpoint, string appId, string accessToken, CancellationToken cancellationToken);
    }
}