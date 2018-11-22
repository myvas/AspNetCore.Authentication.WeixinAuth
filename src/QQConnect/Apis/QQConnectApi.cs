using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Net.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Text.RegularExpressions;
using System.Threading;

namespace Myvas.AspNetCore.Authentication.QQConnect
{
    public class QQConnectApi : IQQConnectApi
    {
        public ILogger Logger { get; }

        public QQConnectApi(
            ILoggerFactory loggerFactory)
        {
            Logger = loggerFactory?.CreateLogger<QQConnectApi>() ?? throw new ArgumentNullException(nameof(loggerFactory));
        }

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers.ToString() + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }

        /// <summary>
        /// 换取access_token
        /// </summary>
        public async Task<OAuthTokenResponse> GetToken(HttpClient backchannel, string tokenEndpoint, string clientId, string clientSecret, string code, string redirectUri, CancellationToken cancellationToken)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "client_id", clientId },
                { "client_secret", clientSecret },
                { "code", code },
                { "redirect_uri", redirectUri },
            };

            var requestUrl = QueryHelpers.AddQueryString(tokenEndpoint, tokenRequestParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = "OAuth token endpoint failure: " + await Display(response);
                Logger.LogError(error);
                return OAuthTokenResponse.Failed(new Exception(error));
            }

            var content = await response.Content.ReadAsStringAsync();
            //access_token=E92FA4F3C0CEB05F2B8AF97D71D89F86&expires_in=7776000&refresh_token=80D06D921B91EAE3B196C8480EEF5521
            var payload = ParseQueryString(content);
            if (!IsQuerySuccess(payload))
            {
                var error = $"OAuth openid endpoint failure: " + await Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }
            return OAuthTokenResponse.Success(payload);
        }

        /// <summary>
        /// 刷新或续期access_token使用。由于access_token有效期（目前为2个小时）较短，当access_token超时后，可以使用refresh_token进行刷新。
        /// </summary>
        /// <param name="refreshToken">refresh_token拥有较长的有效期（30天），当refresh_token失效的后，需要用户重新授权，所以，请开发者在refresh_token即将过期时（如第29天时），进行定时的自动刷新并保存好它。</param>
        /// <returns></returns>
        public async Task<OAuthTokenResponse> RefreshToken(HttpClient backchannel, string refreshTokenEndpoint, string appId, string refreshToken, CancellationToken cancellationToken)
        {
            await Task.FromResult<OAuthTokenResponse>(null);
            throw new NotImplementedException();
        }

        /// <summary>
        /// 检验授权凭证（access_token）是否有效。
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task<bool> ValidateToken(HttpClient backchannel, string validateTokenEndpoint, string appId, string accessToken, CancellationToken cancellationToken)
        {
            await Task.FromResult<OAuthTokenResponse>(null);
            throw new NotImplementedException();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="backchannel"></param>
        /// <param name="openIdEndpoint">OpenIdEndpoint</param>
        /// <param name="accessToken"></param>
        /// <param name="openid"></param>
        /// <param name="languageCode"></param>
        /// <returns>{“client_id”:”YOUR_APPID”,”openid”:”YOUR_OPENID”}</returns>
        public async Task<JObject> GetOpenId(HttpClient backchannel, string openIdEndpoint, string accessToken, CancellationToken cancellationToken)
        {
            // Get the openId and clientId
            var openIdParameters = new Dictionary<string, string>()
            {
                { "access_token", accessToken}
            };
            var requestUrl = QueryHelpers.AddQueryString(openIdEndpoint, openIdParameters);
            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = $"OAuth openid endpoint failure: " + Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }
            var content = await response.Content.ReadAsStringAsync();
            var payload = ParseCallbackString(content);
            //{“client_id”:”YOUR_APPID”,”openid”:”YOUR_OPENID”}
            if (!IsCallbackSuccess(payload))
            {
                var error = $"OAuth openid endpoint failure: " + Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }
            return payload;
        }

        #region QQConnect接口中用到的三种返回内容解析
        /// <summary>
        /// 示例：access_token=E92FA4F3C0CEB05F2B8AF97D71D89F86&expires_in=7776000&refresh_token=80D06D921B91EAE3B196C8480EEF5521
        /// </summary>
        /// <param name="content"></param>
        /// <remarks>access_token=E92FA4F3C0CEB05F2B8AF97D71D89F86&expires_in=7776000&refresh_token=80D06D921B91EAE3B196C8480EEF5521</remarks>
        /// <returns></returns>
        private JObject ParseQueryString(string content)
        {
            try
            {
                var result = new JObject();
                var dict = System.Web.HttpUtility.ParseQueryString(content);
                foreach (var k in dict.AllKeys)
                {
                    result.Add(k, dict[k]);
                }
                return result;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, $"Failed on parsing query string: {content}");
            }

            var error = $"Failed on parsing query string: {content}";
            throw new HttpRequestException(error);
        }
        private bool IsQuerySuccess(JObject payload)
        {
            return payload.Count > 0;
        }

        /// <summary>
        /// 示例：callback( {"error":100001,"error_description":"param client_id is wrong or lost "} );
        /// </summary>
        /// <param name="content"></param>
        /// <remarks>callback( {"error":100001,"error_description":"param client_id is wrong or lost "} );</remarks>
        /// <returns></returns>
        private JObject ParseCallbackString(string content)
        {
            try
            {
                var regexPattern = @"callback\((?<Json>.+)\);";
                var regex = new Regex(regexPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline, TimeSpan.FromMilliseconds(100));
                var match = regex.Match(content);
                if (match.Success)
                {
                    var json = match.Groups["Json"].Value;
                    return JObject.Parse(json);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, $"Failed on parsing callback string: {content}");
            }

            var error = $"Failed on parsing callback string: {content}";
            throw new HttpRequestException(error);
        }
        /// <summary>
        /// 示例：{"error":100001,"error_description":"param client_id is wrong or lost "}
        /// </summary>
        private bool IsCallbackSuccess(JObject payload)
        {
            return payload.Value<int?>("error").GetValueOrDefault(0) == 0;
        }

        /// <summary>
        /// 示例： { "ret":1002, "msg":"请先登录" }
        /// </summary>
        /// <param name="content"></param>
        /// <returns></returns>
        private JObject ParseJsonString(string content)
        {
            try
            {
                return JObject.Parse(content);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, $"Failed on parsing json string: {content}");
            }

            var error = $"Failed on parsing json string: {content}";
            throw new HttpRequestException(error);
        }
        /// <summary>
        /// 示例： { "ret":1002, "msg":"请先登录" }
        /// </summary>
        private bool IsJsonSuccess(JObject payload)
        {
            return payload.Value<int?>("ret").GetValueOrDefault(0) == 0;
        }
        #endregion

        /// <summary>
        /// 获取登录用户的昵称、头像、性别（get_user_info, UnionID机制）
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="clientId">oauth_consumer_key</param>
        /// <param name="openid"></param>
        /// <returns></returns>
        public async Task<JObject> GetUserInfo(HttpClient backchannel, string userInformationEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken)
        {
            // Get the UserInfo
            var getUserInfoParameters = new Dictionary<string, string>()
            {
                {"access_token", accessToken},
                {"oauth_consumer_key", clientId},
                {"openid", openid }
            };

            var requestUrl = QueryHelpers.AddQueryString(userInformationEndpoint, getUserInfoParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = $"OAuth userinformation endpoint failure: " + Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }

            var content = await response.Content.ReadAsStringAsync();
            //{
            //    "ret":0,
            //    "msg":"",
            //    "nickname":"Peter",
            //    "figureurl":"http://qzapp.qlogo.cn/qzapp/111111/942FEA70050EEAFBD4DCE2C1FC775E56/30",
            //    "figureurl_1":"http://qzapp.qlogo.cn/qzapp/111111/942FEA70050EEAFBD4DCE2C1FC775E56/50",
            //    "figureurl_2":"http://qzapp.qlogo.cn/qzapp/111111/942FEA70050EEAFBD4DCE2C1FC775E56/100",
            //    "figureurl_qq_1":"http://q.qlogo.cn/qqapp/100312990/DE1931D5330620DBD07FB4A5422917B6/40",
            //    "figureurl_qq_2":"http://q.qlogo.cn/qqapp/100312990/DE1931D5330620DBD07FB4A5422917B6/100",
            //    "gender":"男",
            //    "is_yellow_vip":"1",
            //    "vip":"1",
            //    "yellow_vip_level":"7",
            //    "level":"7",
            //    "is_yellow_year_vip":"1"
            //}
            // or
            //{ "ret":1002, "msg":"请先登录" }
            var payload = ParseJsonString(content);
            if (!IsJsonSuccess(payload))
            {
                var error = $"OAuth userinformation endpoint failure: " + await Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }
            return payload;
        }

        /// <summary>
        /// 访问用户QQ会员信息：获取QQ会员的基本信息(get_vip_info)
        /// </summary>
        /// <param name="backchannel"></param>
        /// <param name="userVipInfoEndpoint"></param>
        /// <param name="accessToken"></param>
        /// <param name="openid"></param>
        /// <param name="clientId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<JObject> GetUserVipInfo(HttpClient backchannel, string userVipInfoEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken)
        {
            // Get the UserVipInfo
            var getUserInfoParameters = new Dictionary<string, string>()
            {
                {"access_token", accessToken},
                {"oauth_consumer_key", clientId},
                {"openid", openid },
                {"format", "json"}
            };

            var requestUrl = QueryHelpers.AddQueryString(userVipInfoEndpoint, getUserInfoParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = $"OAuth userVipInfo endpoint failure: " + Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }

            var content = await response.Content.ReadAsStringAsync();
            //{
            //"ret":0,
            //"msg":"",
            //"is_qq_vip ":1,
            //"qq_vip_level":3,
            //"is_qq_year_vip":1
            //}
            // or
            //{ "ret":1002, "msg":"请先登录" }
            var payload = ParseJsonString(content);
            if (!IsJsonSuccess(payload))
            {
                var error = $"OAuth userVipInfo endpoint failure: " + await Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }
            return payload;
        }

        /// <summary>
        /// 访问用户QQ会员信息：获取QQ会员的高级信息(get_vip_rich_info)
        /// </summary>
        /// <param name="backchannel"></param>
        /// <param name="userVipRichInfoEndpoint"></param>
        /// <param name="accessToken"></param>
        /// <param name="openid"></param>
        /// <param name="clientId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<JObject> GetUserVipRichInfo(HttpClient backchannel, string userVipRichInfoEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken)
        {
            // Get the userVipRichInfo
            var getUserInfoParameters = new Dictionary<string, string>()
            {
                {"access_token", accessToken},
                {"oauth_consumer_key", clientId},
                {"openid", openid },
                {"format", "json"}
            };

            var requestUrl = QueryHelpers.AddQueryString(userVipRichInfoEndpoint, getUserInfoParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = $"OAuth userVipRichInfo endpoint failure: " + Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }

            var content = await response.Content.ReadAsStringAsync();
            //{
            //ret 返回码
            //msg 如果ret<0，会有相应的错误信息提示，返回数据全部用UTF - 8编码
            //is_qq_vip   标识是否QQ会员（0：不是； 1：是）
            //qq_vip_start QQ会员最后一次充值时间
            //qq_vip_end QQ会员期限
            //qq_vip_payway QQ会员充值方式
            //qq_year_vip_start QQ年费会员最后一次充值时间
            //qq_year_vip_end QQ年费会员期限
            //qq_year_vip_payway QQ年费会员充值方式
            //qq_zuanhuang_start QQ钻皇最后一次充值时间
            //qq_zuanhuang_end QQ钻皇期限
            //qq_zuanhuang_payway QQ钻皇充值方式
            //qq_haohua_start 豪华版QQ会员最后一次充值时间
            //qq_haohua_end 豪华版QQ会员期限
            //qq_haohua_payway 豪华版QQ会员充值方式
            //qq_svip_start QQ SVIP最后一次充值时间，预留字段，当前信息无效
            //qq_svip_end QQ SVIP期限，预留字段，当前信息无效
            //qq_svip_payway  QQ SVIP充值方式，预留字段，当前信息无效
            //history_pay_time    非会员历史充值时间，仅在用户是非会员时信息有效
            //history_end_time    非会员历史充值到期时间，仅在用户是非会员时信息有效
            //}
            // or
            //{ "ret":1002, "msg":"请先登录" }
            var payload = ParseJsonString(content);
            if (!IsJsonSuccess(payload))
            {
                var error = $"OAuth userVipRichInfo endpoint failure: " + await Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }
            return payload;
        }

        /// <summary>
        /// 访问我的空间相册：获取用户QQ空间相册列表(list_album)
        /// </summary>
        /// <param name="backchannel"></param>
        /// <param name="photoListAlbumEndpoint"></param>
        /// <param name="accessToken"></param>
        /// <param name="openid"></param>
        /// <param name="clientId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<JObject> ListAlbum(HttpClient backchannel, string photoListAlbumEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken)
        {
            // Get the photoListAlbum
            var getUserInfoParameters = new Dictionary<string, string>()
            {
                {"access_token", accessToken},
                {"oauth_consumer_key", clientId},
                {"openid", openid },
                {"format", "json"}
            };

            var requestUrl = QueryHelpers.AddQueryString(photoListAlbumEndpoint, getUserInfoParameters);

            var response = await backchannel.GetAsync(requestUrl, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = $"OAuth photoListAlbum endpoint failure: " + Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }

            var content = await response.Content.ReadAsStringAsync();
            //{
            //ret: 返回码
            //albumid: 相册ID
            //classid: 相册分类ID
            //createtime: 相册创建时间
            //desc: 相册描述
            //name: 相册名称
            //coverurl: 相册封面照片地址
            //picnum: 照片数
            //albumnum: 相册总数
            //msg: 错误消息
            //}
            // or
            //{ "ret":1002, "msg":"请先登录" }
            var payload = ParseJsonString(content);
            if (!IsJsonSuccess(payload))
            {
                var error = $"OAuth photoListAlbum endpoint failure: " + await Display(response);
                Logger.LogError(error);
                throw new HttpRequestException(error);
            }
            return payload;
        }

        /// <summary>
        /// 访问我的空间相册：上传一张照片到QQ空间相册(upload_pic)
        /// </summary>
        /// <param name="backchannel"></param>
        /// <param name="uploadPictureEndpoint"></param>
        /// <param name="accessToken"></param>
        /// <param name="openid"></param>
        /// <param name="clientId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<JObject> UploadPicture(HttpClient backchannel, string uploadPictureEndpoint, string accessToken, string openid, string clientId, /*PhotoUploadSinglePictureRequestParameters*/object param, CancellationToken cancellationToken)
        {
            await Task.FromResult<JObject>(null);
            throw new NotImplementedException();
        }

        /// <summary>
        /// 访问我的空间相册：在用户的空间相册里，创建一个新的个人相册(add_album)
        /// </summary>
        /// <param name="backchannel"></param>
        /// <param name="addAlbumEndpoint"></param>
        /// <param name="accessToken"></param>
        /// <param name="openid"></param>
        /// <param name="clientId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<JObject> AddAlbum(HttpClient backchannel, string addAlbumEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken)
        {
            await Task.FromResult<JObject>(null);
            throw new NotImplementedException();
        }

        /// <summary>
        /// 访问我的空间相册：获取用户QQ空间相册中的照片列表（list_photo)
        /// </summary>
        /// <param name="backchannel"></param>
        /// <param name="listPhotoEndpoint"></param>
        /// <param name="accessToken"></param>
        /// <param name="openid"></param>
        /// <param name="clientId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<JObject> ListPhoto(HttpClient backchannel, string listPhotoEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken)
        {
            await Task.FromResult<JObject>(null);
            throw new NotImplementedException();
        }

        public Task<JObject> UploadPicture(HttpClient backchannel, string uploadPictureEndpoint, string accessToken, string openid, string clientId, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
