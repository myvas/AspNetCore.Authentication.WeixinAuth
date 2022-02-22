using Microsoft.AspNetCore.Authentication.OAuth;

namespace Myvas.AspNetCore.Authentication.WeixinAuth.Internal
{
    internal static class OAuthTokenResponseExtensions
    {
        public static string GetUnionId(this OAuthTokenResponse response)
        {
            return response.Response.RootElement.GetString("unionid");
        }

        public static string GetOpenId (this OAuthTokenResponse response)
        {
            return response.Response.RootElement.GetString("openid");
        }
        
        public static string GetScope(this OAuthTokenResponse response)
        {
            return response.Response.RootElement.GetString("scope");
        }

        public static string GetErrorCode(this OAuthTokenResponse response)
        {
            return response.Response.RootElement.GetString("errcode");
        }

        public static string GetErrorMsg(this OAuthTokenResponse response)
        {
            return response.Response.RootElement.GetString("errmsg");
        }
    }
}