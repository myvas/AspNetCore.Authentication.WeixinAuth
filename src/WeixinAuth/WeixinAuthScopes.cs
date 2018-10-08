using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Authentication.WeixinAuth
{
    public class WeixinAuthScopes
    {
        public enum Items
        {
            ///// <summary>
            ///// 此授权用于获取进入页面的用户openid，静默授权并自动跳转到回调页，即使该用户未关注目标微信公众号。
            ///// </summary>
            snsapi_base,

            ///// <summary>
            ///// 此授权用于网页扫码登录。
            ///// </summary>
            [Obsolete("此授权码不适用于本中间件，请使用.AddWeixinOpen(...)", true)]
            snsapi_login,

            ///// <summary>
            ///// 此授权用于获取微信用户资料，未关注目标微信公众号的用户须手动同意，若已关注则用户亦无感知通过授权。
            ///// </summary>
            snsapi_userinfo
        }

        public static ICollection<string> TryAdd(ICollection<string> currentScopes, params string[] scopes)
        {
            Array.ForEach(scopes, x =>
            {
                if (!currentScopes.Contains(x))
                {
                    currentScopes.Add(x);
                }
            });
            return currentScopes;
        }

        public static ICollection<string> TryAdd(ICollection<string> currentScopes, params Items[] scopes)
        {
            Array.ForEach(scopes, x =>
            {
                var s = x.ToString();
                if (!currentScopes.Contains(s))
                {
                    currentScopes.Add(s);
                }
            });
            return currentScopes;
        }

        public static bool Contains(ICollection<string> currentScopes, Items scope)
        {
            return Contains(currentScopes, scope.ToString());
        }

        public static bool Contains(ICollection<string> currentScopes, string scope)
        {
            return currentScopes.Contains(scope);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="currentScopes">a string contains multiple scopes, splited by comma</param>
        /// <param name="scope"></param>
        /// <returns></returns>
        public static bool Contains(string currentScopes, string scope)
        {
            return Contains(currentScopes.Split(','), scope);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="currentScopes">a string contains multiple scopes, splited by comma</param>
        /// <param name="scope"></param>
        /// <returns></returns>
        public static bool Contains(string currentScopes, Items scope)
        {
            return Contains(currentScopes.Split(','), scope);
        }
    }
}
