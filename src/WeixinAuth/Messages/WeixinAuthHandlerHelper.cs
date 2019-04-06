using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace Myvas.AspNetCore.Authentication
{
    public static class WeixinAuthHandlerHelper
    {
        #region 错误时微信会返回含有两个字段的JSON数据包
        /// <summary>
        ///  errcode
        /// </summary>
        public static int GetErrorCode(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<int?>("errcode") ?? 0;
        }

        /// <summary>
        ///  errmsg
        /// </summary>
        public static string GetErrorMessage(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("errmsg");
        }
        #endregion

        /// <summary>
        ///  openid
        /// </summary>
        public static string GetOpenId(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("openid");
        }

        /// <summary>
        /// nickname 微信用户昵称。
        /// </summary>
        public static string GetNickName(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("nickname");
        }

        /// <summary>
        /// headimgurl 微信头像。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetHeadImageUrl(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("headimgurl");
        }

        /// <summary>
        /// sex 姓别。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetGender(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("sex");
        }

        /// <summary>
        /// country 国家。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetCountry(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("country");
        }

        /// <summary>
        /// province 省份。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetProvince(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("province");
        }

        /// <summary>
        /// city 城市。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetCity(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("city");
        }

        /// <summary>
        /// unionid 用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static string GetUnionId(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<string>("unionid");
        }

        /// <summary>
        /// privilege 用户特权信息，json数组，如微信沃卡用户为（chinaunicom）。
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        public static IEnumerable<string> GetPrivileges(JObject payload)
        {
            if (payload == null)
            {
                throw new ArgumentNullException(nameof(payload));
            }
            return payload.Value<JArray>("privilege").Values<string>();
        }
    }
}
